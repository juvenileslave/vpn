// Package prober probes one normalized upstream candidate through a temporary
// pinned Xray process. The process listens only on 127.0.0.1 and routes only
// the probe and optional geo endpoints through the candidate; every other
// destination, including private, loopback and link-local ranges, is blocked.
package prober

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/juvenileslave/vpn/vpnctl/internal/upstream/candidate"
	"github.com/juvenileslave/vpn/vpnctl/internal/upstream/selector"
)

const (
	defaultTimeout      = 10 * time.Second
	defaultSamples      = 2
	maxSamples          = 5
	defaultStartTimeout = 5 * time.Second
	maxCountryBody      = 32
	maxTagLen           = 63
)

var (
	ErrInvalidOptions = errors.New("prober: invalid options")
	ErrCore           = errors.New("prober: pinned xray is unusable")
	ErrConfig         = errors.New("prober: candidate config rejected")
	ErrStart          = errors.New("prober: temporary xray did not become ready")
)

// Options configures a Prober. ProbeURL is required.
type Options struct {
	XrayPath      string        // absolute pinned xray executable
	ProbeURL      string        // https endpoint used for latency and health
	GeoURL        string        // optional https endpoint returning a 2-letter country
	Timeout       time.Duration // per HTTP sample; 0 => 10s
	Samples       int           // 0 => 2, max 5
	VersionPrefix string        // optional required `xray -version` prefix
	StartTimeout  time.Duration // 0 => 5s
}

// Prober implements pipeline.Prober with a temporary Xray per candidate.
type Prober struct {
	xrayPath     string
	probeURL     *url.URL
	geoURL       *url.URL
	timeout      time.Duration
	samples      int
	startTimeout time.Duration
	version      string
}

// New validates options. It does not execute Xray; the pinned version check
// runs on the first Probe.
func New(opts Options) (*Prober, error) {
	if opts.XrayPath == "" || !filepath.IsAbs(opts.XrayPath) {
		return nil, fmt.Errorf("%w: xray path must be absolute", ErrInvalidOptions)
	}
	info, err := os.Lstat(opts.XrayPath)
	if err != nil {
		return nil, fmt.Errorf("%w: xray path is inaccessible", ErrInvalidOptions)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return nil, fmt.Errorf("%w: xray path must be an executable regular file", ErrInvalidOptions)
	}
	if err := validateHTTPSURL(opts.ProbeURL); err != nil {
		return nil, fmt.Errorf("%w: probe URL must be https", ErrInvalidOptions)
	}
	probeURL, _ := url.Parse(opts.ProbeURL)
	var geoURL *url.URL
	if opts.GeoURL != "" {
		if err := validateHTTPSURL(opts.GeoURL); err != nil {
			return nil, fmt.Errorf("%w: geo URL must be https", ErrInvalidOptions)
		}
		geoURL, _ = url.Parse(opts.GeoURL)
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	samples := opts.Samples
	if samples == 0 {
		samples = defaultSamples
	}
	if samples < 1 || samples > maxSamples {
		return nil, fmt.Errorf("%w: samples must be between 1 and %d", ErrInvalidOptions, maxSamples)
	}
	startTimeout := opts.StartTimeout
	if startTimeout <= 0 {
		startTimeout = defaultStartTimeout
	}

	return &Prober{
		xrayPath:     opts.XrayPath,
		probeURL:     probeURL,
		geoURL:       geoURL,
		timeout:      timeout,
		samples:      samples,
		startTimeout: startTimeout,
		version:      opts.VersionPrefix,
	}, nil
}

func validateHTTPSURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return errors.New("invalid https URL")
	}
	return nil
}

// Probe starts one temporary Xray, measures each sample through its HTTP proxy
// inbound, optionally observes the egress country, and always terminates the
// process and removes its configuration.
func (p *Prober) Probe(ctx context.Context, cand candidate.Candidate) ([]selector.Probe, error) {
	if p == nil || p.probeURL == nil {
		return nil, ErrInvalidOptions
	}
	if ctx == nil {
		return nil, ErrInvalidOptions
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := p.checkVersion(ctx); err != nil {
		return nil, err
	}
	outbound, tag, err := parseCandidate(cand)
	if err != nil {
		return nil, err
	}

	port, err := freePort()
	if err != nil {
		return nil, fmt.Errorf("%w: no local port", ErrStart)
	}
	config, err := buildConfig(port, outbound, tag, p.probeURL, p.geoURL)
	if err != nil {
		return nil, err
	}

	dir, err := os.MkdirTemp("", "vpnctl-upstream-probe-")
	if err != nil {
		return nil, fmt.Errorf("%w: temporary directory failed", ErrStart)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("%w: temporary directory permissions", ErrStart)
	}
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, config, 0o600); err != nil {
		return nil, fmt.Errorf("%w: temporary config failed", ErrStart)
	}

	procCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(procCtx, p.xrayPath, "run", "-c", configPath)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("%w: xray did not start", ErrStart)
	}
	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
		close(waitCh)
	}()
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		cancel()
		<-waitCh
	}()

	if err := waitReady(ctx, port, p.startTimeout, waitCh); err != nil {
		return nil, err
	}

	proxyURL := &url.URL{Scheme: "http", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(port))}
	client := &http.Client{
		Timeout: p.timeout,
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(proxyURL),
			DisableKeepAlives: true,
		},
	}
	defer client.CloseIdleConnections()

	probes := make([]selector.Probe, 0, p.samples)
	for range p.samples {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		probes = append(probes, p.sample(ctx, client))
	}

	country := ""
	if p.geoURL != nil {
		country = p.observeCountry(ctx, client)
	}
	for i := range probes {
		probes[i].Country = country
	}
	return probes, nil
}

func (p *Prober) sample(ctx context.Context, client *http.Client) selector.Probe {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.probeURL.String(), nil)
	if err != nil {
		return selector.Probe{Outcome: "failure"}
	}
	start := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(start)
	if err != nil {
		return selector.Probe{Outcome: outcomeFor(err)}
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return selector.Probe{Outcome: "failure", Latency: latency}
	}
	return selector.Probe{Outcome: "success", Latency: latency}
}

func (p *Prober) observeCountry(ctx context.Context, client *http.Client) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.geoURL.String(), nil)
	if err != nil {
		return ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCountryBody+1))
	if err != nil || len(body) > maxCountryBody {
		return ""
	}
	code := strings.ToUpper(strings.TrimSpace(string(body)))
	if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
		return ""
	}
	return code
}

func outcomeFor(err error) string {
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		return "timeout"
	}
	return "failure"
}

func (p *Prober) checkVersion(ctx context.Context) error {
	checkCtx, cancel := context.WithTimeout(ctx, p.startTimeout)
	defer cancel()
	out, err := exec.CommandContext(checkCtx, p.xrayPath, "-version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: version check failed", ErrCore)
	}
	if p.version != "" && !strings.HasPrefix(strings.TrimSpace(string(out)), p.version) {
		return fmt.Errorf("%w: version does not match the pinned prefix", ErrCore)
	}
	return nil
}

func waitReady(ctx context.Context, port int, timeout time.Duration, waitCh <-chan error) error {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-waitCh:
			return fmt.Errorf("%w: xray exited before readiness", ErrStart)
		case <-deadline.C:
			return fmt.Errorf("%w: readiness timeout", ErrStart)
		case <-ticker.C:
			conn, err := net.DialTimeout("tcp", addr, 250*time.Millisecond)
			if err == nil {
				_ = conn.Close()
				return nil
			}
		}
	}
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = l.Close() }()
	addr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		return 0, errors.New("unexpected address type")
	}
	return addr.Port, nil
}

func parseCandidate(cand candidate.Candidate) (json.RawMessage, string, error) {
	if len(strings.TrimSpace(string(cand.Outbound))) == 0 {
		return nil, "", fmt.Errorf("%w: empty outbound", ErrConfig)
	}
	var meta struct {
		Tag string `json:"tag"`
	}
	if err := json.Unmarshal(cand.Outbound, &meta); err != nil {
		return nil, "", fmt.Errorf("%w: outbound is not an object", ErrConfig)
	}
	if !validTag(meta.Tag) {
		return nil, "", fmt.Errorf("%w: outbound tag is missing or invalid", ErrConfig)
	}
	return cand.Outbound, meta.Tag, nil
}

func validTag(tag string) bool {
	if tag == "" || len(tag) > maxTagLen {
		return false
	}
	for i := 0; i < len(tag); i++ {
		b := tag[i]
		if !(b >= 'A' && b <= 'Z') && !(b >= 'a' && b <= 'z') && !(b >= '0' && b <= '9') && b != '.' && b != '_' && b != '-' {
			return false
		}
	}
	return true
}

type inbound struct {
	Listen   string         `json:"listen"`
	Port     int            `json:"port"`
	Protocol string         `json:"protocol"`
	Settings map[string]any `json:"settings"`
	Tag      string         `json:"tag"`
}

type routingRule struct {
	Type        string   `json:"type"`
	Domain      []string `json:"domain,omitempty"`
	IP          []string `json:"ip,omitempty"`
	OutboundTag string   `json:"outboundTag"`
}

type routing struct {
	DomainStrategy string        `json:"domainStrategy"`
	Rules          []routingRule `json:"rules"`
}

type config struct {
	Log       map[string]string `json:"log"`
	Inbounds  []inbound         `json:"inbounds"`
	Outbounds []json.RawMessage `json:"outbounds"`
	Routing   routing           `json:"routing"`
}

func buildConfig(port int, outbound json.RawMessage, tag string, probeURL, geoURL *url.URL) ([]byte, error) {
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("%w: invalid proxy port", ErrConfig)
	}
	if !validTag(tag) || tag == "blocked" || tag == "probe-in" {
		return nil, fmt.Errorf("%w: invalid outbound tag", ErrConfig)
	}
	var candidateOutbound map[string]any
	if err := json.Unmarshal(outbound, &candidateOutbound); err != nil {
		return nil, fmt.Errorf("%w: outbound is not an object", ErrConfig)
	}
	probeHost := probeURL.Hostname()
	allowedDomains := []string{"full:" + probeHost}
	if geoURL != nil {
		if geoHost := geoURL.Hostname(); geoHost != probeHost {
			allowedDomains = append(allowedDomains, "full:"+geoHost)
		}
	}
	blocked := struct {
		Protocol string `json:"protocol"`
		Tag      string `json:"tag"`
	}{Protocol: "blackhole", Tag: "blocked"}

	cfg := config{
		Log: map[string]string{"loglevel": "none"},
		Inbounds: []inbound{{
			Listen:   "127.0.0.1",
			Port:     port,
			Protocol: "http",
			Settings: map[string]any{},
			Tag:      "probe-in",
		}},
		Outbounds: []json.RawMessage{outbound, mustMarshal(blocked)},
		Routing: routing{
			DomainStrategy: "AsIs",
			Rules: []routingRule{
				{Type: "field", Domain: allowedDomains, OutboundTag: tag},
				{Type: "field", IP: privateRanges(), OutboundTag: "blocked"},
				{Type: "field", OutboundTag: "blocked"},
			},
		},
	}
	return json.Marshal(cfg)
}

func mustMarshal(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func privateRanges() []string {
	return []string{
		"127.0.0.0/8",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"0.0.0.0/8",
		"100.64.0.0/10",
		"192.0.0.0/24",
		"192.0.2.0/24",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"224.0.0.0/4",
		"240.0.0.0/4",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
		"2001:db8::/32",
	}
}
