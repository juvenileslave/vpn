// Package prober probes one normalized upstream candidate through a temporary
// pinned Xray process. The process listens only on 127.0.0.1 and routes only
// the probe and optional geo endpoints through the candidate; every other
// destination, including private, loopback and link-local ranges, is blocked.
package prober

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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
	"sync"
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
	maxIPBody           = 64
	maxTagLen           = 63
	versionTimeout      = 5 * time.Second
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
	IPURL         string        // optional https endpoint returning the egress address
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
	ipURL        *url.URL
	geoURL       *url.URL
	timeout      time.Duration
	samples      int
	startTimeout time.Duration
	version      string

	versionMu sync.Mutex
	versionOK bool
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
	var ipURL *url.URL
	if opts.IPURL != "" {
		if err := validateHTTPSURL(opts.IPURL); err != nil {
			return nil, fmt.Errorf("%w: IP URL must be https", ErrInvalidOptions)
		}
		ipURL, _ = url.Parse(opts.IPURL)
	}
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
		ipURL:        ipURL,
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
	creds, err := newCredentials()
	if err != nil {
		return nil, fmt.Errorf("%w: proxy credentials failed", ErrStart)
	}
	config, err := buildConfig(port, outbound, tag, p.probeURL, p.ipURL, p.geoURL, creds)
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
		// CommandContext kills the process when cancel is called; an extra
		// Process.Kill here would race with Wait and could target a reused PID.
		cancel()
		<-waitCh
	}()

	if err := waitReady(ctx, port, p.startTimeout, waitCh); err != nil {
		return nil, err
	}

	proxyURL := &url.URL{
		Scheme: "http",
		User:   url.UserPassword(creds.User, creds.Pass),
		Host:   net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
	}
	client := &http.Client{
		Timeout: p.timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(proxyURL),
			DisableKeepAlives: true,
		},
	}
	defer client.CloseIdleConnections()

	probes := make([]selector.Probe, 0, p.samples)
	successes := 0
	for range p.samples {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		probe := p.sample(ctx, client)
		if probe.Outcome == "success" {
			successes++
		}
		probes = append(probes, probe)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if successes == 0 {
		return probes, nil
	}

	country := ""
	if p.geoURL != nil {
		country = p.observeCountry(ctx, client)
	}
	externalIP := ""
	if p.ipURL != nil {
		externalIP = p.observeIP(ctx, client)
	}
	for i := range probes {
		probes[i].Country = country
		probes[i].ExternalIP = externalIP
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
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
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

func (p *Prober) observeIP(ctx context.Context, client *http.Client) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.ipURL.String(), nil)
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxIPBody+1))
	if err != nil || len(body) > maxIPBody {
		return ""
	}
	raw := strings.TrimSpace(string(body))
	if net.ParseIP(raw) == nil {
		return ""
	}
	return raw
}

func outcomeFor(err error) string {
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		return "timeout"
	}
	return "failure"
}

func (p *Prober) checkVersion(ctx context.Context) error {
	p.versionMu.Lock()
	defer p.versionMu.Unlock()
	if p.versionOK {
		return nil
	}
	checkCtx, cancel := context.WithTimeout(ctx, versionTimeout)
	defer cancel()
	out, err := exec.CommandContext(checkCtx, p.xrayPath, "-version").CombinedOutput()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("%w: version check failed", ErrCore)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	got := strings.TrimSpace(string(out))
	if p.version != "" && !hasVersionPrefix(got, p.version) {
		return fmt.Errorf("%w: version does not match the pinned prefix", ErrCore)
	}
	p.versionOK = true
	return nil
}

func hasVersionPrefix(got, prefix string) bool {
	if !strings.HasPrefix(got, prefix) {
		return false
	}
	if len(got) == len(prefix) {
		return true
	}
	switch got[len(prefix)] {
	case ' ', '\t', '\n', '(', ',':
		return true
	default:
		return false
	}
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
			dialer := &net.Dialer{Timeout: 250 * time.Millisecond}
			conn, err := dialer.DialContext(ctx, "tcp", addr)
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

type account struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

type routingRule struct {
	Type        string   `json:"type"`
	Domain      []string `json:"domain,omitempty"`
	IP          []string `json:"ip,omitempty"`
	Network     string   `json:"network,omitempty"`
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

func buildConfig(port int, outbound json.RawMessage, tag string, probeURL, ipURL, geoURL *url.URL, creds account) ([]byte, error) {
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
	addHost := func(u *url.URL) {
		if u == nil {
			return
		}
		host := u.Hostname()
		for _, existing := range allowedDomains {
			if existing == "full:"+host {
				return
			}
		}
		allowedDomains = append(allowedDomains, "full:"+host)
	}
	addHost(ipURL)
	addHost(geoURL)
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
			Settings: map[string]any{
				"auth":     "password",
				"accounts": []account{creds},
			},
			Tag: "probe-in",
		}},
		// The first outbound is Xray's default; keep the blackhole first so
		// any traffic that escapes routing cannot use the candidate.
		Outbounds: []json.RawMessage{mustMarshal(blocked), outbound},
		Routing: routing{
			DomainStrategy: "AsIs",
			Rules: []routingRule{
				{Type: "field", Domain: allowedDomains, OutboundTag: tag},
				{Type: "field", IP: privateRanges(), OutboundTag: "blocked"},
				{Type: "field", Network: "tcp,udp", OutboundTag: "blocked"},
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

func newCredentials() (account, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return account{}, err
	}
	return account{User: hex.EncodeToString(b[:8]), Pass: hex.EncodeToString(b[8:])}, nil
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
		"::/128",
		"::1/128",
		"::ffff:0:0/96",
		"100::/64",
		"fc00::/7",
		"fec0::/10",
		"ff00::/8",
		"fe80::/10",
		"2001:db8::/32",
	}
}
