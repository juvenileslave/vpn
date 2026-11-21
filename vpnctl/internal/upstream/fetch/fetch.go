// Package fetch retrieves declared upstream sources and normalizes them into
// candidates. It performs no probing: fetching only downloads a bounded
// subscription body or reads one WireGuard file.
package fetch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"syscall"
	"time"

	"github.com/juvenileslave/vpn/vpnctl/internal/upstream/candidate"
	"github.com/juvenileslave/vpn/vpnctl/internal/upstream/sharelink"
	"github.com/juvenileslave/vpn/vpnctl/internal/upstream/source"
)

const (
	// DefaultTimeout bounds one subscription request.
	DefaultTimeout = 15 * time.Second
	// MaxWireguardBytes bounds a WireGuard configuration read from disk.
	MaxWireguardBytes = 64 << 10
)

var (
	ErrInvalidOptions = errors.New("fetch: invalid options")
	ErrRequest        = errors.New("fetch: subscription request failed")
	ErrResponse       = errors.New("fetch: subscription response rejected")
	ErrWireguardFile  = errors.New("fetch: wireguard file rejected")
	errBlockedDest    = errors.New("fetch: destination address is not allowed")
)

// Options configures a Fetcher.
type Options struct {
	// Client overrides the HTTP client. It must enforce its own bounded
	// timeout; the default client uses Timeout.
	Client  *http.Client
	Timeout time.Duration // 0 => DefaultTimeout
}

// Fetcher implements pipeline.Fetcher for declared sources.
type Fetcher struct {
	client *http.Client
}

// New validates options and returns a Fetcher.
func New(opts Options) (*Fetcher, error) {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	client := opts.Client
	if client == nil {
		// An explicit transport with Proxy: nil ignores HTTP_PROXY/HTTPS_PROXY
		// from the environment, so credentials cannot be routed to an
		// unexpected proxy. safeDialContext rejects loopback, private,
		// link-local, multicast and documentation destinations at dial time,
		// which also covers DNS rebinding.
		client = &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				Proxy:                 nil,
				DialContext:           safeDialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          4,
				IdleConnTimeout:       30 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: timeout,
			},
		}
	} else {
		cloned := *client
		client = &cloned
	}
	if client.Timeout <= 0 {
		client.Timeout = timeout
	}
	// Enforce the redirect policy even for a caller-supplied client: a
	// redirect must not downgrade to HTTP, carry userinfo or exceed 3 hops.
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" || req.URL.Host == "" || req.URL.User != nil {
			return fmt.Errorf("%w: redirect destination rejected", ErrResponse)
		}
		if len(via) >= 3 {
			return fmt.Errorf("%w: too many redirects", ErrResponse)
		}
		return nil
	}
	return &Fetcher{client: client}, nil
}

// Fetch retrieves src and returns parsed candidates tagged with tag. Rejects
// contain per-entry failures; the error is non-nil only when the whole source
// is unusable. Errors never contain the locator or credentials.
func (f *Fetcher) Fetch(ctx context.Context, src source.Source, tag string) ([]candidate.Candidate, []candidate.Reject, error) {
	if f == nil || f.client == nil {
		return nil, nil, ErrInvalidOptions
	}
	if ctx == nil {
		return nil, nil, ErrInvalidOptions
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	switch src.Kind() {
	case source.Subscription:
		return f.fetchSubscription(ctx, src.Locator(), tag)
	case source.WireguardFile:
		cand, err := f.fetchWireguard(src.Locator(), tag)
		if err != nil {
			return nil, nil, err
		}
		return []candidate.Candidate{cand}, nil, nil
	default:
		return nil, nil, fmt.Errorf("%w: unsupported source kind", ErrInvalidOptions)
	}
}

func (f *Fetcher) fetchSubscription(ctx context.Context, locator, tag string) ([]candidate.Candidate, []candidate.Reject, error) {
	u, err := url.Parse(locator)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, nil, fmt.Errorf("%w: invalid subscription URL", ErrInvalidOptions)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: request construction failed", ErrRequest)
	}
	req.Header.Set("Accept", "text/plain")
	resp, err := f.client.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, nil, ctxErr
		}
		if errors.Is(err, ErrResponse) {
			return nil, nil, fmt.Errorf("%w", ErrResponse)
		}
		return nil, nil, fmt.Errorf("%w", ErrRequest)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("%w: unexpected status", ErrResponse)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(sharelink.MaxSubscriptionBytes)+1))
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, nil, ctxErr
		}
		return nil, nil, fmt.Errorf("%w: body read failed", ErrResponse)
	}
	if len(body) > sharelink.MaxSubscriptionBytes {
		return nil, nil, fmt.Errorf("%w: body exceeds %d bytes", ErrResponse, sharelink.MaxSubscriptionBytes)
	}
	return candidate.ParseSubscription(body, tag)
}

func safeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, errBlockedDest
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, errBlockedDest
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var lastErr error
	for _, ip := range ips {
		if blockedIP(ip.IP) {
			continue
		}
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errBlockedDest
}

var blockedPrefixes = func() []netip.Prefix {
	raw := []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
		"192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
		"224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "100::/64",
		"2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8",
	}
	out := make([]netip.Prefix, 0, len(raw))
	for _, s := range raw {
		p, err := netip.ParsePrefix(s)
		if err == nil {
			out = append(out, p)
		}
	}
	return out
}()

func blockedIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	addr = addr.Unmap()
	for _, p := range blockedPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func (f *Fetcher) fetchWireguard(path, tag string) (candidate.Candidate, error) {
	early, err := os.Lstat(path)
	if err != nil {
		return candidate.Candidate{}, fmt.Errorf("%w: file is inaccessible", ErrWireguardFile)
	}
	if !early.Mode().IsRegular() || early.Mode()&os.ModeSymlink != 0 {
		return candidate.Candidate{}, fmt.Errorf("%w: file must be a regular non-symlink file", ErrWireguardFile)
	}
	fh, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return candidate.Candidate{}, fmt.Errorf("%w: file is inaccessible", ErrWireguardFile)
	}
	defer func() { _ = fh.Close() }()

	// Validate the opened file and the path entry together so a swap between
	// Lstat and Open (including replacing the file with a symlink) is caught.
	info, err := fh.Stat()
	if err != nil {
		return candidate.Candidate{}, fmt.Errorf("%w: file is inaccessible", ErrWireguardFile)
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, pathInfo) {
		return candidate.Candidate{}, fmt.Errorf("%w: file changed while reading", ErrWireguardFile)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return candidate.Candidate{}, fmt.Errorf("%w: file must be a regular non-symlink file", ErrWireguardFile)
	}
	if info.Mode().Perm() != 0o600 {
		return candidate.Candidate{}, fmt.Errorf("%w: file permissions must be 0600", ErrWireguardFile)
	}
	if info.Size() > MaxWireguardBytes {
		return candidate.Candidate{}, fmt.Errorf("%w: file exceeds %d bytes", ErrWireguardFile, MaxWireguardBytes)
	}

	data, err := io.ReadAll(io.LimitReader(fh, MaxWireguardBytes+1))
	if err != nil {
		return candidate.Candidate{}, fmt.Errorf("%w: file read failed", ErrWireguardFile)
	}
	if len(data) > MaxWireguardBytes {
		return candidate.Candidate{}, fmt.Errorf("%w: file exceeds %d bytes", ErrWireguardFile, MaxWireguardBytes)
	}
	return candidate.ParseWireguard(data, tag)
}
