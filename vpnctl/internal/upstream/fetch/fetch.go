// Package fetch retrieves declared upstream sources and normalizes them into
// candidates. It performs no probing: fetching only downloads a bounded
// subscription body or reads one WireGuard file.
package fetch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
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
	client := opts.Client
	if client == nil {
		timeout := opts.Timeout
		if timeout <= 0 {
			timeout = DefaultTimeout
		}
		client = &http.Client{Timeout: timeout}
	} else {
		cloned := *client
		client = &cloned
	}
	if client.CheckRedirect == nil {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" {
				return fmt.Errorf("%w: redirect to non-https", ErrResponse)
			}
			if len(via) >= 3 {
				return fmt.Errorf("%w: too many redirects", ErrResponse)
			}
			return nil
		}
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

func (f *Fetcher) fetchWireguard(path, tag string) (candidate.Candidate, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return candidate.Candidate{}, fmt.Errorf("%w: file is inaccessible", ErrWireguardFile)
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
	fh, err := os.Open(path)
	if err != nil {
		return candidate.Candidate{}, fmt.Errorf("%w: file is inaccessible", ErrWireguardFile)
	}
	defer func() { _ = fh.Close() }()

	data, err := io.ReadAll(io.LimitReader(fh, MaxWireguardBytes+1))
	if err != nil {
		return candidate.Candidate{}, fmt.Errorf("%w: file read failed", ErrWireguardFile)
	}
	if len(data) > MaxWireguardBytes {
		return candidate.Candidate{}, fmt.Errorf("%w: file exceeds %d bytes", ErrWireguardFile, MaxWireguardBytes)
	}
	return candidate.ParseWireguard(data, tag)
}
