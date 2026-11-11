// Package globalping is a minimal client for the Globalping API
// (https://globalping.io): it creates HTTP measurements from probes in
// Russia, polls them to completion and returns typed results.
//
// The client never follows redirects, never retries automatically, bounds
// every response body and never includes the bearer token in errors.
package globalping

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// DefaultBaseURL is the public Globalping API origin.
	DefaultBaseURL = "https://api.globalping.io"
	// DefaultPollInterval is the wait after each in-progress response. The
	// API asks clients not to poll more often (at most two requests per
	// second), so smaller values are rejected.
	DefaultPollInterval = 500 * time.Millisecond
	// DefaultMaxWait bounds WaitMeasurement when Config.MaxWait is zero.
	DefaultMaxWait = time.Minute
	// DefaultHTTPTimeout is used when Config.HTTPClient is nil.
	DefaultHTTPTimeout = 30 * time.Second

	// MaxLimit is the API maximum of probes per measurement (with a token).
	MaxLimit = 500

	// Up to 500 results, each with up to 10 KB of raw body echoed twice.
	maxMeasurementBytes = 32 << 20
	maxSmallBodyBytes   = 64 << 10
	maxIDLength         = 128
)

// Country is the only probe location used by this client.
const Country = "RU"

// Config configures a Client.
type Config struct {
	// BaseURL is an https URL without userinfo, query or fragment. A path
	// prefix is preserved. Empty means DefaultBaseURL.
	BaseURL string
	// Token is an optional bearer token. It is sent only to BaseURL.
	Token string
	// HTTPClient is copied; its CheckRedirect is replaced to refuse
	// redirects. A transport with InsecureSkipVerify is rejected. Nil means
	// a client with DefaultHTTPTimeout and the default transport.
	HTTPClient *http.Client
	// UserAgent is required; the API asks clients to identify themselves.
	UserAgent string
	// PollInterval is the wait after each in-progress response; zero means
	// DefaultPollInterval, smaller positive values are rejected.
	PollInterval time.Duration
	// MaxWait bounds WaitMeasurement; zero means DefaultMaxWait.
	MaxWait time.Duration
}

// Client talks to the Globalping API. It is safe for concurrent use.
type Client struct {
	base         *url.URL
	http         *http.Client
	userAgent    string
	pollInterval time.Duration
	maxWait      time.Duration
	// authorize is a closure so the token is not a struct field that fmt
	// could print.
	authorize func(*http.Request)
}

// New validates cfg and returns a Client.
func New(cfg Config) (*Client, error) {
	raw := cfg.BaseURL
	if raw == "" {
		raw = DefaultBaseURL
	}
	base, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: base URL is not a valid URL", ErrInvalidConfig)
	}
	switch {
	case base.Scheme != "https":
		return nil, fmt.Errorf("%w: base URL scheme must be https", ErrInvalidConfig)
	case base.Host == "" || base.Hostname() == "":
		return nil, fmt.Errorf("%w: base URL has no host", ErrInvalidConfig)
	case base.User != nil:
		return nil, fmt.Errorf("%w: base URL must not contain userinfo", ErrInvalidConfig)
	case base.RawQuery != "" || base.ForceQuery || base.Fragment != "" || base.Opaque != "":
		return nil, fmt.Errorf("%w: base URL must not contain query or fragment", ErrInvalidConfig)
	}
	base = &url.URL{Scheme: base.Scheme, Host: base.Host, Path: strings.TrimRight(base.Path, "/")}

	if cfg.UserAgent == "" || strings.ContainsAny(cfg.UserAgent, "\r\n\x00") {
		return nil, fmt.Errorf("%w: user agent is required and must be a single line", ErrInvalidConfig)
	}
	for _, r := range cfg.Token {
		if r <= ' ' || r == 0x7f {
			return nil, fmt.Errorf("%w: token contains whitespace or control characters", ErrInvalidConfig)
		}
	}

	poll := cfg.PollInterval
	switch {
	case poll == 0:
		poll = DefaultPollInterval
	case poll < DefaultPollInterval:
		return nil, fmt.Errorf("%w: poll interval must be at least %s", ErrInvalidConfig, DefaultPollInterval)
	}
	maxWait := cfg.MaxWait
	switch {
	case maxWait == 0:
		maxWait = DefaultMaxWait
	case maxWait < 0:
		return nil, fmt.Errorf("%w: max wait must be positive", ErrInvalidConfig)
	}

	var hc http.Client
	if cfg.HTTPClient != nil {
		hc = *cfg.HTTPClient
	} else {
		hc.Timeout = DefaultHTTPTimeout
	}
	if t, ok := hc.Transport.(*http.Transport); ok && t.TLSClientConfig != nil && t.TLSClientConfig.InsecureSkipVerify {
		return nil, fmt.Errorf("%w: TLS verification must not be disabled", ErrInvalidConfig)
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	authorize := func(*http.Request) {}
	if cfg.Token != "" {
		header := "Bearer " + cfg.Token
		authorize = func(r *http.Request) { r.Header.Set("Authorization", header) }
	}

	return &Client{
		base:         base,
		http:         &hc,
		userAgent:    cfg.UserAgent,
		pollInterval: poll,
		maxWait:      maxWait,
		authorize:    authorize,
	}, nil
}

type wireLocation struct {
	Country string `json:"country"`
}

type wireHTTPRequestOptions struct {
	Host   string `json:"host,omitempty"`
	Path   string `json:"path,omitempty"`
	Query  string `json:"query,omitempty"`
	Method string `json:"method,omitempty"`
}

type wireHTTPOptions struct {
	Request   *wireHTTPRequestOptions `json:"request,omitempty"`
	Protocol  string                  `json:"protocol,omitempty"`
	Port      int                     `json:"port,omitempty"`
	IPVersion int                     `json:"ipVersion,omitempty"`
}

type wireCreateRequest struct {
	Type               string          `json:"type"`
	Target             string          `json:"target"`
	Locations          []wireLocation  `json:"locations"`
	Limit              int             `json:"limit"`
	MeasurementOptions wireHTTPOptions `json:"measurementOptions"`
}

func buildCreateRequest(r HTTPMeasurementRequest) (wireCreateRequest, error) {
	invalid := func(format string, args ...any) (wireCreateRequest, error) {
		return wireCreateRequest{}, fmt.Errorf("%w: "+format, append([]any{ErrInvalidRequest}, args...)...)
	}
	if err := validateTarget(r.Target); err != nil {
		return invalid("%v", err)
	}
	limit := r.Limit
	if limit == 0 {
		limit = 1
	}
	if limit < 1 || limit > MaxLimit {
		return invalid("limit must be between 1 and %d", MaxLimit)
	}
	switch r.Protocol {
	case "", ProtocolHTTP, ProtocolHTTPS, ProtocolHTTP2:
	default:
		return invalid("protocol must be HTTP, HTTPS or HTTP2")
	}
	if r.Port < 0 || r.Port > 65535 {
		return invalid("port must be between 1 and 65535")
	}
	switch r.IPVersion {
	case 0:
	case 4, 6:
		if net.ParseIP(r.Target) != nil {
			return invalid("ipVersion is only allowed for hostname targets")
		}
	default:
		return invalid("ipVersion must be 4 or 6")
	}
	switch r.Method {
	case "", http.MethodHead, http.MethodGet, http.MethodOptions:
	default:
		return invalid("method must be HEAD, GET or OPTIONS")
	}
	if r.Path != "" && !strings.HasPrefix(r.Path, "/") {
		return invalid("path must start with /")
	}
	if strings.HasPrefix(r.Query, "?") {
		return invalid("query must not start with ?")
	}
	for _, s := range []string{r.Path, r.Query, r.Host} {
		if strings.ContainsAny(s, " \t\r\n\x00#") {
			return invalid("path, query and host must not contain whitespace, control characters or #")
		}
	}

	opts := wireHTTPOptions{Protocol: r.Protocol, Port: r.Port, IPVersion: r.IPVersion}
	if r.Host != "" || r.Path != "" || r.Query != "" || r.Method != "" {
		opts.Request = &wireHTTPRequestOptions{Host: r.Host, Path: r.Path, Query: r.Query, Method: r.Method}
	}
	return wireCreateRequest{
		Type:               "http",
		Target:             r.Target,
		Locations:          []wireLocation{{Country: Country}},
		Limit:              limit,
		MeasurementOptions: opts,
	}, nil
}

func validateTarget(t string) error {
	if t == "" {
		return errors.New("target is required")
	}
	if len(t) > 253 {
		return errors.New("target is too long")
	}
	if net.ParseIP(t) != nil {
		return nil
	}
	for _, r := range t {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.') {
			return errors.New("target must be a hostname or IP address without scheme, port or path")
		}
	}
	return nil
}

type wireCreateResponse struct {
	ID          *string `json:"id"`
	ProbesCount *int    `json:"probesCount"`
}

// CreateHTTPMeasurement creates an HTTP measurement from probes in Russia.
// Only a 202 response with a valid Location header, id and probesCount is
// accepted. The request is sent once.
func (c *Client) CreateHTTPMeasurement(ctx context.Context, r HTTPMeasurementRequest) (*CreatedMeasurement, error) {
	const op = "create measurement"
	payload, err := buildCreateRequest(r)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("globalping: %s: encode request: %w", op, err)
	}

	u := c.endpoint("/v1/measurements")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("globalping: %s: build request failed", op)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, data, err := c.do(ctx, op, req, http.StatusAccepted, maxSmallBodyBytes)
	if err != nil {
		return nil, err
	}

	var wire wireCreateResponse
	if err := decodeStrict(data, &wire); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrMalformedResponse, op, err)
	}
	if wire.ID == nil || validateID(*wire.ID) != nil {
		return nil, fmt.Errorf("%w: %s: missing or invalid id", ErrMalformedResponse, op)
	}
	if wire.ProbesCount == nil || *wire.ProbesCount < 0 {
		return nil, fmt.Errorf("%w: %s: missing or invalid probesCount", ErrMalformedResponse, op)
	}
	loc, err := c.checkLocation(u, resp.Header.Get("Location"), *wire.ID)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrMalformedResponse, op, err)
	}
	return &CreatedMeasurement{
		ID:          *wire.ID,
		ProbesCount: *wire.ProbesCount,
		Location:    loc,
		RateLimit:   parseRateLimit(resp.Header),
	}, nil
}

// checkLocation requires the Location header to name the created
// measurement on the configured origin.
func (c *Client) checkLocation(reqURL *url.URL, raw, id string) (string, error) {
	if raw == "" {
		return "", errors.New("missing Location header")
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("invalid Location header")
	}
	loc := reqURL.ResolveReference(ref)
	want := c.endpoint("/v1/measurements/" + url.PathEscape(id))
	if loc.Scheme != want.Scheme || loc.Host != want.Host || loc.EscapedPath() != want.EscapedPath() ||
		loc.User != nil || loc.RawQuery != "" || loc.Fragment != "" {
		return "", errors.New("Location header does not match the created measurement")
	}
	return loc.String(), nil
}

// Measurement fetches the current state of a measurement once.
func (c *Client) Measurement(ctx context.Context, id string) (*Measurement, error) {
	const op = "get measurement"
	if err := validateID(id); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	u := c.endpoint("/v1/measurements/" + url.PathEscape(id))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("globalping: %s: build request failed", op)
	}
	_, data, err := c.do(ctx, op, req, http.StatusOK, maxMeasurementBytes)
	if err != nil {
		return nil, err
	}
	var wire wireMeasurement
	if err := decodeStrict(data, &wire); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrMalformedResponse, op, err)
	}
	m, err := wire.toMeasurement(id)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrMalformedResponse, op, err)
	}
	return m, nil
}

// WaitMeasurement polls a measurement until its status is final, waiting
// the poll interval after each in-progress response. It stops at the first
// error, when ctx is done, or after the configured maximum wait; in the last
// case the error wraps ErrStillInProgress and context.DeadlineExceeded.
func (c *Client) WaitMeasurement(ctx context.Context, id string) (*Measurement, error) {
	ctx, cancel := context.WithTimeoutCause(ctx, c.maxWait, ErrStillInProgress)
	defer cancel()

	timer := time.NewTimer(0)
	defer timer.Stop()
	<-timer.C
	for {
		m, err := c.Measurement(ctx, id)
		if err != nil {
			return nil, waitError(ctx, err)
		}
		if m.Status != StatusInProgress {
			return m, nil
		}
		timer.Reset(c.pollInterval)
		select {
		case <-ctx.Done():
			return nil, waitError(ctx, ctx.Err())
		case <-timer.C:
		}
	}
}

func waitError(ctx context.Context, err error) error {
	if errors.Is(context.Cause(ctx), ErrStillInProgress) && errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: %w", ErrStillInProgress, context.DeadlineExceeded)
	}
	return err
}

func (c *Client) endpoint(p string) *url.URL {
	u := *c.base
	u.Path = c.base.Path + p
	u.RawPath = ""
	return &u
}

// do sends req once and returns the bounded body of a response with the
// wanted status. Other statuses become *APIError, 3xx become ErrRedirect.
func (c *Client) do(ctx context.Context, op string, req *http.Request, want int, limit int64) (*http.Response, []byte, error) {
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	c.authorize(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, transportError(ctx, op, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode <= 399 {
		return nil, nil, fmt.Errorf("%w: %s: HTTP %d", ErrRedirect, op, resp.StatusCode)
	}
	if resp.StatusCode != want {
		apiErr := &APIError{Op: op, StatusCode: resp.StatusCode, RateLimit: parseRateLimit(resp.Header)}
		if s := headerInt(resp.Header, "Retry-After"); s > 0 {
			apiErr.RetryAfter = time.Duration(s) * time.Second
		}
		if data, err := readLimited(resp.Body, maxSmallBodyBytes); err == nil {
			var body struct {
				Error struct {
					Type string `json:"type"`
				} `json:"error"`
			}
			if json.Unmarshal(data, &body) == nil {
				apiErr.Type = sanitizeIdentifier(body.Error.Type)
			}
		}
		return nil, nil, apiErr
	}

	data, err := readLimited(resp.Body, limit)
	if err != nil {
		if errors.Is(err, ErrResponseTooLarge) {
			return nil, nil, fmt.Errorf("%w: %s: more than %d bytes", ErrResponseTooLarge, op, limit)
		}
		return nil, nil, transportError(ctx, op, err)
	}
	return resp, data, nil
}

// transportError drops the request URL and wraps the context error when the
// context ended, so errors.Is(err, context.Canceled) keeps working.
func transportError(ctx context.Context, op string, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("globalping: %s: %w", op, ctxErr)
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		err = urlErr.Err
	}
	return fmt.Errorf("globalping: %s: request failed: %w", op, err)
}

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, ErrResponseTooLarge
	}
	return data, nil
}

// decodeStrict decodes exactly one JSON value. Unknown fields are allowed
// (the API may add them); trailing data and truncation are not.
func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(v); err != nil {
		return errors.New("invalid JSON")
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data after JSON value")
	}
	return nil
}

func validateID(id string) error {
	if id == "" || len(id) > maxIDLength {
		return errors.New("measurement id must be 1..128 characters")
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return errors.New("measurement id contains unsupported characters")
		}
	}
	return nil
}
