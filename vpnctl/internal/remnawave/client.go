// Package remnawave is a read-only client for the Remnawave panel REST API.
//
// It covers only GET /api/users, GET /api/users/{userId} and GET /api/nodes as
// described by the official Remnawave OpenAPI specification 3.4.10. The client
// never writes, never retries and never logs. Exported models deliberately omit
// protocol credentials, subscription URLs and raw response bodies.
package remnawave

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
)

const (
	// DefaultMaxResponseBytes bounds a successful response body. A full page
	// of 1000 users stays well below this limit.
	DefaultMaxResponseBytes int64 = 16 << 20

	// MaxPageSize is the largest page size accepted by GET /api/users.
	MaxPageSize = 1000

	// maxErrorBodyBytes bounds how much of an error body is read to extract
	// its error code.
	maxErrorBodyBytes int64 = 64 << 10
)

// Client is a read-only Remnawave API client. It is safe for concurrent use.
type Client struct {
	base     *url.URL
	token    string
	http     *http.Client
	maxBytes int64
}

// Option customises a Client.
type Option func(*Client) error

// WithMaxResponseBytes sets the maximum accepted size of a successful
// response body.
func WithMaxResponseBytes(n int64) Option {
	return func(c *Client) error {
		if n <= 0 {
			return fmt.Errorf("%w: max response bytes must be positive", ErrInvalidConfig)
		}
		c.maxBytes = n
		return nil
	}
}

// New returns a client for the panel at baseURL. baseURL must be an absolute
// https URL without userinfo, query or fragment; a path such as "/panel" is
// kept as a prefix for every API path. token is sent as a bearer token.
//
// httpClient is required and is copied: the copy refuses every redirect, so
// the token is never sent to another location. A transport that disables TLS
// verification is rejected. New performs no network I/O.
func New(baseURL *url.URL, token string, httpClient *http.Client, opts ...Option) (*Client, error) {
	if baseURL == nil {
		return nil, fmt.Errorf("%w: base URL is required", ErrInvalidConfig)
	}
	switch {
	case baseURL.Scheme != "https":
		return nil, fmt.Errorf("%w: base URL scheme must be https", ErrInvalidConfig)
	case baseURL.Host == "" || baseURL.Hostname() == "":
		return nil, fmt.Errorf("%w: base URL must have a host", ErrInvalidConfig)
	case baseURL.User != nil:
		// The userinfo itself is never repeated in the error.
		return nil, fmt.Errorf("%w: base URL must not contain userinfo", ErrInvalidConfig)
	case baseURL.RawQuery != "" || baseURL.ForceQuery || baseURL.Fragment != "":
		return nil, fmt.Errorf("%w: base URL must not contain a query or fragment", ErrInvalidConfig)
	}
	if token == "" {
		return nil, fmt.Errorf("%w: token is required", ErrInvalidConfig)
	}
	for i := 0; i < len(token); i++ {
		if token[i] <= ' ' || token[i] == 0x7f {
			return nil, fmt.Errorf("%w: token contains whitespace or control characters", ErrInvalidConfig)
		}
	}
	if httpClient == nil {
		return nil, fmt.Errorf("%w: HTTP client is required", ErrInvalidConfig)
	}
	if t, ok := httpClient.Transport.(*http.Transport); ok && t.TLSClientConfig != nil && t.TLSClientConfig.InsecureSkipVerify {
		return nil, fmt.Errorf("%w: TLS certificate verification must not be disabled", ErrInvalidConfig)
	}

	hc := *httpClient
	transport := hc.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	hc.Transport = redirectGuard{next: transport}
	// Defence in depth; redirectGuard already stops every 3xx.
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	base := *baseURL
	base.User = nil
	c := &Client{base: &base, token: token, http: &hc, maxBytes: DefaultMaxResponseBytes}
	for _, opt := range opts {
		if err := opt(c); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// String hides the token from fmt verbs such as %v and %+v.
func (c *Client) String() string { return "remnawave.Client{token: redacted}" }

// GoString hides the token from %#v.
func (c *Client) GoString() string { return c.String() }

// ListUsers returns one page of users using offset pagination: start is the
// zero-based offset, size the page size (1..MaxPageSize).
func (c *Client) ListUsers(ctx context.Context, start, size int) (UsersPage, error) {
	const op = "list users"
	if start < 0 {
		return UsersPage{}, fmt.Errorf("remnawave: %s: %w: start must not be negative", op, ErrInvalidArgument)
	}
	if size < 1 || size > MaxPageSize {
		return UsersPage{}, fmt.Errorf("remnawave: %s: %w: size must be between 1 and %d", op, ErrInvalidArgument, MaxPageSize)
	}
	q := url.Values{}
	q.Set("start", strconv.Itoa(start))
	q.Set("size", strconv.Itoa(size))
	body, err := c.get(ctx, op, q, "api", "users")
	if err != nil {
		return UsersPage{}, err
	}
	page, err := decodeUsersPage(body)
	if err != nil {
		return UsersPage{}, fmt.Errorf("remnawave: %s: %w", op, err)
	}
	return page, nil
}

// User returns the user with the given numeric panel ID.
func (c *Client) User(ctx context.Context, id int64) (User, error) {
	const op = "get user"
	if id <= 0 {
		return User{}, fmt.Errorf("remnawave: %s: %w: id must be positive", op, ErrInvalidArgument)
	}
	body, err := c.get(ctx, op, nil, "api", "users", strconv.FormatInt(id, 10))
	if err != nil {
		return User{}, err
	}
	u, err := decodeUser(body)
	if err != nil {
		return User{}, fmt.Errorf("remnawave: %s: %w", op, err)
	}
	return u, nil
}

// ListNodes returns all nodes.
func (c *Client) ListNodes(ctx context.Context) ([]Node, error) {
	const op = "list nodes"
	body, err := c.get(ctx, op, nil, "api", "nodes")
	if err != nil {
		return nil, err
	}
	nodes, err := decodeNodes(body)
	if err != nil {
		return nil, fmt.Errorf("remnawave: %s: %w", op, err)
	}
	return nodes, nil
}

func (c *Client) get(ctx context.Context, op string, query url.Values, elem ...string) ([]byte, error) {
	if ctx == nil {
		return nil, fmt.Errorf("remnawave: %s: %w: context is required", op, ErrInvalidArgument)
	}
	u := c.base.JoinPath(elem...)
	u.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("remnawave: %s: build request: %w", op, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		// url.Error repeats the request URL; keep only the cause.
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		if ctxErr := ctx.Err(); ctxErr != nil && !errors.Is(err, ctxErr) {
			err = fmt.Errorf("%w (%w)", ctxErr, err)
		}
		return nil, fmt.Errorf("remnawave: %s: %w", op, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("remnawave: %s: %w", op, newAPIError(resp))
	}
	if mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		return nil, fmt.Errorf("remnawave: %s: %w: content type is not application/json", op, ErrMalformedResponse)
	}
	if resp.ContentLength > c.maxBytes {
		return nil, fmt.Errorf("remnawave: %s: %w (limit %d bytes)", op, ErrResponseTooLarge, c.maxBytes)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBytes+1))
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("remnawave: %s: read body: %w", op, ctxErr)
		}
		return nil, fmt.Errorf("remnawave: %s: read body: %w", op, err)
	}
	if int64(len(body)) > c.maxBytes {
		return nil, fmt.Errorf("remnawave: %s: %w (limit %d bytes)", op, ErrResponseTooLarge, c.maxBytes)
	}
	return body, nil
}

// redirectGuard turns every 3xx response into an *APIError inside the
// transport. http.Client parses Location before calling CheckRedirect and
// quotes a malformed Location in its error, which could echo credentials.
type redirectGuard struct{ next http.RoundTripper }

func (g redirectGuard) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := g.next.RoundTrip(req)
	if err != nil || resp.StatusCode < 300 || resp.StatusCode > 399 {
		return resp, err
	}
	_ = resp.Body.Close()
	return nil, &APIError{StatusCode: resp.StatusCode}
}

func newAPIError(resp *http.Response) *APIError {
	e := &APIError{StatusCode: resp.StatusCode}
	if resp.StatusCode == http.StatusTooManyRequests {
		e.RetryAfter = parseRetryAfter(resp.Header.Get("Retry-After"))
	}
	if resp.StatusCode >= 300 && resp.StatusCode <= 399 {
		return e
	}
	if mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err == nil && mt == "application/json" {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		e.Code = extractErrorCode(body)
	}
	return e
}
