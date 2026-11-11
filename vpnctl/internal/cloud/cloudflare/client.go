// Package cloudflare is a read-only client for the Cloudflare API v4: it lists
// zones and DNS records. It has no write operations.
//
// The client never logs; tokens, Authorization headers and raw response
// bodies are never included in returned errors.
package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// DefaultBaseURL is the production Cloudflare API v4 endpoint.
const DefaultBaseURL = "https://api.cloudflare.com/client/v4"

const (
	// MaxResponseBytes bounds every response body read by the client.
	MaxResponseBytes = 4 << 20
	// DefaultTimeout applies to a request whose context has no deadline.
	DefaultTimeout = 30 * time.Second
	// MaxPages bounds pagination of a single list call.
	MaxPages = 1000

	maxMessageLen = 256
	userAgent     = "vpnctl"
)

// Sentinel errors. Use errors.Is; *APIError matches the status sentinels.
var (
	ErrUnauthorized      = errors.New("cloudflare: unauthorized (401)")
	ErrForbidden         = errors.New("cloudflare: forbidden (403)")
	ErrNotFound          = errors.New("cloudflare: not found (404)")
	ErrRateLimited       = errors.New("cloudflare: rate limited (429)")
	ErrServer            = errors.New("cloudflare: server error (5xx)")
	ErrUnsuccessful      = errors.New("cloudflare: success is false")
	ErrMalformedResponse = errors.New("cloudflare: malformed response")
	ErrResponseTooLarge  = errors.New("cloudflare: response body too large")
	ErrRedirect          = errors.New("cloudflare: redirect refused")
	ErrPaginationLimit   = errors.New("cloudflare: pagination limit exceeded")
)

// APIError is a non-2xx response, or a 2xx response with "success": false.
// Code and Message come from the first entry of the provider's errors array,
// are length-limited and never contain the token.
type APIError struct {
	StatusCode int
	Code       int
	Message    string
}

func (e *APIError) Error() string {
	s := "cloudflare: HTTP " + strconv.Itoa(e.StatusCode)
	if e.StatusCode >= 200 && e.StatusCode <= 299 {
		s += " success=false"
	}
	if e.Code != 0 {
		s += " code " + strconv.Itoa(e.Code)
	}
	if e.Message != "" {
		s += ": " + e.Message
	}
	return s
}

// Is maps the status code onto the sentinel errors.
func (e *APIError) Is(target error) bool {
	switch target {
	case ErrUnauthorized:
		return e.StatusCode == http.StatusUnauthorized
	case ErrForbidden:
		return e.StatusCode == http.StatusForbidden
	case ErrNotFound:
		return e.StatusCode == http.StatusNotFound
	case ErrRateLimited:
		return e.StatusCode == http.StatusTooManyRequests
	case ErrServer:
		return e.StatusCode >= 500 && e.StatusCode <= 599
	case ErrUnsuccessful:
		return e.StatusCode >= 200 && e.StatusCode <= 299
	}
	return false
}

// Client is a read-only Cloudflare API client. It is safe for concurrent use.
type Client struct {
	base  *url.URL
	token string
	http  *http.Client
}

// New validates its arguments and returns a client. It performs no network
// I/O. baseURL must be an absolute https URL without userinfo, query or
// fragment; any path prefix (such as /client/v4) is preserved. httpClient is
// copied and the copy refuses redirects; the caller's client is not modified.
func New(baseURL, token string, httpClient *http.Client) (*Client, error) {
	base, err := parseBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	if err := validateToken(token); err != nil {
		return nil, err
	}
	if httpClient == nil {
		return nil, errors.New("cloudflare: http client is required")
	}
	hc := *httpClient
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return ErrRedirect }
	return &Client{base: base, token: token, http: &hc}, nil
}

// String hides the token from fmt verbs.
func (c *Client) String() string { return "cloudflare.Client{" + c.base.Host + "}" }

// GoString hides the token from %#v.
func (c *Client) GoString() string { return c.String() }

func parseBaseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	// The raw value and the parse error are not echoed: they may embed userinfo.
	if err != nil {
		return nil, errors.New("cloudflare: base URL is not a valid URL")
	}
	switch {
	case u.Scheme != "https":
		return nil, errors.New("cloudflare: base URL must use https")
	case u.Host == "" || u.Opaque != "":
		return nil, errors.New("cloudflare: base URL must have a host")
	case u.User != nil:
		return nil, errors.New("cloudflare: base URL must not contain userinfo")
	case u.RawQuery != "" || u.ForceQuery || u.Fragment != "":
		return nil, errors.New("cloudflare: base URL must not contain a query or fragment")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u, nil
}

func validateToken(token string) error {
	if token == "" {
		return errors.New("cloudflare: token is required")
	}
	for _, r := range token {
		if r > unicode.MaxASCII || !unicode.IsPrint(r) || r == ' ' {
			return errors.New("cloudflare: token contains invalid characters")
		}
	}
	return nil
}

// errorItem is one entry of the errors/messages arrays of the v4 envelope.
type errorItem struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// resultInfo mirrors result_info of paginated v4 responses.
type resultInfo struct {
	Page       *int `json:"page"`
	PerPage    *int `json:"per_page"`
	TotalPages *int `json:"total_pages"`
	Count      *int `json:"count"`
	TotalCount *int `json:"total_count"`
}

// listEnvelope is the v4 envelope of list endpoints; Result stays raw so that
// the envelope is validated before items are decoded.
type listEnvelope struct {
	Success    *bool           `json:"success"`
	Errors     []errorItem     `json:"errors"`
	Result     json.RawMessage `json:"result"`
	ResultInfo *resultInfo     `json:"result_info"`
}

// get performs a GET of base+path and returns the validated envelope.
// label is the OpenAPI path used in error messages.
func (c *Client) get(ctx context.Context, label, path string, query url.Values) (*listEnvelope, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultTimeout)
		defer cancel()
	}
	u := *c.base
	u.Path = c.base.Path + path
	u.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("cloudflare: GET %s: %w", label, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		// *url.Error carries only the request URL, which holds no credentials.
		return nil, fmt.Errorf("cloudflare: GET %s: %w", label, err)
	}
	defer resp.Body.Close()

	body, err := readBounded(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("cloudflare: GET %s: %w", label, err)
	}
	var env listEnvelope
	decodeErr := json.Unmarshal(body, &env)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		e := &APIError{StatusCode: resp.StatusCode}
		if decodeErr == nil {
			c.fill(e, env.Errors)
		}
		return nil, e
	}
	if decodeErr != nil {
		return nil, fmt.Errorf("%w: GET %s: invalid JSON", ErrMalformedResponse, label)
	}
	if env.Success == nil {
		return nil, fmt.Errorf("%w: GET %s: missing success", ErrMalformedResponse, label)
	}
	if !*env.Success {
		e := &APIError{StatusCode: resp.StatusCode}
		c.fill(e, env.Errors)
		return nil, e
	}
	return &env, nil
}

func readBounded(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, MaxResponseBytes+1))
	if err != nil {
		// Truncated bodies (Content-Length mismatch) surface here.
		return nil, fmt.Errorf("%w: reading body: %w", ErrMalformedResponse, err)
	}
	if len(body) > MaxResponseBytes {
		return nil, ErrResponseTooLarge
	}
	return body, nil
}

func (c *Client) fill(e *APIError, items []errorItem) {
	if len(items) == 0 {
		return
	}
	e.Code = items[0].Code
	e.Message = c.sanitize(items[0].Message)
}

func (c *Client) sanitize(s string) string {
	s = strings.ReplaceAll(s, c.token, "[REDACTED]")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	if r := []rune(s); len(r) > maxMessageLen {
		s = string(r[:maxMessageLen]) + "…"
	}
	return s
}

// listAll requests pages 1..total_pages of label. decode receives each
// page's result array and returns the number of items it holds.
func (c *Client) listAll(ctx context.Context, label, path string, query url.Values, perPage int,
	decode func(result json.RawMessage) (int, error)) error {
	for page := 1; ; page++ {
		if page > MaxPages {
			return fmt.Errorf("%w: GET %s: more than %d pages", ErrPaginationLimit, label, MaxPages)
		}
		q := url.Values{}
		for k, v := range query {
			q[k] = v
		}
		q.Set("page", strconv.Itoa(page))
		q.Set("per_page", strconv.Itoa(perPage))

		env, err := c.get(ctx, label, path, q)
		if err != nil {
			return err
		}
		if len(env.Result) == 0 || string(env.Result) == "null" {
			return fmt.Errorf("%w: GET %s: missing result", ErrMalformedResponse, label)
		}
		count, err := decode(env.Result)
		if err != nil {
			return err
		}
		ri := env.ResultInfo
		if ri == nil || ri.Page == nil || ri.PerPage == nil || ri.TotalPages == nil {
			return fmt.Errorf("%w: GET %s: missing result_info", ErrMalformedResponse, label)
		}
		if *ri.Page != page {
			return fmt.Errorf("%w: GET %s: requested page %d, got %d", ErrMalformedResponse, label, page, *ri.Page)
		}
		if *ri.PerPage < 1 || count > *ri.PerPage || *ri.TotalPages < 0 {
			return fmt.Errorf("%w: GET %s: inconsistent result_info", ErrMalformedResponse, label)
		}
		if ri.Count != nil && *ri.Count != count {
			return fmt.Errorf("%w: GET %s: result_info.count %d, result holds %d", ErrMalformedResponse, label, *ri.Count, count)
		}
		if page >= *ri.TotalPages {
			return nil
		}
		if count == 0 {
			return fmt.Errorf("%w: GET %s: empty page %d of %d", ErrMalformedResponse, label, page, *ri.TotalPages)
		}
	}
}
