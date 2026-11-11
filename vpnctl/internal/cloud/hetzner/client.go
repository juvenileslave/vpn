// Package hetzner is a read-only client for the Hetzner Cloud API: it lists and
// reads servers and Primary IPs. It has no write operations.
//
// The client never logs; tokens, Authorization headers and raw response
// bodies are never included in returned errors.
package hetzner

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

// DefaultBaseURL is the production Hetzner Cloud API endpoint.
const DefaultBaseURL = "https://api.hetzner.cloud/v1"

const (
	// MaxResponseBytes bounds every response body read by the client.
	MaxResponseBytes = 4 << 20
	// DefaultTimeout applies to a request whose context has no deadline.
	DefaultTimeout = 30 * time.Second
	// MaxPages bounds pagination of a single list call.
	MaxPages = 1000

	perPage       = 50 // API maximum for list endpoints.
	maxID         = 1<<53 - 1
	maxMessageLen = 256
	userAgent     = "vpnctl"
)

// Sentinel errors. Use errors.Is; *APIError matches the status sentinels.
var (
	ErrUnauthorized      = errors.New("hetzner: unauthorized (401)")
	ErrForbidden         = errors.New("hetzner: forbidden (403)")
	ErrNotFound          = errors.New("hetzner: not found (404)")
	ErrRateLimited       = errors.New("hetzner: rate limited (429)")
	ErrServer            = errors.New("hetzner: server error (5xx)")
	ErrMalformedResponse = errors.New("hetzner: malformed response")
	ErrResponseTooLarge  = errors.New("hetzner: response body too large")
	ErrRedirect          = errors.New("hetzner: redirect refused")
	ErrPaginationLimit   = errors.New("hetzner: pagination limit exceeded")
)

// APIError is a non-2xx response. Code and Message come from the provider's
// error object, are length-limited and never contain the token.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
}

func (e *APIError) Error() string {
	s := "hetzner: HTTP " + strconv.Itoa(e.StatusCode)
	if e.Code != "" {
		s += " " + e.Code
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
	}
	return false
}

// Client is a read-only Hetzner Cloud API client. It is safe for concurrent use.
type Client struct {
	base  *url.URL
	token string
	http  *http.Client
}

// New validates its arguments and returns a client. It performs no network
// I/O. baseURL must be an absolute https URL without userinfo, query or
// fragment; any path prefix (such as /v1) is preserved. httpClient is copied
// and the copy refuses redirects; the caller's client is not modified.
func New(baseURL, token string, httpClient *http.Client) (*Client, error) {
	base, err := parseBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	if err := validateToken(token); err != nil {
		return nil, err
	}
	if httpClient == nil {
		return nil, errors.New("hetzner: http client is required")
	}
	hc := *httpClient
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return ErrRedirect }
	return &Client{base: base, token: token, http: &hc}, nil
}

// String hides the token from fmt verbs.
func (c *Client) String() string { return "hetzner.Client{" + c.base.Host + "}" }

// GoString hides the token from %#v.
func (c *Client) GoString() string { return c.String() }

func parseBaseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	// The raw value and the parse error are not echoed: they may embed userinfo.
	if err != nil {
		return nil, errors.New("hetzner: base URL is not a valid URL")
	}
	switch {
	case u.Scheme != "https":
		return nil, errors.New("hetzner: base URL must use https")
	case u.Host == "" || u.Opaque != "":
		return nil, errors.New("hetzner: base URL must have a host")
	case u.User != nil:
		return nil, errors.New("hetzner: base URL must not contain userinfo")
	case u.RawQuery != "" || u.ForceQuery || u.Fragment != "":
		return nil, errors.New("hetzner: base URL must not contain a query or fragment")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u, nil
}

func validateToken(token string) error {
	if token == "" {
		return errors.New("hetzner: token is required")
	}
	for _, r := range token {
		if r > unicode.MaxASCII || !unicode.IsPrint(r) || r == ' ' {
			return errors.New("hetzner: token contains invalid characters")
		}
	}
	return nil
}

// get performs a GET of base+path and decodes a 2xx JSON body into out.
func (c *Client) get(ctx context.Context, path string, query url.Values, out any) error {
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
		return fmt.Errorf("hetzner: GET %s: %w", path, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		// *url.Error carries only the request URL, which holds no credentials.
		return fmt.Errorf("hetzner: GET %s: %w", path, err)
	}
	defer resp.Body.Close()

	body, err := readBounded(resp.Body)
	if err != nil {
		return fmt.Errorf("hetzner: GET %s: %w", path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return c.apiError(resp.StatusCode, body)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("%w: GET %s: invalid JSON", ErrMalformedResponse, path)
	}
	return nil
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

func (c *Client) apiError(status int, body []byte) error {
	e := &APIError{StatusCode: status}
	var env struct {
		Error *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	// The body is untrusted: only the code and message fields are kept.
	if json.Unmarshal(body, &env) == nil && env.Error != nil {
		e.Code = c.sanitize(env.Error.Code)
		e.Message = c.sanitize(env.Error.Message)
	}
	return e
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

// pagination mirrors meta.pagination of Hetzner list responses.
type pagination struct {
	Page     *int64 `json:"page"`
	PerPage  *int64 `json:"per_page"`
	NextPage *int64 `json:"next_page"`
}

type listMeta struct {
	Pagination *pagination `json:"pagination"`
}

// listAll walks pages 1..N by following meta.pagination.next_page. fetch
// decodes one page and returns the number of items and the page metadata.
func (c *Client) listAll(ctx context.Context, path string, query url.Values,
	fetch func(ctx context.Context, q url.Values) (int, *listMeta, error)) error {
	page := int64(1)
	for n := 0; ; n++ {
		if n >= MaxPages {
			return fmt.Errorf("%w: GET %s: more than %d pages", ErrPaginationLimit, path, MaxPages)
		}
		q := url.Values{}
		for k, v := range query {
			q[k] = v
		}
		q.Set("page", strconv.FormatInt(page, 10))
		q.Set("per_page", strconv.Itoa(perPage))

		count, meta, err := fetch(ctx, q)
		if err != nil {
			return err
		}
		if meta == nil || meta.Pagination == nil || meta.Pagination.Page == nil || meta.Pagination.PerPage == nil {
			return fmt.Errorf("%w: GET %s: missing meta.pagination", ErrMalformedResponse, path)
		}
		p := meta.Pagination
		if *p.Page != page {
			return fmt.Errorf("%w: GET %s: requested page %d, got %d", ErrMalformedResponse, path, page, *p.Page)
		}
		if *p.PerPage < 1 || int64(count) > *p.PerPage {
			return fmt.Errorf("%w: GET %s: page holds %d items, per_page %d", ErrMalformedResponse, path, count, *p.PerPage)
		}
		if p.NextPage == nil {
			return nil
		}
		if *p.NextPage != page+1 {
			return fmt.Errorf("%w: GET %s: next_page %d after page %d", ErrMalformedResponse, path, *p.NextPage, page)
		}
		if count == 0 {
			return fmt.Errorf("%w: GET %s: empty page %d announces next_page", ErrMalformedResponse, path, page)
		}
		page++
	}
}

func checkID(kind string, id int64) error {
	if id < 1 || id > maxID {
		return fmt.Errorf("hetzner: invalid %s ID %d", kind, id)
	}
	return nil
}
