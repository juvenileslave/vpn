package globalping

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// Sentinel errors. Use errors.Is to classify an error returned by the client.
var (
	ErrInvalidConfig  = errors.New("globalping: invalid client configuration")
	ErrInvalidRequest = errors.New("globalping: invalid measurement request")
	// ErrRedirect means the API answered with a 3xx status; redirects are
	// never followed so the bearer token cannot leave the configured origin.
	ErrRedirect = errors.New("globalping: redirect refused")
	// ErrMalformedResponse covers invalid, truncated or incomplete JSON and
	// missing or inconsistent required fields and headers.
	ErrMalformedResponse = errors.New("globalping: malformed response")
	ErrResponseTooLarge  = errors.New("globalping: response body exceeds limit")
	// ErrStillInProgress is returned by WaitMeasurement when the maximum wait
	// elapses before the measurement reaches a final status.
	ErrStillInProgress = errors.New("globalping: measurement still in progress")

	// Status classes matched by *APIError.
	ErrBadRequest       = errors.New("globalping: bad request (400)")
	ErrForbidden        = errors.New("globalping: forbidden (403)")
	ErrNotFound         = errors.New("globalping: not found (404)")
	ErrNoProbes         = errors.New("globalping: no suitable probes (422)")
	ErrRateLimited      = errors.New("globalping: rate limited (429)")
	ErrServer           = errors.New("globalping: server error (5xx)")
	ErrUnexpectedStatus = errors.New("globalping: unexpected HTTP status")
)

// APIError is a non-success API response. It carries only the HTTP status,
// the machine-readable error type and rate-limit headers: the human-readable
// message and parameters are dropped because they may echo request data.
type APIError struct {
	Op         string
	StatusCode int
	// Type is error.type from the body (for example "validation_error"),
	// empty when absent or not a plain identifier.
	Type      string
	RateLimit RateLimit
	// RetryAfter is the Retry-After header value, zero when absent.
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("globalping: %s: HTTP %d", e.Op, e.StatusCode)
	if e.Type != "" {
		msg += " (" + e.Type + ")"
	}
	if e.RetryAfter > 0 {
		msg += ", retry after " + e.RetryAfter.String()
	}
	return msg
}

// Is maps the status code to the matching sentinel error.
func (e *APIError) Is(target error) bool {
	return target == e.class()
}

func (e *APIError) class() error {
	switch {
	case e.StatusCode == http.StatusBadRequest:
		return ErrBadRequest
	case e.StatusCode == http.StatusForbidden:
		return ErrForbidden
	case e.StatusCode == http.StatusNotFound:
		return ErrNotFound
	case e.StatusCode == http.StatusUnprocessableEntity:
		return ErrNoProbes
	case e.StatusCode == http.StatusTooManyRequests:
		return ErrRateLimited
	case e.StatusCode >= 500 && e.StatusCode <= 599:
		return ErrServer
	default:
		return ErrUnexpectedStatus
	}
}

// RateLimit holds the X-RateLimit-* and X-Credits-* response headers.
// A field is -1 when its header is absent or not a non-negative integer.
type RateLimit struct {
	Limit            int
	Consumed         int
	Remaining        int
	Reset            time.Duration // -1 when absent
	CreditsConsumed  int
	CreditsRemaining int
	RequestCost      int
}

func parseRateLimit(h http.Header) RateLimit {
	rl := RateLimit{
		Limit:            headerInt(h, "X-RateLimit-Limit"),
		Consumed:         headerInt(h, "X-RateLimit-Consumed"),
		Remaining:        headerInt(h, "X-RateLimit-Remaining"),
		Reset:            -1,
		CreditsConsumed:  headerInt(h, "X-Credits-Consumed"),
		CreditsRemaining: headerInt(h, "X-Credits-Remaining"),
		RequestCost:      headerInt(h, "X-Request-Cost"),
	}
	if s := headerInt(h, "X-RateLimit-Reset"); s >= 0 {
		rl.Reset = time.Duration(s) * time.Second
	}
	return rl
}

func headerInt(h http.Header, name string) int {
	n, err := strconv.Atoi(h.Get(name))
	if err != nil || n < 0 {
		return -1
	}
	return n
}

// sanitizeIdentifier keeps short machine identifiers and drops anything else,
// so server-controlled text never reaches error strings verbatim.
func sanitizeIdentifier(s string) string {
	if s == "" || len(s) > 64 {
		return ""
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return ""
		}
	}
	return s
}
