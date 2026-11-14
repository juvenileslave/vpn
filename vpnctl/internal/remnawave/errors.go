package remnawave

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

// Sentinel errors. Match them with errors.Is.
var (
	ErrInvalidConfig     = errors.New("remnawave: invalid client configuration")
	ErrInvalidArgument   = errors.New("invalid argument")
	ErrMalformedResponse = errors.New("malformed response")
	ErrResponseTooLarge  = errors.New("response body too large")

	ErrRedirect         = errors.New("redirect refused")
	ErrBadRequest       = errors.New("bad request")
	ErrUnauthorized     = errors.New("unauthorized")
	ErrForbidden        = errors.New("forbidden")
	ErrNotFound         = errors.New("not found")
	ErrRateLimited      = errors.New("rate limited")
	ErrServer           = errors.New("server error")
	ErrUnexpectedStatus = errors.New("unexpected HTTP status")
)

// safeCause preserves errors.Is/As without formatting a transport or body-read
// error that may quote request URLs, credentials or server-controlled text.
type safeCause struct{ cause error }

func (e safeCause) Error() string    { return "transport or response read failure" }
func (e safeCause) String() string   { return e.Error() }
func (e safeCause) GoString() string { return e.Error() }
func (e safeCause) Unwrap() error    { return e.cause }

// APIError is a non-2xx response. It carries only the status, the panel error
// code (such as "A025") and Retry-After; the response message, body and the
// redirect location are never kept.
type APIError struct {
	StatusCode int
	// Code is the panel errorCode when the body had a well-formed one.
	Code string
	// RetryAfter is set for 429 responses with a valid Retry-After header.
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	s := "HTTP " + strconv.Itoa(e.StatusCode)
	if text := http.StatusText(e.StatusCode); text != "" {
		s += " " + text
	}
	if e.Code != "" {
		s += " (code " + e.Code + ")"
	}
	return fmt.Sprintf("%v: %s", e.Unwrap(), s)
}

// Unwrap maps the status to a sentinel error.
func (e *APIError) Unwrap() error {
	switch s := e.StatusCode; {
	case s >= 300 && s <= 399:
		return ErrRedirect
	case s == http.StatusBadRequest:
		return ErrBadRequest
	case s == http.StatusUnauthorized:
		return ErrUnauthorized
	case s == http.StatusForbidden:
		return ErrForbidden
	case s == http.StatusNotFound:
		return ErrNotFound
	case s == http.StatusTooManyRequests:
		return ErrRateLimited
	case s >= 500 && s <= 599:
		return ErrServer
	default:
		return ErrUnexpectedStatus
	}
}

var errorCodePattern = regexp.MustCompile(`^[A-Z][0-9]{3}$`)

// extractErrorCode returns errorCode from a panel error body, or "" if it is
// absent or not shaped like a code, so arbitrary text never reaches errors.
func extractErrorCode(body []byte) string {
	var v struct {
		ErrorCode string `json:"errorCode"`
	}
	if json.Unmarshal(body, &v) != nil || !errorCodePattern.MatchString(v.ErrorCode) {
		return ""
	}
	return v.ErrorCode
}

func parseRetryAfter(h string) time.Duration {
	if h == "" {
		return 0
	}
	if secs, err := strconv.Atoi(h); err == nil {
		if secs < 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(h); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}
