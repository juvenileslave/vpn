// Package telegram is a small standard-library client for the Telegram Bot
// API methods used by vpnctl: getMe, getUpdates and sendMessage.
//
// The client never retries, never logs and never writes message text or the
// bot token into an error. The token is sent only in the request path, as the
// Bot API requires.
package telegram

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// Sentinel errors. Match them with errors.Is.
var (
	ErrInvalidConfig     = errors.New("telegram: invalid client configuration")
	ErrInvalidArgument   = errors.New("invalid argument")
	ErrMalformedResponse = errors.New("malformed response")
	ErrResponseTooLarge  = errors.New("response body too large")

	ErrBadRequest       = errors.New("bad request")
	ErrUnauthorized     = errors.New("unauthorized")
	ErrForbidden        = errors.New("forbidden")
	ErrNotFound         = errors.New("not found")
	ErrRateLimited      = errors.New("rate limited")
	ErrServer           = errors.New("server error")
	ErrUnexpectedStatus = errors.New("unexpected HTTP status")
)

// Error is a non-success Bot API response. It carries only the method, the
// HTTP status, the Bot API error code and, for 429, the retry delay. The
// server description, response body and request URL are never kept.
type Error struct {
	Method     string
	StatusCode int
	// Code is error_code from the Bot API envelope; 0 when absent.
	Code int
	// RetryAfter is set for 429 responses with a positive retry_after.
	RetryAfter time.Duration
}

func (e *Error) Error() string {
	status := e.StatusCode
	if e.Code != 0 && (status == 0 || (status >= 200 && status <= 299)) {
		status = e.Code
	}
	s := http.StatusText(status)
	if s == "" {
		s = strconv.Itoa(status)
	}
	return fmt.Sprintf("telegram: %s: %s", e.Method, s)
}

// Unwrap maps the response to a sentinel error. The Bot API error code wins
// over the HTTP status when both are present.
func (e *Error) Unwrap() error {
	code := e.StatusCode
	if e.Code != 0 {
		code = e.Code
	}
	switch {
	case code == http.StatusBadRequest:
		return ErrBadRequest
	case code == http.StatusUnauthorized:
		return ErrUnauthorized
	case code == http.StatusForbidden:
		return ErrForbidden
	case code == http.StatusNotFound:
		return ErrNotFound
	case code == http.StatusTooManyRequests:
		return ErrRateLimited
	case code >= 500 && code <= 599:
		return ErrServer
	default:
		return ErrUnexpectedStatus
	}
}

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrMalformedResponse}, args...)...)
}
