package vless

import (
	"errors"
	"fmt"
)

// FieldError is a parse failure attributed to one part of a link, such as
// "port", "pbk" or "extra.xmux.maxConnections".
//
// Reasons never contain the offending value: links carry credentials (the
// user ID, REALITY keys, short IDs), so errors name the field only.
type FieldError struct {
	Field  string
	Reason string
}

func (e *FieldError) Error() string {
	if e.Field == "" {
		return e.Reason
	}
	return e.Field + ": " + e.Reason
}

func fieldErr(field, format string, args ...any) error {
	return &FieldError{Field: field, Reason: fmt.Sprintf(format, args...)}
}

// EntryError reports why one subscription entry was rejected. Entry is the
// 1-based ordinal among non-blank, non-comment lines; Line is the 1-based line
// number in the (decoded) subscription text.
type EntryError struct {
	Entry int
	Line  int
	Err   error
}

func (e *EntryError) Error() string {
	return fmt.Sprintf("entry %d (line %d): %v", e.Entry, e.Line, e.Err)
}

func (e *EntryError) Unwrap() error { return e.Err }

var (
	// ErrTooLarge is returned for a subscription above MaxSubscriptionBytes.
	ErrTooLarge = errors.New("subscription is too large")
	// ErrEncoding is returned when a subscription is neither plain links nor
	// valid standard (padded or raw) base64 of UTF-8 text.
	ErrEncoding = errors.New("subscription is neither plain links nor valid base64")
	// ErrEmpty is returned when a subscription has no entries.
	ErrEmpty = errors.New("subscription has no entries")
)
