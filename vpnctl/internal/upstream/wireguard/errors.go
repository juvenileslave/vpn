package wireguard

import (
	"errors"
	"strconv"
	"strings"
)

// Error kinds. Match them with errors.Is against the value returned by Parse.
var (
	ErrSyntax      = errors.New("syntax error")
	ErrHook        = errors.New("shell hook rejected")
	ErrUnsupported = errors.New("unsupported directive")
	ErrInvalid     = errors.New("invalid value")
	ErrDuplicate   = errors.New("duplicate value")
	ErrMissing     = errors.New("missing required field")
)

// Error describes one problem in a config. It deliberately carries only the
// position, section, canonical key name and a fixed reason: never the value,
// the raw line or an unrecognised key name, which may contain key material.
type Error struct {
	Line    int    // 1-based; 0 when the problem concerns the whole file
	Section string // "Interface", "Peer 2" or "" outside any section
	Key     string // canonical key name, empty when unknown
	Kind    error  // one of the Err* kinds
	Reason  string // fixed text, never derived from config content
}

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("wireguard config")
	if e.Line > 0 {
		b.WriteString(": line ")
		b.WriteString(strconv.Itoa(e.Line))
	}
	if e.Section != "" {
		b.WriteString(": [")
		b.WriteString(e.Section)
		b.WriteString("]")
	}
	if e.Key != "" {
		b.WriteString(": ")
		b.WriteString(e.Key)
	}
	b.WriteString(": ")
	b.WriteString(e.Kind.Error())
	if e.Reason != "" {
		b.WriteString(": ")
		b.WriteString(e.Reason)
	}
	return b.String()
}

func (e *Error) Unwrap() error { return e.Kind }

// ErrorList is returned by Parse and contains every problem found.
type ErrorList []*Error

func (l ErrorList) Error() string {
	parts := make([]string, len(l))
	for i, e := range l {
		parts[i] = e.Error()
	}
	return strings.Join(parts, "\n")
}

func (l ErrorList) Unwrap() []error {
	errs := make([]error, len(l))
	for i, e := range l {
		errs[i] = e
	}
	return errs
}
