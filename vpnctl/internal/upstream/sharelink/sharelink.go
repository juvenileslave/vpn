// Package sharelink implements the strict primitives shared by the upstream
// share-link parsers: percent-decoding, host and port validation, query
// handling, display labels and subscription decoding.
//
// It is an implementation detail of the per-scheme packages, which re-export
// the error types and values they use.
package sharelink

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// MaxLinkBytes bounds the raw length of a single link.
	MaxLinkBytes = 16 << 10
	// MaxSubscriptionBytes bounds an already obtained subscription body.
	MaxSubscriptionBytes = 1 << 20
	// MaxLabelRunes bounds the display-only fragment of a link.
	MaxLabelRunes = 256
	// MaxEntries is the default entry limit for share-link subscriptions.
	MaxEntries = 1024
)

var (
	// ErrTooLarge is returned for a subscription above MaxSubscriptionBytes.
	ErrTooLarge = errors.New("subscription is too large")
	// ErrEncoding is returned when a subscription is neither plain links nor
	// valid standard (padded or raw) base64 of UTF-8 text.
	ErrEncoding = errors.New("subscription is neither plain links nor valid base64")
	// ErrEmpty is returned when a subscription has no entries.
	ErrEmpty = errors.New("subscription has no entries")
	// ErrTooManyEntries is returned when a subscription exceeds the entry
	// limit of the calling parser.
	ErrTooManyEntries = errors.New("subscription has too many entries")
)

// FieldError is a parse failure attributed to one part of a link, such as
// "port", "password" or "plugin".
//
// Reasons never contain the offending value: links carry credentials
// (passwords, user information), so errors name the field only.
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

// Fieldf builds a *FieldError with a formatted reason.
func Fieldf(field, format string, args ...any) error {
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
	schemeRe    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]{0,15}$`)
	paramNameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,31}$`)
	alpnRe      = regexp.MustCompile(`^[!-+\--~]+$`) // printable ASCII except ','
)

// ValidateLink rejects a link that is too large, not valid UTF-8 or contains
// unencoded whitespace or control characters.
func ValidateLink(raw string) error {
	if len(raw) > MaxLinkBytes {
		return Fieldf("", "link exceeds %d bytes", MaxLinkBytes)
	}
	if !utf8.ValidString(raw) {
		return Fieldf("", "link is not valid UTF-8")
	}
	for _, r := range raw {
		if r <= ' ' || r == 0x7f || unicode.IsSpace(r) {
			return Fieldf("", "link contains unencoded whitespace or control characters")
		}
	}
	return nil
}

// SplitScheme cuts "scheme://" from raw and requires scheme to equal want
// case-insensitively. The error names the scheme only when it is syntactically
// valid, and never echoes the rest of the link.
func SplitScheme(raw, want string) (string, error) {
	scheme, rest, ok := strings.Cut(raw, "://")
	if !ok {
		return "", Fieldf("scheme", "not a URI link")
	}
	if !strings.EqualFold(scheme, want) {
		if schemeRe.MatchString(scheme) {
			return "", Fieldf("scheme", "unsupported scheme %q", strings.ToLower(scheme))
		}
		return "", Fieldf("scheme", "unsupported scheme")
	}
	return rest, nil
}

// Unescape percent-decodes s exactly once. '+' stays literal, matching
// encodeURIComponent producers.
func Unescape(s string) (string, error) {
	// PathUnescape keeps '+' literal.
	v, err := url.PathUnescape(s)
	if err != nil {
		return "", fmt.Errorf("invalid percent-encoding")
	}
	if !utf8.ValidString(v) {
		return "", fmt.Errorf("decodes to invalid UTF-8")
	}
	return v, nil
}

// ParseLabel decodes the optional "#fragment" of a link. The label is
// display-only and may contain personal data: it is never used in network
// settings and must not be logged.
func ParseLabel(frag string, hasFrag bool) (string, error) {
	if !hasFrag {
		return "", nil
	}
	label, err := Unescape(frag)
	if err != nil {
		return "", Fieldf("label", "%v", err)
	}
	for _, r := range label {
		if unicode.IsControl(r) {
			return "", Fieldf("label", "contains control characters")
		}
	}
	label = strings.TrimSpace(label)
	if utf8.RuneCountInString(label) > MaxLabelRunes {
		return "", Fieldf("label", "longer than %d characters", MaxLabelRunes)
	}
	return label, nil
}

// ParseHostPort parses "host:port" where host is a DNS name (LDH, IDN only in
// xn-- form), an IPv4 literal or a bracketed IPv6 literal without a zone. Hosts
// are normalised to lower case and canonical IP text.
func ParseHostPort(s string) (string, uint16, error) {
	var host, portStr string
	if strings.HasPrefix(s, "[") {
		end := strings.IndexByte(s, ']')
		if end < 0 {
			return "", 0, Fieldf("host", "unterminated IPv6 bracket")
		}
		after := s[end+1:]
		if !strings.HasPrefix(after, ":") {
			return "", 0, Fieldf("port", "missing")
		}
		portStr = after[1:]
		addr, err := netip.ParseAddr(s[1:end])
		if err != nil || !addr.Is6() || addr.Zone() != "" {
			return "", 0, Fieldf("host", "invalid bracketed IPv6 address")
		}
		host = addr.String()
	} else {
		i := strings.LastIndexByte(s, ':')
		if i < 0 {
			return "", 0, Fieldf("port", "missing")
		}
		host, portStr = s[:i], s[i+1:]
		switch {
		case host == "":
			return "", 0, Fieldf("host", "missing")
		case strings.Contains(host, ":"):
			return "", 0, Fieldf("host", "IPv6 address must be in brackets")
		}
		if addr, err := netip.ParseAddr(host); err == nil && addr.Is4() {
			host = addr.String()
		} else if ValidDNSName(host) {
			host = strings.ToLower(host)
		} else {
			return "", 0, Fieldf("host", "not an IPv4 address or DNS name")
		}
	}
	port, err := ParsePort(portStr)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

// ParsePort parses a decimal port number 1-65535 without leading zeros.
func ParsePort(s string) (uint16, error) {
	if s == "" {
		return 0, Fieldf("port", "missing")
	}
	if len(s) > 5 || (len(s) > 1 && s[0] == '0') || strings.Trim(s, "0123456789") != "" {
		return 0, Fieldf("port", "not a decimal port number")
	}
	n, _ := strconv.Atoi(s)
	if n < 1 || n > 65535 {
		return 0, Fieldf("port", "out of range 1-65535")
	}
	return uint16(n), nil
}

// ValidDNSName accepts LDH names (IDNs must already be in xn-- form). An
// all-numeric final label is rejected so that malformed IPv4 addresses are not
// mistaken for names.
func ValidDNSName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range len(label) {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return strings.Trim(labels[len(labels)-1], "0123456789") != ""
}

// HasControl reports whether s contains a control character.
func HasControl(s string) bool {
	return strings.IndexFunc(s, unicode.IsControl) >= 0
}

// Params is a parsed query string. Keys are consumed so that unknown and
// inapplicable parameters are never ignored silently.
type Params map[string]string

// ParseQuery parses an undeclared-order query string. Empty parameters,
// malformed names, missing values, duplicates and invalid percent-encoding are
// errors; values are percent-decoded exactly once.
func ParseQuery(raw string) (Params, error) {
	params := Params{}
	if raw == "" {
		return params, nil
	}
	for _, part := range strings.Split(raw, "&") {
		if part == "" {
			return nil, Fieldf("query", "empty parameter")
		}
		k, v, hasValue := strings.Cut(part, "=")
		if !paramNameRe.MatchString(k) {
			return nil, Fieldf("query", "malformed parameter name")
		}
		if !hasValue {
			return nil, Fieldf(k, "missing value")
		}
		if _, dup := params[k]; dup {
			return nil, Fieldf(k, "duplicate parameter")
		}
		val, err := Unescape(v)
		if err != nil {
			return nil, Fieldf(k, "%v", err)
		}
		params[k] = val
	}
	return params, nil
}

// Take returns the value of key and marks it consumed.
func (p Params) Take(key string) (string, bool) {
	v, ok := p[key]
	delete(p, key)
	return v, ok
}

// TakeNonEmpty returns the value of an optional parameter that must not be
// empty when present.
func (p Params) TakeNonEmpty(key string) (string, bool, error) {
	v, ok := p.Take(key)
	if ok && v == "" {
		return "", false, Fieldf(key, "must not be empty")
	}
	return v, ok, nil
}

// TakeALPN consumes the optional alpn parameter: a comma-separated list of
// non-empty IANA protocol tokens without duplicates.
func (p Params) TakeALPN() ([]string, bool, error) {
	v, ok, err := p.TakeNonEmpty("alpn")
	switch {
	case err != nil:
		return nil, false, err
	case !ok:
		return nil, false, nil
	}
	var alpn []string
	for _, a := range strings.Split(v, ",") {
		switch {
		case a == "" || !alpnRe.MatchString(a):
			return nil, false, Fieldf("alpn", "malformed protocol list")
		case slices.Contains(alpn, a):
			return nil, false, Fieldf("alpn", "duplicate protocol")
		}
		alpn = append(alpn, a)
	}
	return alpn, true, nil
}

// Keys returns the remaining parameter names in sorted order.
func (p Params) Keys() []string {
	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
