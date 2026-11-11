package vless

import (
	"bytes"
	"encoding/base64"
	"strings"
	"unicode/utf8"
)

// MaxSubscriptionBytes bounds the raw subscription body.
const MaxSubscriptionBytes = 1 << 20

// Encoding is the detected subscription encoding.
type Encoding string

const (
	EncodingPlain  Encoding = "plain"
	EncodingBase64 Encoding = "base64"
)

// Candidate is a successfully parsed subscription entry.
type Candidate struct {
	Entry int
	Line  int
	Link  *Link
}

// Subscription is the result of parsing a subscription body. Every entry is
// either a Candidate or an EntryError; nothing is dropped silently.
type Subscription struct {
	Encoding   Encoding
	Candidates []Candidate
	Errors     []*EntryError
}

// ParseSubscription parses an already obtained subscription body: one link per
// line, either as plain text or as standard (padded or raw) base64 of it.
// Blank lines and lines starting with '#' are skipped. The returned error is
// non-nil only when the body as a whole is unusable; per-entry failures are
// reported in Subscription.Errors.
func ParseSubscription(data []byte) (*Subscription, error) {
	if len(data) > MaxSubscriptionBytes {
		return nil, ErrTooLarge
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if !utf8.Valid(data) {
		return nil, ErrEncoding
	}
	text := string(data)
	sub := &Subscription{Encoding: EncodingPlain}
	if strings.TrimSpace(text) == "" {
		return nil, ErrEmpty
	}
	if !strings.Contains(text, "://") {
		decoded, ok := decodeBase64(text)
		if !ok {
			return nil, ErrEncoding
		}
		text, sub.Encoding = decoded, EncodingBase64
	}

	entry := 0
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entry++
		link, err := ParseLink(line)
		if err != nil {
			sub.Errors = append(sub.Errors, &EntryError{Entry: entry, Line: i + 1, Err: err})
			continue
		}
		sub.Candidates = append(sub.Candidates, Candidate{Entry: entry, Line: i + 1, Link: link})
	}
	if entry == 0 {
		return nil, ErrEmpty
	}
	return sub, nil
}

func decodeBase64(text string) (string, bool) {
	// Line-wrapped base64 is common; ASCII whitespace is not part of the data.
	compact := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, text)
	enc := base64.RawStdEncoding
	if strings.HasSuffix(compact, "=") {
		enc = base64.StdEncoding
	}
	b, err := enc.Strict().DecodeString(compact)
	if err != nil || !utf8.Valid(b) {
		return "", false
	}
	return string(b), true
}
