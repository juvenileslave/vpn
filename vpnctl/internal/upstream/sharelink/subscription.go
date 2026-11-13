package sharelink

import (
	"bytes"
	"encoding/base64"
	"strings"
	"unicode/utf8"
)

// Encoding is the detected subscription encoding.
type Encoding string

const (
	EncodingPlain  Encoding = "plain"
	EncodingBase64 Encoding = "base64"
)

// Entry is one non-blank, non-comment line of a decoded subscription.
// Text may contain credentials.
type Entry struct {
	Number int    // 1-based ordinal among entries
	Line   int    // 1-based line number in the decoded text
	Text   string // trimmed line
}

// Document is a decoded subscription body.
type Document struct {
	Encoding Encoding
	Entries  []Entry
}

// Decode parses an already obtained subscription body: one link per line,
// either as plain text or as standard (padded or raw) base64 of it. Blank lines
// and lines starting with '#' are skipped. The returned error is one of
// ErrTooLarge, ErrEncoding or ErrEmpty; per-entry failures are left to the
// calling parser.
func Decode(data []byte) (*Document, error) {
	if len(data) > MaxSubscriptionBytes {
		return nil, ErrTooLarge
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if !utf8.Valid(data) {
		return nil, ErrEncoding
	}
	text := string(data)
	if strings.TrimSpace(text) == "" {
		return nil, ErrEmpty
	}
	doc := &Document{Encoding: EncodingPlain}
	if !strings.Contains(text, "://") {
		decoded, ok := decodeSubscriptionBase64(text)
		if !ok {
			return nil, ErrEncoding
		}
		text, doc.Encoding = decoded, EncodingBase64
	}
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		doc.Entries = append(doc.Entries, Entry{Number: len(doc.Entries) + 1, Line: i + 1, Text: line})
	}
	if len(doc.Entries) == 0 {
		return nil, ErrEmpty
	}
	return doc, nil
}

// decodeSubscriptionBase64 follows the accepted subscription rules: standard
// base64 only (URL-safe is rejected), padding optional, line wrapping allowed.
func decodeSubscriptionBase64(text string) (string, bool) {
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

// DecodeBase64 decodes standard or URL-safe base64, padded or unpadded, and
// requires the result to be valid UTF-8. It is used for SIP002 userinfo and
// legacy shadowsocks payloads, not for subscription bodies.
func DecodeBase64(text string) (string, bool) {
	for _, enc := range [...]*base64.Encoding{
		base64.RawStdEncoding, base64.StdEncoding,
		base64.RawURLEncoding, base64.URLEncoding,
	} {
		if b, err := enc.Strict().DecodeString(text); err == nil && utf8.Valid(b) {
			return string(b), true
		}
	}
	return "", false
}
