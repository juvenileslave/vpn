package vless

import (
	"errors"

	"github.com/juvenileslave/vpn/vpnctl/internal/upstream/sharelink"
)

// MaxSubscriptionBytes bounds the raw subscription body.
const MaxSubscriptionBytes = sharelink.MaxSubscriptionBytes

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
	doc, err := sharelink.Decode(data)
	switch {
	case errors.Is(err, sharelink.ErrTooLarge):
		return nil, ErrTooLarge
	case errors.Is(err, sharelink.ErrEmpty):
		return nil, ErrEmpty
	case err != nil:
		return nil, ErrEncoding
	}

	sub := &Subscription{Encoding: Encoding(doc.Encoding)}
	for _, e := range doc.Entries {
		link, err := ParseLink(e.Text)
		if err != nil {
			sub.Errors = append(sub.Errors, &EntryError{Entry: e.Number, Line: e.Line, Err: err})
			continue
		}
		sub.Candidates = append(sub.Candidates, Candidate{Entry: e.Number, Line: e.Line, Link: link})
	}
	return sub, nil
}
