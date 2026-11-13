package trojan

import "github.com/juvenileslave/vpn/vpnctl/internal/upstream/sharelink"

// Encoding is the detected subscription encoding.
type Encoding = sharelink.Encoding

const (
	EncodingPlain  = sharelink.EncodingPlain
	EncodingBase64 = sharelink.EncodingBase64
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

// ParseSubscription parses an already obtained subscription body: one trojan
// link per line, either plain or as standard base64 of it. Blank lines and
// lines starting with '#' are skipped. The returned error is non-nil only when
// the body as a whole is unusable (ErrTooLarge, ErrEncoding, ErrEmpty,
// ErrTooManyEntries); per-entry failures are reported in Subscription.Errors.
func ParseSubscription(data []byte) (*Subscription, error) {
	doc, err := sharelink.Decode(data)
	if err != nil {
		return nil, err
	}
	if len(doc.Entries) > MaxEntries {
		return nil, ErrTooManyEntries
	}
	sub := &Subscription{Encoding: doc.Encoding}
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
