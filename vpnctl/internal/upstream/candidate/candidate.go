package candidate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/juvenileslave/vpn/vpnctl/internal/upstream/shadowsocks"
	"github.com/juvenileslave/vpn/vpnctl/internal/upstream/sharelink"
	"github.com/juvenileslave/vpn/vpnctl/internal/upstream/trojan"
	"github.com/juvenileslave/vpn/vpnctl/internal/upstream/vless"
	"github.com/juvenileslave/vpn/vpnctl/internal/upstream/wireguard"
)

// Scheme identifies the upstream proxy protocol of a normalized candidate.
type Scheme string

const (
	SchemeVLESS       Scheme = "vless"
	SchemeTrojan      Scheme = "trojan"
	SchemeShadowsocks Scheme = "shadowsocks"
	SchemeWireguard   Scheme = "wireguard"
)

const (
	maxEntries   = 1024
	maxSchemeLen = 16
	maxTagLen    = 63
	idPreviewLen = 12
)

// Whole-body subscription decoding sentinel errors.
var (
	ErrEmpty          = errors.New("candidate: subscription body is empty")
	ErrEncoding       = errors.New("candidate: invalid subscription encoding")
	ErrTooLarge       = errors.New("candidate: subscription body too large")
	ErrTooManyEntries = errors.New("candidate: too many subscription entries")
)

// Candidate is one parsed upstream outbound. Outbound contains credentials:
// never log or persist it in plaintext.
type Candidate struct {
	ID       string
	Scheme   Scheme
	Label    string
	Outbound json.RawMessage
}

// String returns a redacted representation of c without its Outbound payload.
func (c Candidate) String() string {
	return c.redacted()
}

// GoString returns a redacted Go-syntax representation of c without its Outbound payload.
func (c Candidate) GoString() string {
	return c.redacted()
}

func (c Candidate) redacted() string {
	id := c.ID
	if len(id) > idPreviewLen {
		id = id[:idPreviewLen] + "..."
	}
	return fmt.Sprintf("candidate.Candidate{id=%s scheme=%s label=%q outbound=<redacted>}", id, c.Scheme, c.Label)
}

// Reject is one unusable entry. It never contains the raw line or credentials.
type Reject struct {
	Entry  int
	Line   int
	Scheme string
	Reason string
}

// ParseSubscription dispatches each decoded entry by scheme and uses the
// accepted per-scheme parser. tag is written into every outbound (for example
// "upstream-slot-1"). Per-entry failures become Rejects; the error is non-nil
// only when the whole body is unusable.
func ParseSubscription(data []byte, tag string) ([]Candidate, []Reject, error) {
	if err := validateTag(tag); err != nil {
		return nil, nil, err
	}
	doc, err := sharelink.DecodeLimit(data, maxEntries)
	if err != nil {
		return nil, nil, mapDecodeError(err)
	}
	if doc == nil || len(doc.Entries) == 0 {
		return nil, nil, ErrEmpty
	}

	var (
		candidates []Candidate
		rejects    []Reject
	)
	for _, entry := range doc.Entries {
		cand, rej := parseEntry(entry, tag)
		if rej != nil {
			rejects = append(rejects, *rej)
			continue
		}
		candidates = append(candidates, cand)
	}
	return candidates, rejects, nil
}

// ParseWireguard parses exactly one WireGuard config into one candidate.
func ParseWireguard(data []byte, tag string) (Candidate, error) {
	if err := validateTag(tag); err != nil {
		return Candidate{}, err
	}
	cfg, err := wireguard.Parse(data)
	if err != nil {
		return Candidate{}, fmt.Errorf("candidate: parse wireguard: %w", err)
	}
	if cfg == nil {
		return Candidate{}, errors.New("candidate: wireguard config is nil")
	}
	return buildCandidate(SchemeWireguard, "", cfg.XrayOutbound(tag))
}

func parseEntry(entry sharelink.Entry, tag string) (Candidate, *Reject) {
	idx := strings.Index(entry.Text, "://")
	if idx <= 0 {
		return Candidate{}, rejectEntry(entry, "", "not a share link")
	}

	scheme := sanitizeScheme(entry.Text[:idx])
	switch scheme {
	case "vless":
		link, err := vless.ParseLink(entry.Text)
		if err != nil {
			return Candidate{}, rejectEntry(entry, scheme, err.Error())
		}
		if link == nil {
			return Candidate{}, rejectEntry(entry, scheme, "empty vless link")
		}
		cand, err := buildCandidate(SchemeVLESS, link.Label, link.Outbound(tag))
		if err != nil {
			return Candidate{}, rejectEntry(entry, scheme, "marshal outbound failed")
		}
		return cand, nil

	case "trojan":
		link, err := trojan.ParseLink(entry.Text)
		if err != nil {
			return Candidate{}, rejectEntry(entry, scheme, err.Error())
		}
		if link == nil {
			return Candidate{}, rejectEntry(entry, scheme, "empty trojan link")
		}
		cand, err := buildCandidate(SchemeTrojan, link.Label, link.Outbound(tag))
		if err != nil {
			return Candidate{}, rejectEntry(entry, scheme, "marshal outbound failed")
		}
		return cand, nil

	case "ss":
		link, err := shadowsocks.ParseLink(entry.Text)
		if err != nil {
			return Candidate{}, rejectEntry(entry, scheme, err.Error())
		}
		if link == nil {
			return Candidate{}, rejectEntry(entry, scheme, "empty shadowsocks link")
		}
		cand, err := buildCandidate(SchemeShadowsocks, link.Label, link.Outbound(tag))
		if err != nil {
			return Candidate{}, rejectEntry(entry, scheme, "marshal outbound failed")
		}
		return cand, nil

	default:
		return Candidate{}, rejectEntry(entry, scheme, "unsupported scheme")
	}
}

func rejectEntry(entry sharelink.Entry, scheme, reason string) *Reject {
	return &Reject{
		Entry:  entry.Number,
		Line:   entry.Line,
		Scheme: scheme,
		Reason: reason,
	}
}

func buildCandidate(scheme Scheme, label string, outbound any) (Candidate, error) {
	raw, err := json.Marshal(outbound)
	if err != nil {
		return Candidate{}, fmt.Errorf("candidate: marshal %s outbound: %w", scheme, err)
	}
	sum := sha256.Sum256(raw)
	return Candidate{
		ID:       hex.EncodeToString(sum[:]),
		Scheme:   scheme,
		Label:    label,
		Outbound: json.RawMessage(raw),
	}, nil
}

func validateTag(tag string) error {
	if len(tag) == 0 || len(tag) > maxTagLen {
		return errors.New("candidate: invalid tag")
	}
	for i := 0; i < len(tag); i++ {
		b := tag[i]
		isAlphaNum := (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
		if !isAlphaNum && b != '.' && b != '_' && b != '-' {
			return errors.New("candidate: invalid tag")
		}
	}
	return nil
}

func sanitizeScheme(prefix string) string {
	if len(prefix) == 0 {
		return ""
	}
	limit := len(prefix)
	if limit > maxSchemeLen {
		limit = maxSchemeLen
	}
	var b strings.Builder
	b.Grow(limit)
	for i := 0; i < len(prefix); i++ {
		c := prefix[i]
		switch {
		case c >= 'A' && c <= 'Z':
			if b.Len() < maxSchemeLen {
				b.WriteByte(c + ('a' - 'A'))
			}
		case (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'):
			if b.Len() < maxSchemeLen {
				b.WriteByte(c)
			}
		default:
			return ""
		}
	}
	return b.String()
}

func mapDecodeError(err error) error {
	switch {
	case errors.Is(err, sharelink.ErrEmpty):
		return fmt.Errorf("%w: %w", ErrEmpty, err)
	case errors.Is(err, sharelink.ErrEncoding):
		return fmt.Errorf("%w: %w", ErrEncoding, err)
	case errors.Is(err, sharelink.ErrTooLarge):
		return fmt.Errorf("%w: %w", ErrTooLarge, err)
	case errors.Is(err, sharelink.ErrTooManyEntries):
		return fmt.Errorf("%w: %w", ErrTooManyEntries, err)
	default:
		return fmt.Errorf("candidate: decode subscription: %w", err)
	}
}
