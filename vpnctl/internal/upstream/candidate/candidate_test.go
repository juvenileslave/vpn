package candidate

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/juvenileslave/vpn/vpnctl/internal/upstream/sharelink"
)

const (
	testVLESSLink  = "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp&security=tls#label-a"
	testTrojanLink = "trojan://secret-password@example.com:443?type=tcp#label-b"
	testSSLink     = "ss://YWVzLTI1Ni1nY206c2VjcmV0@example.com:8388#label-c"

	testWireguardConfig = "[Interface]\n" +
		"PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n" +
		"Address = 10.0.0.2/24\n\n" +
		"[Peer]\n" +
		"PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n" +
		"Endpoint = 192.0.2.1:51820\n" +
		"AllowedIPs = 0.0.0.0/0\n"
)

func isLowerHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func assertOutboundMeta(t *testing.T, raw json.RawMessage, wantTag, wantProtocol string) {
	t.Helper()
	var meta struct {
		Tag      string `json:"tag"`
		Protocol string `json:"protocol"`
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatalf("unmarshal outbound: %v", err)
	}
	if meta.Tag != wantTag {
		t.Errorf("outbound tag = %q, want %q", meta.Tag, wantTag)
	}
	if meta.Protocol != wantProtocol {
		t.Errorf("outbound protocol = %q, want %q", meta.Protocol, wantProtocol)
	}
}

func assertIDMatchesOutbound(t *testing.T, c Candidate) {
	t.Helper()
	if !isLowerHex64(c.ID) {
		t.Fatalf("ID %q is not 64 lowercase hex chars", c.ID)
	}
	sum := sha256.Sum256(c.Outbound)
	want := hex.EncodeToString(sum[:])
	if c.ID != want {
		t.Errorf("ID = %q, want sha256(outbound) %q", c.ID, want)
	}
}

func TestParseSubscriptionMixedPlainAndBase64(t *testing.T) {
	const tag = "upstream-slot-1"
	plain := strings.Join([]string{testVLESSLink, testTrojanLink, testSSLink}, "\n") + "\n"

	cands, rejects, err := ParseSubscription([]byte(plain), tag)
	if err != nil {
		t.Fatalf("ParseSubscription(plain) error = %v", err)
	}
	if len(rejects) != 0 {
		t.Fatalf("len(rejects) = %d, want 0: %+v", len(rejects), rejects)
	}
	if len(cands) != 3 {
		t.Fatalf("len(cands) = %d, want 3", len(cands))
	}

	want := []struct {
		scheme   Scheme
		label    string
		protocol string
	}{
		{scheme: SchemeVLESS, label: "label-a", protocol: "vless"},
		{scheme: SchemeTrojan, label: "label-b", protocol: "trojan"},
		{scheme: SchemeShadowsocks, label: "label-c", protocol: "shadowsocks"},
	}

	seenIDs := make(map[string]struct{}, len(cands))
	for i, w := range want {
		c := cands[i]
		if c.Scheme != w.scheme {
			t.Errorf("cands[%d].Scheme = %q, want %q", i, c.Scheme, w.scheme)
		}
		if c.Label != w.label {
			t.Errorf("cands[%d].Label = %q, want %q", i, c.Label, w.label)
		}
		assertIDMatchesOutbound(t, c)
		if _, dup := seenIDs[c.ID]; dup {
			t.Errorf("duplicate candidate ID %q", c.ID)
		}
		seenIDs[c.ID] = struct{}{}
		assertOutboundMeta(t, c.Outbound, tag, w.protocol)
	}

	// Tag must influence the deterministic candidate ID.
	otherCands, _, err := ParseSubscription([]byte(plain), "upstream-slot-2")
	if err != nil {
		t.Fatalf("ParseSubscription(other tag) error = %v", err)
	}
	for i := range cands {
		if otherCands[i].ID == cands[i].ID {
			t.Errorf("cands[%d].ID did not change when tag changed", i)
		}
	}

	// Base64 standard (with and without padding) must yield identical IDs.
	encodings := []struct {
		name string
		body []byte
	}{
		{name: "base64-padded", body: []byte(base64.StdEncoding.EncodeToString([]byte(plain)))},
		{name: "base64-unpadded", body: []byte(base64.RawStdEncoding.EncodeToString([]byte(plain)))},
	}
	for _, enc := range encodings {
		t.Run(enc.name, func(t *testing.T) {
			got, rejs, err := ParseSubscription(enc.body, tag)
			if err != nil {
				t.Fatalf("ParseSubscription(%s) error = %v", enc.name, err)
			}
			if len(rejs) != 0 {
				t.Fatalf("len(rejects) = %d, want 0", len(rejs))
			}
			if len(got) != len(cands) {
				t.Fatalf("len(got) = %d, want %d", len(got), len(cands))
			}
			for i := range cands {
				if got[i].ID != cands[i].ID {
					t.Errorf("cand[%d].ID = %q, want %q", i, got[i].ID, cands[i].ID)
				}
			}
		})
	}
}

func TestParseSubscriptionRejectsAndSecretSafety(t *testing.T) {
	const (
		vmessLine     = "vmess://eyJ2IjoiMiIsInBzIjoidm1lc3Mtc2VjcmV0IiwiaWQiOiJ2bWVzcy11dWlkIn0="
		nonLinkLine   = "not-a-link-secret-token"
		badVLESSLine  = "vless://bad-uuid-secret-value@example.com:443?type=tcp"
		longProtoLine = "abcdefghijklmnopqrstuv://super-secret-value"
	)
	body := strings.Join([]string{
		testVLESSLink,
		vmessLine,
		nonLinkLine,
		badVLESSLine,
		longProtoLine,
		testTrojanLink,
	}, "\n") + "\n"

	cands, rejects, err := ParseSubscription([]byte(body), "upstream-slot-1")
	if err != nil {
		t.Fatalf("ParseSubscription error = %v", err)
	}
	if len(cands) != 2 {
		t.Fatalf("len(cands) = %d, want 2", len(cands))
	}
	if cands[0].Scheme != SchemeVLESS || cands[1].Scheme != SchemeTrojan {
		t.Fatalf("unexpected candidate schemes: %q, %q", cands[0].Scheme, cands[1].Scheme)
	}
	if len(rejects) != 4 {
		t.Fatalf("len(rejects) = %d, want 4: %+v", len(rejects), rejects)
	}

	wantRejects := []struct {
		entry      int
		line       int
		scheme     string
		wantReason string
	}{
		{entry: 2, line: 2, scheme: "vmess", wantReason: "unsupported scheme"},
		{entry: 3, line: 3, scheme: "", wantReason: "not a share link"},
		{entry: 4, line: 4, scheme: "vless", wantReason: ""},
		{entry: 5, line: 5, scheme: "abcdefghijklmnop", wantReason: "unsupported scheme"},
	}

	secrets := []string{
		vmessLine,
		nonLinkLine,
		badVLESSLine,
		longProtoLine,
		"eyJ2IjoiMi",
		"bad-uuid-secret-value",
		"super-secret-value",
		"11111111-1111-1111-1111-111111111111",
		"secret-password",
	}

	for i, w := range wantRejects {
		r := rejects[i]
		if r.Entry != w.entry || r.Line != w.line {
			t.Errorf("rejects[%d] entry/line = %d/%d, want %d/%d", i, r.Entry, r.Line, w.entry, w.line)
		}
		if r.Scheme != w.scheme {
			t.Errorf("rejects[%d].Scheme = %q, want %q", i, r.Scheme, w.scheme)
		}
		if w.wantReason != "" {
			if r.Reason != w.wantReason {
				t.Errorf("rejects[%d].Reason = %q, want %q", i, r.Reason, w.wantReason)
			}
		} else if r.Reason == "" {
			t.Errorf("rejects[%d].Reason is empty, want parser error", i)
		}
		for _, sec := range secrets {
			if strings.Contains(r.Reason, sec) || strings.Contains(r.Scheme, sec) {
				t.Errorf("rejects[%d] leaked secret %q: %+v", i, sec, r)
			}
		}
	}
}

func TestParseSubscriptionWholeBodyErrors(t *testing.T) {
	tooMany := []byte(strings.Repeat(testVLESSLink+"\n", 1025))
	tooLarge := bytes.Repeat([]byte("a"), sharelink.MaxSubscriptionBytes+1)

	tests := []struct {
		name     string
		data     []byte
		wantErr  error
		shareErr error
	}{
		{name: "empty", data: nil, wantErr: ErrEmpty, shareErr: sharelink.ErrEmpty},
		{name: "whitespace", data: []byte("  \n\t\n"), wantErr: ErrEmpty, shareErr: sharelink.ErrEmpty},
		{name: "invalid-utf8", data: []byte{0xff, 0xfe, 0xfd}, wantErr: ErrEncoding, shareErr: sharelink.ErrEncoding},
		{name: "too-large", data: tooLarge, wantErr: ErrTooLarge, shareErr: sharelink.ErrTooLarge},
		{name: "too-many-entries", data: tooMany, wantErr: ErrTooManyEntries, shareErr: sharelink.ErrTooManyEntries},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cands, rejs, err := ParseSubscription(tc.data, "upstream-slot-1")
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
			if !errors.Is(err, tc.shareErr) {
				t.Errorf("error = %v, want wrapped %v", err, tc.shareErr)
			}
			if len(cands) != 0 || len(rejs) != 0 {
				t.Errorf("got %d candidates and %d rejects on whole-body error, want 0/0", len(cands), len(rejs))
			}
		})
	}
}

func TestInvalidTagRejected(t *testing.T) {
	invalidTags := []string{
		"",
		"upstream slot",
		"upstream/slot",
		"upstream:slot",
		strings.Repeat("a", 64),
	}
	for _, tag := range invalidTags {
		cands, rejs, err := ParseSubscription([]byte(testVLESSLink), tag)
		if err == nil {
			t.Errorf("ParseSubscription(tag=%q) error = nil, want error", tag)
		}
		if len(cands) != 0 || len(rejs) != 0 {
			t.Errorf("ParseSubscription(tag=%q) returned %d cands, %d rejects; want 0/0", tag, len(cands), len(rejs))
		}
		if _, err := ParseWireguard([]byte(testWireguardConfig), tag); err == nil {
			t.Errorf("ParseWireguard(tag=%q) error = nil, want error", tag)
		}
	}

	maxValidTag := strings.Repeat("a", 60) + "._-"
	if _, _, err := ParseSubscription([]byte(testVLESSLink), maxValidTag); err != nil {
		t.Errorf("ParseSubscription(maxValidTag) error = %v, want nil", err)
	}
}

func TestParseWireguard(t *testing.T) {
	const tag = "upstream-wg-1"
	cand, err := ParseWireguard([]byte(testWireguardConfig), tag)
	if err != nil {
		t.Fatalf("ParseWireguard error = %v", err)
	}
	if cand.Scheme != SchemeWireguard {
		t.Errorf("Scheme = %q, want %q", cand.Scheme, SchemeWireguard)
	}
	if cand.Label != "" {
		t.Errorf("Label = %q, want empty", cand.Label)
	}
	assertIDMatchesOutbound(t, cand)
	assertOutboundMeta(t, cand.Outbound, tag, "wireguard")

	again, err := ParseWireguard([]byte(testWireguardConfig), tag)
	if err != nil {
		t.Fatalf("ParseWireguard(second) error = %v", err)
	}
	if again.ID != cand.ID {
		t.Errorf("ID not deterministic: %q != %q", again.ID, cand.ID)
	}

	diffTag, err := ParseWireguard([]byte(testWireguardConfig), "upstream-wg-2")
	if err != nil {
		t.Fatalf("ParseWireguard(diff tag) error = %v", err)
	}
	if diffTag.ID == cand.ID {
		t.Errorf("ID did not change when tag changed")
	}

	invalid := "[Interface]\nPrivateKey = not-a-valid-key\n"
	if _, err := ParseWireguard([]byte(invalid), tag); err == nil {
		t.Errorf("ParseWireguard(invalid) error = nil, want error")
	}
}

func TestCandidateRedaction(t *testing.T) {
	plain := strings.Join([]string{testVLESSLink, testTrojanLink, testSSLink}, "\n") + "\n"
	cands, _, err := ParseSubscription([]byte(plain), "upstream-slot-1")
	if err != nil {
		t.Fatalf("ParseSubscription error = %v", err)
	}
	wgCand, err := ParseWireguard([]byte(testWireguardConfig), "upstream-wg-1")
	if err != nil {
		t.Fatalf("ParseWireguard error = %v", err)
	}
	all := append(cands, wgCand, Candidate{})

	secrets := []string{
		"11111111-1111-1111-1111-111111111111",
		"secret-password",
		"secret",
		"YWVzLTI1Ni1nY206c2VjcmV0",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	}
	for i, c := range all {
		formatted := []string{
			fmt.Sprintf("%v", c),
			fmt.Sprintf("%+v", c),
			fmt.Sprintf("%#v", c),
		}
		for _, out := range formatted {
			for _, sec := range secrets {
				if strings.Contains(out, sec) {
					t.Errorf("cand[%d] formatted %q leaked secret %q", i, out, sec)
				}
			}
		}
	}
}
