package shadowsocks

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSubscriptionPlainMixed(t *testing.T) {
	legacy := base64.RawStdEncoding.EncodeToString([]byte("chacha20-poly1305:" + testPassword + "@198.51.100.5:8388"))
	body := strings.Join([]string{
		"# synthetic shadowsocks subscription",
		"ss://" + sip002("aes-256-gcm", testPassword) + "@vpn.example.net:8388#first",
		"",
		"trojan://" + testPassword + "@192.0.2.1:443",
		"ss://aes-256-cfb:" + testPassword + "@192.0.2.1:8388",
		"# trailing comment",
		"ss://" + legacy + "#second",
	}, "\r\n")
	sub, err := ParseSubscription([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if sub.Encoding != EncodingPlain {
		t.Errorf("encoding = %s", sub.Encoding)
	}
	if len(sub.Candidates) != 2 ||
		sub.Candidates[0].Entry != 1 || sub.Candidates[0].Line != 2 || sub.Candidates[0].Link.Label != "first" ||
		sub.Candidates[1].Entry != 4 || sub.Candidates[1].Line != 7 || sub.Candidates[1].Link.Address != "198.51.100.5" {
		t.Fatalf("candidates = %+v", sub.Candidates)
	}
	want := []struct {
		entry, line int
		field       string
	}{{2, 4, "scheme"}, {3, 5, "method"}}
	if len(sub.Errors) != len(want) {
		t.Fatalf("errors = %v", sub.Errors)
	}
	for i, w := range want {
		e := sub.Errors[i]
		var fe *FieldError
		if e.Entry != w.entry || e.Line != w.line || !errors.As(e, &fe) || fe.Field != w.field {
			t.Errorf("errors[%d] = %v; want entry %d line %d field %s", i, e, w.entry, w.line, w.field)
		}
		assertNoSecrets(t, e.Error(), "")
	}
}

func TestParseSubscriptionBase64(t *testing.T) {
	plain := "ss://" + sip002("aes-256-gcm", testPassword) + "@192.0.2.10:8388#a\n" +
		"ss://" + sip002("aes-128-gcm", testPassword) + "@[2001:db8::10]:8388#b\n"
	std := base64.StdEncoding.EncodeToString([]byte(plain))
	var wrapped strings.Builder
	for i := 0; i < len(std); i += 76 {
		wrapped.WriteString(std[i:min(i+76, len(std))] + "\r\n")
	}
	for name, body := range map[string]string{
		"padded":  std,
		"raw":     base64.RawStdEncoding.EncodeToString([]byte(plain + "x")),
		"wrapped": wrapped.String(),
	} {
		t.Run(name, func(t *testing.T) {
			sub, err := ParseSubscription([]byte(body))
			if err != nil {
				t.Fatal(err)
			}
			if sub.Encoding != EncodingBase64 || len(sub.Candidates) != 2 || sub.Candidates[1].Link.Label != "b" {
				t.Fatalf("got %+v", sub)
			}
			if name == "raw" && (len(sub.Errors) != 1 || sub.Errors[0].Line != 3) {
				t.Errorf("trailing invalid entry not reported: %v", sub.Errors)
			}
		})
	}
}

func TestParseSubscriptionWholeBodyErrors(t *testing.T) {
	notUTF8 := base64.StdEncoding.EncodeToString([]byte{0xff, 0xfe, 0xfd})
	tooMany := strings.Repeat("ss://"+sip002("aes-256-gcm", testPassword)+"@192.0.2.1:8388\n", MaxEntries+1)
	for name, tc := range map[string]struct {
		body string
		want error
	}{
		"empty":            {"", ErrEmpty},
		"blank":            {" \r\n\t\n", ErrEmpty},
		"comments":         {"# a://b\n# c\n", ErrEmpty},
		"base64 comments":  {base64.StdEncoding.EncodeToString([]byte("# only\n")), ErrEmpty},
		"not base64":       {"not a subscription", ErrEncoding},
		"url-safe":         {base64.URLEncoding.EncodeToString([]byte{0xfb, 0xff, 0xfe}), ErrEncoding},
		"bad padding":      {"c3M6Ly8=eA", ErrEncoding},
		"decoded binary":   {notUTF8, ErrEncoding},
		"raw binary":       {"ss://\xff", ErrEncoding},
		"too large":        {strings.Repeat("a", MaxSubscriptionBytes+1), ErrTooLarge},
		"too many entries": {tooMany, ErrTooManyEntries},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseSubscription([]byte(tc.body)); !errors.Is(err, tc.want) {
				t.Errorf("err = %v; want %v", err, tc.want)
			}
		})
	}
}

func TestParseSubscriptionAllMalformed(t *testing.T) {
	body := "vmess://a@192.0.2.1:443\ntrojan://p@192.0.2.1:443\n"
	sub, err := ParseSubscription([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(sub.Candidates) != 0 || len(sub.Errors) != 2 {
		t.Fatalf("got %+v", sub)
	}
}

func TestParseSubscriptionEntryLimit(t *testing.T) {
	line := "ss://" + sip002("aes-256-gcm", testPassword) + "@192.0.2.1:8388\n"
	sub, err := ParseSubscription([]byte(strings.Repeat(line, MaxEntries)))
	if err != nil {
		t.Fatal(err)
	}
	if len(sub.Candidates) != MaxEntries || len(sub.Errors) != 0 {
		t.Fatalf("at limit: %d candidates, %d errors", len(sub.Candidates), len(sub.Errors))
	}
	if _, err := ParseSubscription([]byte(strings.Repeat(line, MaxEntries+1))); !errors.Is(err, ErrTooManyEntries) {
		t.Errorf("over limit err = %v", err)
	}
}

func TestParseSubscriptionOversizedEntry(t *testing.T) {
	oversized := "ss://" + sip002("aes-256-gcm", testPassword) + "@192.0.2.1:8388#" + strings.Repeat("a", MaxLinkBytes)
	body := oversized + "\nss://" + sip002("aes-256-gcm", testPassword) + "@192.0.2.1:8388\n"
	sub, err := ParseSubscription([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(sub.Candidates) != 1 || len(sub.Errors) != 1 {
		t.Fatalf("got %d candidates, %d errors", len(sub.Candidates), len(sub.Errors))
	}
	e := sub.Errors[0]
	var fe *FieldError
	if e.Entry != 1 || e.Line != 1 || !errors.As(e, &fe) || fe.Field != "" || !strings.Contains(fe.Reason, "exceeds") {
		t.Errorf("oversized entry error = %v", e)
	}
}

// TestXrayConfigSmoke loads representative outbounds with a pinned Xray binary
// ("xray run -test" parses and builds the config without connecting).
// Set VPNCTL_XRAY_BIN to enable it.
func TestXrayConfigSmoke(t *testing.T) {
	bin := os.Getenv("VPNCTL_XRAY_BIN")
	if bin == "" {
		t.Skip("VPNCTL_XRAY_BIN not set")
	}
	legacy := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:" + testPassword + "@198.51.100.5:8388"))
	links := []string{
		"ss://" + sip002("aes-256-gcm", testPassword) + "@192.0.2.10:8388",
		"ss://" + sip002("aes-128-gcm", testPassword) + "@vpn.example.com:8388",
		"ss://" + sip002("chacha20-poly1305", testPassword) + "@[2001:db8::10]:8388",
		"ss://2022-blake3-aes-128-gcm:" + testKey16 + "@192.0.2.10:8388",
		"ss://2022-blake3-aes-256-gcm:" + testKey32 + "@192.0.2.10:8388",
		"ss://2022-blake3-chacha20-poly1305:" + testKey32 + "@192.0.2.10:8388",
		"ss://" + legacy,
	}
	var outbounds []Outbound
	for i, link := range links {
		outbounds = append(outbounds, mustParse(t, link).Outbound("p"+string(rune('0'+i))))
	}
	cfg, err := json.Marshal(map[string]any{"log": map[string]string{"loglevel": "warning"}, "outbounds": outbounds})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "run", "-test", "-c", path)
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+t.TempDir())
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("xray run -test: %v\n%s", err, out)
	}
}
