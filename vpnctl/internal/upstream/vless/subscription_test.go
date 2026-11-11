package vless

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSubscriptionPlainMixed(t *testing.T) {
	body := strings.Join([]string{
		"\ufeff# provider header",
		"",
		realityLink("", "#first") + "\r",
		"vmess://" + testID + "@192.0.2.1:443",
		"   ",
		"vless://" + testID + "@192.0.2.1:443?type=ws&security=tls#" + testPBK,
		tlsLink("#second"),
		"justtext",
	}, "\n")
	sub, err := ParseSubscription([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if sub.Encoding != EncodingPlain {
		t.Errorf("encoding = %s", sub.Encoding)
	}
	if len(sub.Candidates) != 2 ||
		sub.Candidates[0].Entry != 1 || sub.Candidates[0].Line != 3 || sub.Candidates[0].Link.Label != "first" ||
		sub.Candidates[1].Entry != 4 || sub.Candidates[1].Line != 7 || sub.Candidates[1].Link.Transport != TransportRAW {
		t.Fatalf("candidates = %+v", sub.Candidates)
	}
	want := []struct {
		entry, line int
		field       string
	}{{2, 4, "scheme"}, {3, 6, "type"}, {5, 8, "scheme"}}
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
	plain := realityLink("", "#a") + "\n" + tlsLink("#b") + "\n"
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
	for name, tc := range map[string]struct {
		body string
		want error
	}{
		"empty":           {"", ErrEmpty},
		"blank":           {" \r\n\t\n", ErrEmpty},
		"comments":        {"# a://b\n# c\n", ErrEmpty},
		"base64 comments": {base64.StdEncoding.EncodeToString([]byte("# only\n")), ErrEmpty},
		"not base64":      {"not a subscription", ErrEncoding},
		"url-safe":        {strings.ReplaceAll(base64.StdEncoding.EncodeToString([]byte("vless://??>>")), "/", "_"), ErrEncoding},
		"bad padding":     {"dmxlc3M6Ly8=x", ErrEncoding},
		"decoded binary":  {notUTF8, ErrEncoding},
		"raw binary":      {"vless://\xff", ErrEncoding},
		"too large":       {strings.Repeat("a", MaxSubscriptionBytes+1), ErrTooLarge},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseSubscription([]byte(tc.body)); !errors.Is(err, tc.want) {
				t.Errorf("err = %v; want %v", err, tc.want)
			}
		})
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
	extra := `{"headers":{"User-Agent":"Mozilla/5.0"},"xPaddingBytes":"100-1000","uplinkHTTPMethod":"GET",` +
		`"uplinkDataPlacement":"header","sessionIDPlacement":"query","seqPlacement":"header","seqKey":"X-Seq",` +
		`"xPaddingObfsMode":true,"xPaddingPlacement":"header","xPaddingMethod":"tokenish","uplinkChunkSize":"100-200",` +
		`"scMinPostsIntervalMs":"10-50","xmux":{"maxConnections":"2-4","cMaxReuseTimes":8,"hKeepAlivePeriod":30}}`
	links := []string{
		realityLink("", ""),
		realityLink("&mode=packet-up&path=%2Fx&host=cdn.example.org&spx=%2Fs&pqv="+testPQV+"&extra="+url.PathEscape(extra), ""),
		strings.Replace(realityLink("&mode=stream-one", ""), "vpn.example.net:443", "[2001:db8::10]:8443", 1),
		tlsLink("&flow=xtls-rprx-vision&alpn=h2%2Chttp%2F1.1&pcs=" + testPCS + "&vcn=cert.example.com"),
		tlsLink("&fp=randomized"),
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
