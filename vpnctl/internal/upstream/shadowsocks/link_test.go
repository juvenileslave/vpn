package shadowsocks

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Synthetic credentials and RFC 5737/3849 documentation addresses only.
const testPassword = "synthetic-pass"

var (
	testKey16 = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 16))
	testKey32 = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32))
)

func sip002(method, password string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(method + ":" + password))
}

func mustParse(t *testing.T, link string) *Link {
	t.Helper()
	l, err := ParseLink(link)
	if err != nil {
		t.Fatalf("ParseLink: %v", err)
	}
	return l
}

// outboundJSON returns the outbound as generic JSON for semantic comparison.
func outboundJSON(t *testing.T, l *Link, tag string) map[string]any {
	t.Helper()
	b, err := json.Marshal(l.Outbound(tag))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func jsonValue(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("bad expected JSON: %v", err)
	}
	return m
}

func TestParseSIP002Base64Userinfo(t *testing.T) {
	for name, encode := range map[string]func([]byte) string{
		"url-safe raw":    base64.RawURLEncoding.EncodeToString,
		"url-safe padded": base64.URLEncoding.EncodeToString,
		"standard raw":    base64.RawStdEncoding.EncodeToString,
		"standard padded": base64.StdEncoding.EncodeToString,
	} {
		t.Run(name, func(t *testing.T) {
			link := "ss://" + encode([]byte("aes-256-gcm:"+testPassword)) + "@vpn.example.net:8388#%D0%9D%D0%BE%D0%B4%D0%B0%20100%2541"
			l := mustParse(t, link)
			if l.Label != "Нода 100%41" {
				t.Errorf("label decoded %q; want single decoding", l.Label)
			}
			if l.Method != "aes-256-gcm" || l.Password != testPassword || l.Address != "vpn.example.net" || l.Port != 8388 {
				t.Fatalf("link = %+v", l)
			}
			got := outboundJSON(t, l, "proxy-1")
			want := jsonValue(t, `{
			  "tag": "proxy-1", "protocol": "shadowsocks",
			  "settings": {"servers": [{"address": "vpn.example.net", "port": 8388,
			    "method": "aes-256-gcm", "password": "`+testPassword+`"}]}
			}`)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("outbound mismatch\n got: %v\nwant: %v", got, want)
			}
			if _, ok := got["streamSettings"]; ok {
				t.Error("shadowsocks must not emit streamSettings")
			}
		})
	}
}

func TestParseSIP002PercentEncoded(t *testing.T) {
	l := mustParse(t, "ss://aes-128-gcm:p%40ss%3Aword@192.0.2.10:8388")
	if l.Method != "aes-128-gcm" || l.Password != "p@ss:word" {
		t.Errorf("method %q password %q", l.Method, l.Password)
	}
}

func TestParseSIP002MethodAlias(t *testing.T) {
	l := mustParse(t, "ss://CHACHA20-IETF-POLY1305:"+testPassword+"@192.0.2.10:8388")
	if l.Method != "chacha20-poly1305" {
		t.Errorf("method = %q; want canonical name", l.Method)
	}
}

func TestParseLegacyBase64(t *testing.T) {
	payload := "chacha20-ietf-poly1305:" + testPassword + "@[2001:db8::1]:8388"
	for name, body := range map[string]string{
		"standard padded": base64.StdEncoding.EncodeToString([]byte(payload)),
		"standard raw":    base64.RawStdEncoding.EncodeToString([]byte(payload)),
		"url-safe raw":    base64.RawURLEncoding.EncodeToString([]byte(payload)),
	} {
		t.Run(name, func(t *testing.T) {
			l := mustParse(t, "ss://"+body+"#legacy")
			if l.Method != "chacha20-poly1305" || l.Password != testPassword ||
				l.Address != "2001:db8::1" || l.Port != 8388 || l.Label != "legacy" {
				t.Errorf("link = %+v", l)
			}
		})
	}
}

func TestParse2022(t *testing.T) {
	for method, key := range map[string]string{
		"2022-blake3-aes-128-gcm":       testKey16,
		"2022-blake3-aes-256-gcm":       testKey32,
		"2022-blake3-chacha20-poly1305": testKey32,
	} {
		t.Run(method, func(t *testing.T) {
			l := mustParse(t, "ss://"+method+":"+key+"@192.0.2.10:8388")
			if l.Method != method || l.Password != key {
				t.Errorf("link = %+v", l)
			}
			got := outboundJSON(t, l, "")
			server := got["settings"].(map[string]any)["servers"].([]any)[0].(map[string]any)
			if server["method"] != method || server["password"] != key {
				t.Errorf("server = %v", server)
			}
		})
	}
}

func TestParseLinkErrors(t *testing.T) {
	tests := []struct {
		name, link, field, reason string
	}{
		{"no scheme", sip002("aes-256-gcm", testPassword) + "@192.0.2.1:8388", "scheme", "not a URI"},
		{"other scheme", "vmess://" + sip002("aes-256-gcm", testPassword) + "@192.0.2.1:8388", "scheme", `"vmess"`},
		{"whitespace", "ss://" + sip002("aes-256-gcm", testPassword) + "@192.0.2.1:8388 ", "", "whitespace"},
		{"empty userinfo", "ss://@192.0.2.1:8388", "userinfo", "missing"},
		{"two at", "ss://a:b@c@192.0.2.1:8388", "userinfo", "ambiguous"},
		{"bad userinfo escape", "ss://aes-256-gcm:%zz@192.0.2.1:8388", "userinfo", "percent-encoding"},
		{"not base64", "ss://notbase64!@192.0.2.1:8388", "userinfo", "neither base64"},
		{"bad userinfo padding", "ss://AAAA=@192.0.2.1:8388", "userinfo", "neither base64"},
		{"base64 without colon", "ss://" + base64.RawURLEncoding.EncodeToString([]byte("nocolon")) + "@192.0.2.1:8388", "userinfo", "missing method or password"},
		{"empty method", "ss://:pass@192.0.2.1:8388", "method", "missing"},
		{"empty password", "ss://aes-256-gcm:@192.0.2.1:8388", "password", "missing"},
		{"base64 empty password", "ss://" + sip002("aes-256-gcm", "") + "@192.0.2.1:8388", "password", "missing"},
		{"legacy cipher", "ss://rc4-md5:" + testPassword + "@192.0.2.1:8388", "method", "unsupported"},
		{"stream cipher", "ss://aes-256-cfb:" + testPassword + "@192.0.2.1:8388", "method", "unsupported"},
		{"xchacha", "ss://xchacha20-poly1305:" + testPassword + "@192.0.2.1:8388", "method", "unsupported"},
		{"2022 short key", "ss://2022-blake3-aes-256-gcm:" + testKey16 + "@192.0.2.1:8388", "password", "32 bytes"},
		{"2022 long key", "ss://2022-blake3-aes-128-gcm:" + testKey32 + "@192.0.2.1:8388", "password", "16 bytes"},
		{"2022 unpadded key", "ss://2022-blake3-aes-256-gcm:" + strings.TrimRight(testKey32, "=") + "@192.0.2.1:8388", "password", "padded"},
		{"2022 multi-key", "ss://2022-blake3-aes-256-gcm:" + testKey32 + "%3A" + testKey32 + "@192.0.2.1:8388", "password", "multi-key"},
		{"control password", "ss://aes-256-gcm:a%0Ab@192.0.2.1:8388", "password", "control"},
		{"missing port", "ss://" + sip002("aes-256-gcm", testPassword) + "@192.0.2.1", "port", "missing"},
		{"port zero", "ss://" + sip002("aes-256-gcm", testPassword) + "@192.0.2.1:0", "port", "range"},
		{"bare ipv6", "ss://" + sip002("aes-256-gcm", testPassword) + "@2001:db8::1:8388", "host", "brackets"},
		{"bad host", "ss://" + sip002("aes-256-gcm", testPassword) + "@bad_host.example:8388", "host", "DNS name"},
		{"uri path", "ss://" + sip002("aes-256-gcm", testPassword) + "@192.0.2.1:8388/sub", "uri", "path"},
		{"bad label escape", "ss://" + sip002("aes-256-gcm", testPassword) + "@192.0.2.1:8388#%E0%A4", "label", "UTF-8"},
		{"control label", "ss://" + sip002("aes-256-gcm", testPassword) + "@192.0.2.1:8388#a%0Ab", "label", "control"},
		{"legacy not base64", "ss://%%%", "uri", "not a SIP002"},
		{"legacy without at", "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:"+testPassword)), "uri", "legacy payload"},
		{"legacy two at", "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:p@ss@192.0.2.1:8388")), "uri", "legacy payload"},
		{"legacy without colon", "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm@192.0.2.1:8388")), "userinfo", "missing method or password"},
		{"plugin", "ss://" + sip002("aes-256-gcm", testPassword) + "@192.0.2.1:8388?plugin=obfs-local%3Bobfs%3Dhttp", "plugin", "not supported"},
		{"empty plugin", "ss://" + sip002("aes-256-gcm", testPassword) + "@192.0.2.1:8388?plugin=", "plugin", "not supported"},
		{"unknown param", "ss://" + sip002("aes-256-gcm", testPassword) + "@192.0.2.1:8388?uot=1", "uot", "unknown parameter"},
		{"duplicate param", "ss://" + sip002("aes-256-gcm", testPassword) + "@192.0.2.1:8388?plugin=a&plugin=b", "plugin", "duplicate"},
		{"empty param", "ss://" + sip002("aes-256-gcm", testPassword) + "@192.0.2.1:8388?&plugin=a", "query", "empty"},
		{"no value", "ss://" + sip002("aes-256-gcm", testPassword) + "@192.0.2.1:8388?plugin", "plugin", "missing value"},
		{"too long", "ss://" + sip002("aes-256-gcm", testPassword) + "@192.0.2.1:8388#" + strings.Repeat("a", MaxLinkBytes), "", "exceeds"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseLink(tc.link)
			var fe *FieldError
			if !errors.As(err, &fe) {
				t.Fatalf("err = %v; want *FieldError", err)
			}
			if fe.Field != tc.field || !strings.Contains(fe.Reason, tc.reason) {
				t.Errorf("err = %q; want field %q with reason containing %q", err, tc.field, tc.reason)
			}
			assertNoSecrets(t, err.Error(), tc.link)
		})
	}
}

func assertNoSecrets(t *testing.T, msg, link string) {
	t.Helper()
	for _, secret := range []string{testPassword, testKey16, testKey32, link} {
		if secret != "" && strings.Contains(msg, secret) {
			t.Errorf("error %q leaks credential-bearing input", msg)
		}
	}
}

func TestLinkFormattingHidesCredentials(t *testing.T) {
	l := mustParse(t, "ss://"+sip002("aes-256-gcm", testPassword)+"@vpn.example.net:8388#label")
	for _, s := range []string{fmt.Sprint(l), fmt.Sprintf("%+v", l), fmt.Sprintf("%#v", l)} {
		assertNoSecrets(t, s, "")
		if s != "shadowsocks aes-256-gcm vpn.example.net:8388" {
			t.Errorf("formatted link = %q", s)
		}
	}
}
