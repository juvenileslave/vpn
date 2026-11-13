package trojan

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Synthetic password and RFC 5737/3849 documentation addresses only.
const testPassword = "synthetic-pass"

const testPasswordEnc = "synthetic%2Dpass"

func trojanLink(query, label string) string {
	return "trojan://" + testPasswordEnc + "@vpn.example.net:443" + query + label
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

func TestParseLinkTLS(t *testing.T) {
	link := "trojan://" + testPasswordEnc + "@vpn.example.net:443?type=tcp&security=tls" +
		"&sni=www.example.com&alpn=h2%2Chttp%2F1.1&allowInsecure=0&headerType=none" +
		"#%D0%9D%D0%BE%D0%B4%D0%B0%20100%2541"
	l := mustParse(t, link)

	if l.Label != "Нода 100%41" {
		t.Errorf("label decoded %q; want single decoding", l.Label)
	}
	if l.Password != testPassword || l.Address != "vpn.example.net" || l.Port != 443 ||
		l.Transport != TransportRAW || l.TLS.ServerName != "www.example.com" ||
		!reflect.DeepEqual(l.TLS.ALPN, []string{"h2", "http/1.1"}) {
		t.Fatalf("link = %+v", l)
	}
	got := outboundJSON(t, l, "proxy-1")
	want := jsonValue(t, `{
	  "tag": "proxy-1",
	  "protocol": "trojan",
	  "settings": {"servers": [{"address": "vpn.example.net", "port": 443,
	    "password": "`+testPassword+`"}]},
	  "streamSettings": {"network": "raw", "security": "tls",
	    "tlsSettings": {"serverName": "www.example.com", "alpn": ["h2", "http/1.1"]}}
	}`)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("outbound mismatch\n got: %v\nwant: %v", got, want)
	}
}

func TestParseLinkDefaults(t *testing.T) {
	l := mustParse(t, "trojan://"+testPassword+"@Example.COM:443")
	if l.Address != "example.com" || l.TLS.ServerName != "" || l.TLS.ALPN != nil {
		t.Errorf("link = %+v", l)
	}
	got := outboundJSON(t, l, "")
	ss := got["streamSettings"].(map[string]any)
	if !reflect.DeepEqual(ss, map[string]any{"network": "raw", "security": "tls"}) {
		t.Errorf("streamSettings = %v; want no empty tlsSettings", ss)
	}
	if _, ok := got["tag"]; ok {
		t.Error("empty tag must be omitted; the label is never used as a tag")
	}
}

func TestParseLinkPeerAlias(t *testing.T) {
	l := mustParse(t, trojanLink("?peer=Peer.Example.COM", ""))
	if l.TLS.ServerName != "peer.example.com" {
		t.Errorf("peer alias = %q", l.TLS.ServerName)
	}
}

func TestParseLinkAddresses(t *testing.T) {
	for _, tc := range []struct{ hostport, want string }{
		{"[2001:db8::10]:443", "2001:db8::10"},
		{"[2001:DB8:0:0::10]:443", "2001:db8::10"},
		{"198.51.100.7:443", "198.51.100.7"},
		{"xn--e1afmkfd.example:443", "xn--e1afmkfd.example"},
	} {
		l := mustParse(t, "trojan://"+testPassword+"@"+tc.hostport)
		if l.Address != tc.want || l.Port != 443 {
			t.Errorf("%s: address %q port %d", tc.hostport, l.Address, l.Port)
		}
		if tc.want == "2001:db8::10" && l.String() != "trojan raw+tls [2001:db8::10]:443" {
			t.Errorf("String() = %q", l.String())
		}
	}
}

func TestParseLinkLimits(t *testing.T) {
	l := mustParse(t, "trojan://"+testPassword+"@192.0.2.1:65535/")
	if l.Port != 65535 {
		t.Errorf("port = %d; want 65535", l.Port)
	}
	label := strings.Repeat("a", 256)
	l = mustParse(t, "trojan://"+testPassword+"@192.0.2.1:443#"+label)
	if l.Label != label {
		t.Errorf("256-rune label not preserved")
	}
	l = mustParse(t, "trojan://"+testPassword+"@192.0.2.1:443#%20"+label+"%20")
	if l.Label != label {
		t.Errorf("label must be trimmed before the length check")
	}
	_, err := ParseLink("trojan://" + testPassword + "@192.0.2.1:443#" + label + "a")
	var fe *FieldError
	if !errors.As(err, &fe) || fe.Field != "label" || !strings.Contains(fe.Reason, "longer") {
		t.Errorf("over-limit label err = %v", err)
	}
}

func TestParseLinkErrors(t *testing.T) {
	tests := []struct {
		name, link, field, reason string
	}{
		{"no scheme", testPassword + "@192.0.2.1:443", "scheme", "not a URI"},
		{"other scheme", "vmess://" + testPassword + "@192.0.2.1:443", "scheme", `"vmess"`},
		{"whitespace", "trojan://" + testPassword + "@192.0.2.1:443 ", "", "whitespace"},
		{"empty password", "trojan://@192.0.2.1:443", "password", "missing"},
		{"two at", "trojan://p@x@192.0.2.1:443", "password", "ambiguous"},
		{"bad password escape", "trojan://%zz@192.0.2.1:443", "password", "percent-encoding"},
		{"control password", "trojan://a%0Ab@192.0.2.1:443", "password", "control"},
		{"missing port", "trojan://" + testPassword + "@192.0.2.1", "port", "missing"},
		{"empty port", "trojan://" + testPassword + "@192.0.2.1:", "port", "missing"},
		{"port zero", "trojan://" + testPassword + "@192.0.2.1:0", "port", "range"},
		{"port high", "trojan://" + testPassword + "@192.0.2.1:65536", "port", "range"},
		{"port leading zero", "trojan://" + testPassword + "@192.0.2.1:0443", "port", "decimal"},
		{"port sign", "trojan://" + testPassword + "@192.0.2.1:+443", "port", "decimal"},
		{"bare ipv6", "trojan://" + testPassword + "@2001:db8::1:443", "host", "brackets"},
		{"bracketed ipv4", "trojan://" + testPassword + "@[192.0.2.1]:443", "host", "IPv6"},
		{"ipv6 zone", "trojan://" + testPassword + "@[fe80::1%25eth0]:443", "host", "IPv6"},
		{"unterminated ipv6", "trojan://" + testPassword + "@[2001:db8::1:443", "host", "unterminated"},
		{"short ipv4", "trojan://" + testPassword + "@192.0.2:443", "host", "DNS name"},
		{"underscore host", "trojan://" + testPassword + "@bad_host.example:443", "host", "DNS name"},
		{"encoded host", "trojan://" + testPassword + "@ex%61mple.com:443", "host", "DNS name"},
		{"uri path", "trojan://" + testPassword + "@192.0.2.1:443/sub", "uri", "path"},
		{"bad label escape", trojanLink("", "#%E0%A4"), "label", "UTF-8"},
		{"control label", trojanLink("", "#a%0Ab"), "label", "control"},
		{"duplicate param", "trojan://" + testPassword + "@vpn.example.net:443?type=tcp&type=tcp", "type", "duplicate"},
		{"empty param", trojanLink("?&sni=a.example", ""), "query", "empty"},
		{"no value", trojanLink("?sni", ""), "sni", "missing value"},
		{"bad value escape", trojanLink("?sni=%2", ""), "sni", "percent-encoding"},
		{"ws", trojanLink("?type=ws", ""), "type", "unsupported transport"},
		{"grpc", trojanLink("?type=grpc", ""), "type", "unsupported transport"},
		{"raw alias", trojanLink("?type=raw", ""), "type", "unsupported transport"},
		{"empty type", trojanLink("?type=", ""), "type", "unsupported transport"},
		{"security none", trojanLink("?security=none", ""), "security", "required"},
		{"security reality", trojanLink("?security=reality", ""), "security", "unsupported security"},
		{"security xtls", trojanLink("?security=xtls", ""), "security", "unsupported security"},
		{"empty security", trojanLink("?security=", ""), "security", "unsupported security"},
		{"allow insecure", trojanLink("?allowInsecure=1", ""), "allowInsecure", "not supported"},
		{"allow insecure true", trojanLink("?allowInsecure=true", ""), "allowInsecure", "not supported"},
		{"bad allow insecure", trojanLink("?allowInsecure=maybe", ""), "allowInsecure", "boolean"},
		{"http header", trojanLink("?headerType=http", ""), "headerType", "unsupported"},
		{"empty sni", trojanLink("?sni=", ""), "sni", "must not be empty"},
		{"bad sni", trojanLink("?sni=bad_name", ""), "sni", "DNS name"},
		{"bad peer", trojanLink("?peer=192.0.2.1", ""), "peer", "DNS name"},
		{"both sni peer", trojanLink("?sni=a.example&peer=b.example", ""), "peer", "conflicts"},
		{"empty alpn", trojanLink("?alpn=", ""), "alpn", "empty"},
		{"dup alpn", trojanLink("?alpn=h2%2Ch2", ""), "alpn", "duplicate"},
		{"bad alpn", trojanLink("?alpn=h2%2C%2Chttp%2F1.1", ""), "alpn", "malformed"},
		{"path on tcp", trojanLink("?path=%2Fws", ""), "path", "not applicable"},
		{"host on tcp", trojanLink("?host=cdn.example.org", ""), "host", "not applicable"},
		{"fp", trojanLink("?fp=chrome", ""), "fp", "not supported"},
		{"ech", trojanLink("?ech=AAAA", ""), "ech", "not supported"},
		{"unknown param", trojanLink("?foo=1", ""), "foo", "unknown parameter"},
		{"too long", trojanLink("#"+strings.Repeat("a", MaxLinkBytes), ""), "", "exceeds"},
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
	for _, secret := range []string{testPassword, testPasswordEnc, link} {
		if secret != "" && strings.Contains(msg, secret) {
			t.Errorf("error %q leaks credential-bearing input", msg)
		}
	}
}

func TestLinkFormattingHidesCredentials(t *testing.T) {
	l := mustParse(t, trojanLink("", "#label"))
	for _, s := range []string{fmt.Sprint(l), fmt.Sprintf("%+v", l), fmt.Sprintf("%#v", l)} {
		assertNoSecrets(t, s, "")
		if s != "trojan raw+tls vpn.example.net:443" {
			t.Errorf("formatted link = %q", s)
		}
	}
}
