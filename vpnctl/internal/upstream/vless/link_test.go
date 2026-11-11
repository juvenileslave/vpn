package vless

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

// Synthetic credentials and RFC 5737/3849 documentation addresses only.
const (
	testID  = "6f1d2e3c-4b5a-4987-8a6b-5c4d3e2f1a0b"
	testSID = "a1b2c3d4"
)

var (
	testPBK = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 32))
	testPQV = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x3c}, 1952))
	testPCS = strings.Repeat("ab", 32)
)

func realityLink(query, label string) string {
	return "vless://" + testID + "@vpn.example.net:443?type=xhttp&security=reality&sni=www.example.com&fp=chrome&pbk=" +
		testPBK + "&sid=" + testSID + query + label
}

func tlsLink(query string) string {
	return "vless://" + testID + "@192.0.2.10:8443?type=tcp&security=tls&sni=tls.example.com" + query
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

func TestParseLinkXHTTPReality(t *testing.T) {
	extra := `{"headers":{"User-Agent":"Mozilla/5.0 (X11)"},"xPaddingBytes":"100-1000","noGRPCHeader":true,` +
		`"scMaxEachPostBytes":1000000,"uplinkHTTPMethod":"get","uplinkDataPlacement":"header",` +
		`"xmux":{"maxConcurrency":"16-32","hKeepAlivePeriod":-1}}`
	link := realityLink("&spx=%2Fsearch%3Fq%3D1&pqv="+testPQV+"&encryption=none&path=%2Fapi%2Fv1&host=cdn.example.org&mode=packet-up&extra="+
		url.PathEscape(extra), "#%D0%9D%D0%BE%D0%B4%D0%B0%20100%2541")
	l := mustParse(t, link)

	if l.Label != "Нода 100%41" {
		t.Errorf("label decoded %q; want single decoding", l.Label)
	}
	got := outboundJSON(t, l, "proxy-1")
	want := jsonValue(t, `{
	  "tag": "proxy-1",
	  "protocol": "vless",
	  "settings": {"vnext": [{"address": "vpn.example.net", "port": 443,
	    "users": [{"id": "`+testID+`", "encryption": "none"}]}]},
	  "streamSettings": {
	    "network": "xhttp",
	    "security": "reality",
	    "realitySettings": {"serverName": "www.example.com", "fingerprint": "chrome",
	      "password": "`+testPBK+`", "shortId": "`+testSID+`", "spiderX": "/search?q=1",
	      "mldsa65Verify": "`+testPQV+`"},
	    "xhttpSettings": {"host": "cdn.example.org", "path": "/api/v1", "mode": "packet-up",
	      "headers": {"User-Agent": "Mozilla/5.0 (X11)"}, "xPaddingBytes": "100-1000",
	      "noGRPCHeader": true, "scMaxEachPostBytes": 1000000, "uplinkHTTPMethod": "GET",
	      "uplinkDataPlacement": "header",
	      "xmux": {"maxConcurrency": "16-32", "hKeepAlivePeriod": -1}}
	  }
	}`)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("outbound mismatch\n got: %v\nwant: %v", got, want)
	}
}

func TestXHTTPDefaultsAddNoFlowOrXmux(t *testing.T) {
	l := mustParse(t, realityLink("", ""))
	got := outboundJSON(t, l, "")
	ss := got["streamSettings"].(map[string]any)
	if x := ss["xhttpSettings"]; !reflect.DeepEqual(x, map[string]any{"path": "/", "mode": "auto"}) {
		t.Errorf("xhttpSettings = %v; want only default path and mode", x)
	}
	user := got["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)
	if _, ok := user["flow"]; ok {
		t.Error("flow must not be injected for XHTTP")
	}
	if _, ok := got["tag"]; ok {
		t.Error("empty tag must be omitted; the label is never used as a tag")
	}
	// Extra repeating link values or holding only defaults adds nothing.
	l = mustParse(t, realityLink("&extra="+url.PathEscape(`{"path":"/","mode":"auto","xmux":{}}`), ""))
	if l.XHTTP.Extra != nil {
		t.Errorf("extra = %+v; want nil", l.XHTTP.Extra)
	}
}

func TestParseLinkRawTLS(t *testing.T) {
	l := mustParse(t, tlsLink("&flow=xtls-rprx-vision&alpn=h2%2Chttp%2F1.1&pcs="+testPCS+"&vcn=cert.example.com&headerType=none&allowInsecure=0#tls"))
	got := outboundJSON(t, l, "t")
	want := jsonValue(t, `{
	  "tag": "t", "protocol": "vless",
	  "settings": {"vnext": [{"address": "192.0.2.10", "port": 8443,
	    "users": [{"id": "`+testID+`", "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
	  "streamSettings": {"network": "raw", "security": "tls",
	    "tlsSettings": {"serverName": "tls.example.com", "fingerprint": "chrome",
	      "alpn": ["h2", "http/1.1"], "pinnedPeerCertSha256": "`+testPCS+`",
	      "verifyPeerCertByName": "cert.example.com"}}
	}`)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("outbound mismatch\n got: %v\nwant: %v", got, want)
	}
	if l.Label != "tls" {
		t.Errorf("label = %q", l.Label)
	}

	// Without sni Xray uses the address; fp defaults to chrome per the spec.
	l = mustParse(t, "vless://"+testID+"@Example.COM:443/?type=tcp&security=tls&fp=firefox")
	if l.TLS.ServerName != "" || l.TLS.Fingerprint != "firefox" || l.Address != "example.com" || l.Flow != "" {
		t.Errorf("got %+v %+v", *l.TLS, l)
	}
}

func TestParseLinkAddresses(t *testing.T) {
	for _, tc := range []struct{ hostport, want string }{
		{"[2001:db8::10]:443", "2001:db8::10"},
		{"[2001:DB8:0:0::10]:443", "2001:db8::10"},
		{"198.51.100.7:443", "198.51.100.7"},
		{"xn--e1afmkfd.example:443", "xn--e1afmkfd.example"},
	} {
		l := mustParse(t, "vless://"+testID+"@"+tc.hostport+"?type=tcp&security=tls")
		if l.Address != tc.want || l.Port != 443 {
			t.Errorf("%s: address %q port %d", tc.hostport, l.Address, l.Port)
		}
		if tc.want == "2001:db8::10" && l.String() != "vless raw+tls [2001:db8::10]:443" {
			t.Errorf("String() = %q", l.String())
		}
	}
}

func TestParseLinkErrors(t *testing.T) {
	x := func(extra string) string { return realityLink("&extra="+url.PathEscape(extra), "") }
	tests := []struct {
		name, link, field, reason string
	}{
		{"no scheme", testID + "@192.0.2.1:443", "scheme", "not a URI"},
		{"other scheme", "vmess://" + testID + "@192.0.2.1:443", "scheme", `"vmess"`},
		{"whitespace", tlsLink(" "), "", "whitespace"},
		{"bad id", "vless://not-a-uuid@192.0.2.1:443?type=tcp&security=tls", "id", "not a UUID"},
		{"two at", "vless://" + testID + "@x@192.0.2.1:443?type=tcp&security=tls", "id", "ambiguous"},
		{"bad id escape", "vless://%zz@192.0.2.1:443?type=tcp&security=tls", "id", "percent-encoding"},
		{"missing port", "vless://" + testID + "@192.0.2.1?type=tcp&security=tls", "port", "missing"},
		{"empty port", "vless://" + testID + "@192.0.2.1:?type=tcp&security=tls", "port", "missing"},
		{"port zero", "vless://" + testID + "@192.0.2.1:0?type=tcp&security=tls", "port", "range"},
		{"port high", "vless://" + testID + "@192.0.2.1:65536?type=tcp&security=tls", "port", "range"},
		{"port leading zero", "vless://" + testID + "@192.0.2.1:0443?type=tcp&security=tls", "port", "decimal"},
		{"port sign", "vless://" + testID + "@192.0.2.1:+443?type=tcp&security=tls", "port", "decimal"},
		{"bare ipv6", "vless://" + testID + "@2001:db8::1:443?type=tcp&security=tls", "host", "brackets"},
		{"bracketed ipv4", "vless://" + testID + "@[192.0.2.1]:443?type=tcp&security=tls", "host", "IPv6"},
		{"ipv6 zone", "vless://" + testID + "@[fe80::1%25eth0]:443?type=tcp&security=tls", "host", "IPv6"},
		{"unterminated ipv6", "vless://" + testID + "@[2001:db8::1:443?type=tcp&security=tls", "host", "unterminated"},
		{"short ipv4", "vless://" + testID + "@192.0.2:443?type=tcp&security=tls", "host", "DNS name"},
		{"underscore host", "vless://" + testID + "@bad_host.example:443?type=tcp&security=tls", "host", "DNS name"},
		{"encoded host", "vless://" + testID + "@ex%61mple.com:443?type=tcp&security=tls", "host", "DNS name"},
		{"uri path", "vless://" + testID + "@192.0.2.1:443/sub?type=tcp&security=tls", "uri", "path"},
		{"bad label escape", tlsLink("#%E0%A4"), "label", "UTF-8"},
		{"control label", tlsLink("#a%0Ab"), "label", "control"},
		{"duplicate param", tlsLink("&type=tcp"), "type", "duplicate"},
		{"empty param", tlsLink("&&fp=chrome"), "query", "empty"},
		{"no value", tlsLink("&fp"), "fp", "missing value"},
		{"bad value escape", tlsLink("&fp=%2"), "fp", "percent-encoding"},
		{"no type", "vless://" + testID + "@192.0.2.1:443?security=tls", "type", "required"},
		{"ws", "vless://" + testID + "@192.0.2.1:443?type=ws&security=tls", "type", "unsupported transport"},
		{"raw alias", "vless://" + testID + "@192.0.2.1:443?type=raw&security=tls", "type", "unsupported transport"},
		{"splithttp alias", "vless://" + testID + "@192.0.2.1:443?type=splithttp&security=reality", "type", "unsupported transport"},
		{"grpc", "vless://" + testID + "@192.0.2.1:443?type=grpc&security=reality", "type", "unsupported transport"},
		{"no security", "vless://" + testID + "@192.0.2.1:443?type=tcp", "security", "required"},
		{"security none", "vless://" + testID + "@192.0.2.1:443?type=xhttp&security=none", "security", "required"},
		{"xtls", "vless://" + testID + "@192.0.2.1:443?type=tcp&security=xtls", "security", "unsupported security"},
		{"raw reality", "vless://" + testID + "@192.0.2.1:443?type=tcp&security=reality&pbk=" + testPBK, "security", "combination"},
		{"xhttp tls", "vless://" + testID + "@192.0.2.1:443?type=xhttp&security=tls", "security", "combination"},
		{"encryption", tlsLink("&encryption=mlkem768x25519plus.native.0rtt.AAAA"), "encryption", "unsupported"},
		{"empty encryption", tlsLink("&encryption="), "encryption", "unsupported"},
		{"vision on xhttp", realityLink("&flow=xtls-rprx-vision", ""), "flow", "only valid with type=tcp"},
		{"unknown flow", tlsLink("&flow=xtls-rprx-direct"), "flow", "unsupported flow"},
		{"http header", tlsLink("&headerType=http"), "headerType", "unsupported"},
		{"allow insecure", tlsLink("&allowInsecure=1"), "allowInsecure", "not supported"},
		{"ech", tlsLink("&ech=AAAA"), "ech", "not supported"},
		{"empty sni", "vless://" + testID + "@192.0.2.1:443?type=tcp&security=tls&sni=", "sni", "must not be empty"},
		{"bad fp", tlsLink("&fp=unsafe"), "fp", "unsupported fingerprint"},
		{"go fp", tlsLink("&fp=hellogolang"), "fp", "unsupported fingerprint"},
		{"empty alpn", tlsLink("&alpn="), "alpn", "empty"},
		{"dup alpn", tlsLink("&alpn=h2%2Ch2"), "alpn", "duplicate"},
		{"bad pcs", tlsLink("&pcs=abcd"), "pcs", "SHA-256"},
		{"bad vcn", tlsLink("&vcn=bad_name"), "vcn", "DNS"},
		{"host on raw", tlsLink("&host=cdn.example.org"), "host", "not applicable to type=tcp, security=tls"},
		{"pbk on tls", tlsLink("&pbk=" + testPBK), "pbk", "not applicable"},
		{"unknown param", tlsLink("&foo=1"), "foo", "unknown parameter"},
		{"alpn on reality", realityLink("&alpn=h2", ""), "alpn", "not applicable"},
		{"service name on xhttp", realityLink("&serviceName=svc", ""), "serviceName", "not applicable"},
		{"no pbk", "vless://" + testID + "@192.0.2.1:443?type=xhttp&security=reality&sni=www.example.com&fp=chrome", "pbk", "required"},
		{"short pbk", "vless://" + testID + "@192.0.2.1:443?type=xhttp&security=reality&sni=www.example.com&fp=chrome&pbk=" + testPBK[:20], "pbk", "public key"},
		{"padded pbk", "vless://" + testID + "@192.0.2.1:443?type=xhttp&security=reality&sni=www.example.com&fp=chrome&pbk=" + testPBK + "%3D", "pbk", "public key"},
		{"no fp", "vless://" + testID + "@192.0.2.1:443?type=xhttp&security=reality&sni=www.example.com&pbk=" + testPBK, "fp", "required"},
		{"no sni", "vless://" + testID + "@192.0.2.1:443?type=xhttp&security=reality&fp=chrome&pbk=" + testPBK, "sni", "required"},
		{"ip sni", "vless://" + testID + "@192.0.2.1:443?type=xhttp&security=reality&fp=chrome&sni=192.0.2.1&pbk=" + testPBK, "sni", "DNS name"},
		{"odd sid", realityLink("", "")[:len(realityLink("", ""))-1], "sid", "even"},
		{"long sid", strings.Replace(realityLink("", ""), testSID, strings.Repeat("ab", 9), 1), "sid", "at most 16"},
		{"hex sid", strings.Replace(realityLink("", ""), testSID, "zz11", 1), "sid", "hexadecimal"},
		{"relative spx", realityLink("&spx=search", ""), "spx", "start with /"},
		{"spx space", realityLink("&spx=%2Fa%20b", ""), "spx", "whitespace"},
		{"bad pqv", realityLink("&pqv=AAAA", ""), "pqv", "ML-DSA-65"},
		{"bad mode", realityLink("&mode=stream", ""), "mode", "unsupported XHTTP mode"},
		{"relative path", realityLink("&path=api", ""), "path", "absolute"},
		{"empty path", realityLink("&path=", ""), "path", "empty"},
		{"bad xhttp host", realityLink("&host=a%20b", ""), "host", "DNS name or IP"},
		{"extra syntax", x(`{"noGRPCHeader":`), "extra", "JSON object"},
		{"extra array", x(`[1]`), "extra", "JSON object"},
		{"extra trailing", x(`{}{}`), "extra", "JSON object"},
		{"extra duplicate", x(`{"noGRPCHeader":true,"noGRPCHeader":false}`), "extra.noGRPCHeader", "duplicate"},
		{"extra unknown", x(`{"futureOption":1}`), "extra.futureOption", "unknown option"},
		{"extra unsafe key", x(`{"a b":1}`), "extra", "unknown option"},
		{"extra server only", x(`{"noSSEHeader":true}`), "extra.noSSEHeader", "server-side"},
		{"extra download", x(`{"downloadSettings":{}}`), "extra.downloadSettings", "not supported"},
		{"extra path conflict", x(`{"path":"/other"}`), "extra.path", "conflicts"},
		{"extra mode conflict", x(`{"mode":"stream-one"}`), "extra.mode", "conflicts"},
		{"extra wrong type", x(`{"noGRPCHeader":"yes"}`), "extra.noGRPCHeader", "boolean"},
		{"extra null", x(`{"xPaddingKey":null}`), "extra.xPaddingKey", "string"},
		{"extra host header", x(`{"headers":{"host":"a.example"}}`), "extra.headers.host", "host link parameter"},
		{"extra header dup", x(`{"headers":{"X-A":"1","x-a":"2"}}`), "extra.headers.x-a", "duplicate"},
		{"extra header crlf", x(`{"headers":{"X-A":"1\r\nX-B: 2"}}`), "extra.headers.X-A", "control"},
		{"extra padding off", x(`{"xPaddingBytes":0}`), "extra.xPaddingBytes", "cannot be disabled"},
		{"extra reversed range", x(`{"xPaddingBytes":"500-100"}`), "extra.xPaddingBytes", "exceeds"},
		{"extra negative", x(`{"scMaxEachPostBytes":-1}`), "extra.scMaxEachPostBytes", "non-negative"},
		{"extra float", x(`{"scMaxEachPostBytes":1.5}`), "extra.scMaxEachPostBytes", "non-negative"},
		{"extra placement", x(`{"xPaddingPlacement":"body"}`), "extra.xPaddingPlacement", "unsupported value"},
		{"extra get mode", x(`{"uplinkHTTPMethod":"GET"}`), "extra.uplinkHTTPMethod", "packet-up"},
		{"extra data placement mode", x(`{"uplinkDataPlacement":"cookie"}`), "extra.uplinkDataPlacement", "packet-up"},
		{"extra xmux conflict", x(`{"xmux":{"maxConnections":4,"maxConcurrency":8}}`), "extra.xmux", "conflicts"},
		{"extra xmux unknown", x(`{"xmux":{"maxStreams":4}}`), "extra.xmux.maxStreams", "unknown"},
		{"extra keepalive", x(`{"xmux":{"hKeepAlivePeriod":"30"}}`), "extra.xmux.hKeepAlivePeriod", "integer"},
		{"extra too large", x(`{"headers":{"X-A":"` + strings.Repeat("a", MaxExtraBytes) + `"}}`), "extra", "exceeds"},
		{"too long", tlsLink("#" + strings.Repeat("a", MaxLinkBytes)), "", "exceeds"},
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
	for _, secret := range []string{testID, testPBK, testPQV, testSID, testPCS, "zz11", link} {
		if secret != "" && strings.Contains(msg, secret) {
			t.Errorf("error %q leaks credential-bearing input", msg)
		}
	}
}

func TestLinkFormattingHidesCredentials(t *testing.T) {
	l := mustParse(t, realityLink("", "#label"))
	for _, s := range []string{fmt.Sprint(l), fmt.Sprintf("%+v", l), fmt.Sprintf("%#v", l)} {
		assertNoSecrets(t, s, "")
		if s != "vless xhttp+reality vpn.example.net:443" {
			t.Errorf("formatted link = %q", s)
		}
	}
}
