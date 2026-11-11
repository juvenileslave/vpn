// Package vless parses VLESS share links and plain or base64 subscriptions into
// typed candidates and Xray outbound configurations.
//
// The package is offline: it never downloads subscriptions, opens network
// connections or applies configurations. Only the subset described in
// docs/VLESS_SUBSCRIPTIONS.md is accepted; everything else is an explicit error.
package vless

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxLinkBytes bounds the length of a single link.
const MaxLinkBytes = 16 << 10

// Transport is the stream transport of a link.
type Transport string

// Security is the transport security layer of a link.
type Security string

const (
	// TransportRAW is Xray RAW (formerly TCP), written as type=tcp in links.
	TransportRAW Transport = "raw"
	// TransportXHTTP is Xray XHTTP, written as type=xhttp in links.
	TransportXHTTP Transport = "xhttp"

	SecurityTLS     Security = "tls"
	SecurityREALITY Security = "reality"
)

// Vision flow values accepted by Xray; only valid with RAW transport.
const (
	FlowVision        = "xtls-rprx-vision"
	FlowVisionUDP443  = "xtls-rprx-vision-udp443"
	defaultTLSFP      = "chrome"
	defaultXHTTPPath  = "/"
	defaultXHTTPMode  = "auto"
	encryptionNone    = "none"
	maxLabelRuneCount = 256
)

// Link is a validated VLESS link. Label is display-only and never used in
// network settings. ID and the REALITY keys are credentials: do not log them.
type Link struct {
	Label      string
	ID         string
	Address    string
	Port       uint16
	Encryption string
	Flow       string
	Transport  Transport
	Security   Security
	TLS        *TLS
	Reality    *Reality
	XHTTP      *XHTTP
}

// TLS holds settings for security=tls.
type TLS struct {
	ServerName           string
	Fingerprint          string
	ALPN                 []string
	PinnedPeerCertSHA256 []string
	VerifyPeerCertByName []string
}

// Reality holds client settings for security=reality.
type Reality struct {
	ServerName    string
	Fingerprint   string
	PublicKey     string
	ShortID       string
	SpiderX       string
	MLDSA65Verify string
}

// XHTTP holds settings for type=xhttp.
type XHTTP struct {
	Host  string
	Path  string
	Mode  string
	Extra *XHTTPExtra
}

// String summarises the link without credentials.
func (l *Link) String() string {
	return fmt.Sprintf("vless %s+%s %s", l.Transport, l.Security,
		net.JoinHostPort(l.Address, strconv.Itoa(int(l.Port))))
}

// GoString keeps %#v from printing credentials.
func (l *Link) GoString() string { return l.String() }

var (
	uuidRe      = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	paramNameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,31}$`)
	schemeRe    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]{0,15}$`)
	tokenRe     = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
	alpnRe      = regexp.MustCompile(`^[!-+\--~]+$`) // printable ASCII except ','
)

// knownParams are the documented share-link parameters. A known parameter
// outside the supported combination is "not applicable"; anything else is
// "unknown". Both are errors.
var knownParams = map[string]bool{
	"type": true, "encryption": true, "flow": true, "security": true,
	"fp": true, "sni": true, "alpn": true, "ech": true, "pcs": true, "vcn": true,
	"pbk": true, "sid": true, "pqv": true, "spx": true,
	"path": true, "host": true, "mode": true, "extra": true,
	"mtu": true, "tti": true, "serviceName": true, "authority": true,
	"fm": true, "headerType": true, "allowInsecure": true, "seed": true,
}

// Fingerprints accepted by Xray, excluding "unsafe" and Go's own hello, which
// would weaken or fingerprint the client.
var fingerprints = []string{
	"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq",
	"random", "randomized", "randomizednoalpn",
}

// ParseLink parses one vless:// link. Percent-encoding is decoded exactly once.
func ParseLink(link string) (*Link, error) {
	if len(link) > MaxLinkBytes {
		return nil, fieldErr("", "link exceeds %d bytes", MaxLinkBytes)
	}
	if !utf8.ValidString(link) {
		return nil, fieldErr("", "link is not valid UTF-8")
	}
	for _, r := range link {
		if r <= ' ' || r == 0x7f || unicode.IsSpace(r) {
			return nil, fieldErr("", "link contains unencoded whitespace or control characters")
		}
	}

	scheme, rest, ok := strings.Cut(link, "://")
	if !ok {
		return nil, fieldErr("scheme", "not a URI link")
	}
	if !strings.EqualFold(scheme, "vless") {
		if schemeRe.MatchString(scheme) {
			return nil, fieldErr("scheme", "unsupported scheme %q", strings.ToLower(scheme))
		}
		return nil, fieldErr("scheme", "unsupported scheme")
	}

	l := &Link{}
	rest, frag, hasFrag := strings.Cut(rest, "#")
	if hasFrag {
		label, err := unescape(frag)
		if err != nil {
			return nil, fieldErr("label", "%v", err)
		}
		for _, r := range label {
			if unicode.IsControl(r) {
				return nil, fieldErr("label", "contains control characters")
			}
		}
		if utf8.RuneCountInString(label) > maxLabelRuneCount {
			return nil, fieldErr("label", "longer than %d characters", maxLabelRuneCount)
		}
		l.Label = strings.TrimSpace(label)
	}

	rest, rawQuery, _ := strings.Cut(rest, "?")
	authority, path, _ := strings.Cut(rest, "/")
	if path != "" {
		return nil, fieldErr("uri", "unexpected URI path")
	}
	if strings.Count(authority, "@") != 1 {
		return nil, fieldErr("id", "missing or ambiguous user ID")
	}
	userinfo, hostport, _ := strings.Cut(authority, "@")
	id, err := unescape(userinfo)
	if err != nil {
		return nil, fieldErr("id", "%v", err)
	}
	if !uuidRe.MatchString(id) {
		return nil, fieldErr("id", "not a UUID")
	}
	l.ID = strings.ToLower(id)

	if l.Address, l.Port, err = parseHostPort(hostport); err != nil {
		return nil, err
	}

	params, err := parseQuery(rawQuery)
	if err != nil {
		return nil, err
	}
	if err := l.applyParams(params); err != nil {
		return nil, err
	}
	return l, nil
}

func unescape(s string) (string, error) {
	// PathUnescape keeps '+' literal, matching encodeURIComponent producers.
	v, err := url.PathUnescape(s)
	if err != nil {
		return "", fmt.Errorf("invalid percent-encoding")
	}
	if !utf8.ValidString(v) {
		return "", fmt.Errorf("decodes to invalid UTF-8")
	}
	return v, nil
}

func parseHostPort(s string) (string, uint16, error) {
	var host, portStr string
	if strings.HasPrefix(s, "[") {
		end := strings.IndexByte(s, ']')
		if end < 0 {
			return "", 0, fieldErr("host", "unterminated IPv6 bracket")
		}
		after := s[end+1:]
		if !strings.HasPrefix(after, ":") {
			return "", 0, fieldErr("port", "missing")
		}
		portStr = after[1:]
		addr, err := netip.ParseAddr(s[1:end])
		if err != nil || !addr.Is6() || addr.Zone() != "" {
			return "", 0, fieldErr("host", "invalid bracketed IPv6 address")
		}
		host = addr.String()
	} else {
		i := strings.LastIndexByte(s, ':')
		if i < 0 {
			return "", 0, fieldErr("port", "missing")
		}
		host, portStr = s[:i], s[i+1:]
		switch {
		case host == "":
			return "", 0, fieldErr("host", "missing")
		case strings.Contains(host, ":"):
			return "", 0, fieldErr("host", "IPv6 address must be in brackets")
		}
		if addr, err := netip.ParseAddr(host); err == nil && addr.Is4() {
			host = addr.String()
		} else if validDNSName(host) {
			host = strings.ToLower(host)
		} else {
			return "", 0, fieldErr("host", "not an IPv4 address or DNS name")
		}
	}
	port, err := parsePort(portStr)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

func parsePort(s string) (uint16, error) {
	if s == "" {
		return 0, fieldErr("port", "missing")
	}
	if len(s) > 5 || (len(s) > 1 && s[0] == '0') || strings.Trim(s, "0123456789") != "" {
		return 0, fieldErr("port", "not a decimal port number")
	}
	n, _ := strconv.Atoi(s)
	if n < 1 || n > 65535 {
		return 0, fieldErr("port", "out of range 1-65535")
	}
	return uint16(n), nil
}

// validDNSName accepts LDH names (IDNs must already be in xn-- form). An
// all-numeric final label is rejected so that malformed IPv4 addresses are not
// mistaken for names.
func validDNSName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return strings.Trim(labels[len(labels)-1], "0123456789") != ""
}

func parseQuery(raw string) (map[string]string, error) {
	params := map[string]string{}
	if raw == "" {
		return params, nil
	}
	for _, part := range strings.Split(raw, "&") {
		if part == "" {
			return nil, fieldErr("query", "empty parameter")
		}
		k, v, hasValue := strings.Cut(part, "=")
		if !paramNameRe.MatchString(k) {
			return nil, fieldErr("query", "malformed parameter name")
		}
		if !hasValue {
			return nil, fieldErr(k, "missing value")
		}
		if _, dup := params[k]; dup {
			return nil, fieldErr(k, "duplicate parameter")
		}
		val, err := unescape(v)
		if err != nil {
			return nil, fieldErr(k, "%v", err)
		}
		params[k] = val
	}
	return params, nil
}

// params tracks which query parameters were consumed.
type params map[string]string

func (p params) take(key string) (string, bool) {
	v, ok := p[key]
	delete(p, key)
	return v, ok
}

// takeNonEmpty returns the value of an optional parameter that must not be
// empty when present.
func (p params) takeNonEmpty(key string) (string, bool, error) {
	v, ok := p.take(key)
	if ok && v == "" {
		return "", false, fieldErr(key, "must not be empty")
	}
	return v, ok, nil
}

func (l *Link) applyParams(raw map[string]string) error {
	p := params(raw)

	typ, ok := p.take("type")
	switch {
	case !ok:
		return fieldErr("type", "required")
	case typ == "tcp":
		l.Transport = TransportRAW
	case typ == "xhttp":
		l.Transport = TransportXHTTP
	default:
		return fieldErr("type", "unsupported transport (supported: tcp, xhttp)")
	}

	sec, ok := p.take("security")
	switch {
	case !ok || sec == "none":
		return fieldErr("security", "transport security is required; unencrypted links are not supported")
	case sec == "tls":
		l.Security = SecurityTLS
	case sec == "reality":
		l.Security = SecurityREALITY
	default:
		return fieldErr("security", "unsupported security (supported: tls, reality)")
	}
	if !(l.Transport == TransportRAW && l.Security == SecurityTLS ||
		l.Transport == TransportXHTTP && l.Security == SecurityREALITY) {
		return fieldErr("security", "unsupported combination type=%s, security=%s (supported: tcp+tls, xhttp+reality)", typ, sec)
	}

	l.Encryption = encryptionNone
	if v, ok := p.take("encryption"); ok && v != encryptionNone {
		return fieldErr("encryption", "unsupported VLESS encryption (supported: none)")
	}

	if v, _ := p.take("flow"); v != "" {
		switch {
		case v != FlowVision && v != FlowVisionUDP443:
			return fieldErr("flow", "unsupported flow")
		case l.Transport != TransportRAW:
			return fieldErr("flow", "Vision flow is only valid with type=tcp")
		}
		l.Flow = v
	}

	// No-op values that some exporters emit; any other value changes behaviour.
	if v, ok := p.take("headerType"); ok && v != "none" {
		return fieldErr("headerType", "unsupported header obfuscation (supported: none)")
	}
	if v, ok := p.take("allowInsecure"); ok {
		switch v {
		case "0", "false":
		case "1", "true":
			return fieldErr("allowInsecure", "disabling certificate verification is not supported")
		default:
			return fieldErr("allowInsecure", "invalid boolean")
		}
	}

	var err error
	switch l.Security {
	case SecurityTLS:
		err = l.applyTLS(p)
	case SecurityREALITY:
		err = l.applyReality(p)
	}
	if err != nil {
		return err
	}
	if l.Transport == TransportXHTTP {
		if err := l.applyXHTTP(p); err != nil {
			return err
		}
	}

	if len(p) > 0 {
		keys := make([]string, 0, len(p))
		for k := range p {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if knownParams[keys[0]] {
			return fieldErr(keys[0], "not applicable to type=%s, security=%s", typ, sec)
		}
		return fieldErr(keys[0], "unknown parameter")
	}
	return nil
}

func takeFingerprint(p params, required bool) (string, error) {
	fp, ok, err := p.takeNonEmpty("fp")
	switch {
	case err != nil:
		return "", err
	case !ok && required:
		return "", fieldErr("fp", "required")
	case !ok:
		return defaultTLSFP, nil
	case !slices.Contains(fingerprints, fp):
		return "", fieldErr("fp", "unsupported fingerprint")
	}
	return fp, nil
}

func takeServerName(p params, required bool) (string, error) {
	sni, ok, err := p.takeNonEmpty("sni")
	switch {
	case err != nil:
		return "", err
	case !ok && required:
		return "", fieldErr("sni", "required")
	case ok && !validDNSName(sni):
		return "", fieldErr("sni", "not a DNS name")
	}
	return strings.ToLower(sni), nil
}

func (l *Link) applyTLS(p params) error {
	t := &TLS{}
	var err error
	if t.ServerName, err = takeServerName(p, false); err != nil {
		return err
	}
	if t.Fingerprint, err = takeFingerprint(p, false); err != nil {
		return err
	}
	if _, ok := p.take("ech"); ok {
		return fieldErr("ech", "ECH is not supported")
	}
	if v, ok, err := p.takeNonEmpty("alpn"); err != nil {
		return err
	} else if ok {
		for _, a := range strings.Split(v, ",") {
			switch {
			case a == "" || !alpnRe.MatchString(a):
				return fieldErr("alpn", "malformed protocol list")
			case slices.Contains(t.ALPN, a):
				return fieldErr("alpn", "duplicate protocol")
			}
			t.ALPN = append(t.ALPN, a)
		}
	}
	if v, _ := p.take("pcs"); v != "" {
		for _, h := range strings.Split(v, ",") {
			b, err := hex.DecodeString(strings.ReplaceAll(h, ":", ""))
			if err != nil || len(b) != 32 {
				return fieldErr("pcs", "not a list of SHA-256 fingerprints")
			}
			t.PinnedPeerCertSHA256 = append(t.PinnedPeerCertSHA256, hex.EncodeToString(b))
		}
	}
	if v, _ := p.take("vcn"); v != "" {
		for _, n := range strings.Split(v, ",") {
			if !validDNSName(n) {
				return fieldErr("vcn", "not a list of DNS names")
			}
			t.VerifyPeerCertByName = append(t.VerifyPeerCertByName, strings.ToLower(n))
		}
	}
	l.TLS = t
	return nil
}

func (l *Link) applyReality(p params) error {
	r := &Reality{}
	var err error
	if r.ServerName, err = takeServerName(p, true); err != nil {
		return err
	}
	if r.Fingerprint, err = takeFingerprint(p, true); err != nil {
		return err
	}
	pbk, ok := p.take("pbk")
	if !ok || pbk == "" {
		return fieldErr("pbk", "required")
	}
	if b, err := base64.RawURLEncoding.Strict().DecodeString(pbk); err != nil || len(b) != 32 {
		return fieldErr("pbk", "not a base64url X25519 public key")
	}
	r.PublicKey = pbk
	if sid, _ := p.take("sid"); sid != "" {
		if len(sid) > 16 || len(sid)%2 != 0 {
			return fieldErr("sid", "must be an even number of hex digits, at most 16")
		}
		if _, err := hex.DecodeString(sid); err != nil {
			return fieldErr("sid", "not hexadecimal")
		}
		r.ShortID = strings.ToLower(sid)
	}
	if spx, _ := p.take("spx"); spx != "" {
		if spx[0] != '/' || hasControlOrSpace(spx) {
			return fieldErr("spx", "must start with / and contain no whitespace")
		}
		r.SpiderX = spx
	}
	if pqv, _ := p.take("pqv"); pqv != "" {
		if b, err := base64.RawURLEncoding.Strict().DecodeString(pqv); err != nil || len(b) != 1952 {
			return fieldErr("pqv", "not a base64url ML-DSA-65 public key")
		}
		r.MLDSA65Verify = pqv
	}
	l.Reality = r
	return nil
}

func (l *Link) applyXHTTP(p params) error {
	x := &XHTTP{Path: defaultXHTTPPath, Mode: defaultXHTTPMode}
	if v, ok, err := p.takeNonEmpty("path"); err != nil {
		return err
	} else if ok {
		if v[0] != '/' || hasControlOrSpace(v) {
			return fieldErr("path", "must be an absolute path without whitespace")
		}
		x.Path = v
	}
	if v, ok, err := p.takeNonEmpty("host"); err != nil {
		return err
	} else if ok {
		if !validDNSName(v) {
			if a, err := netip.ParseAddr(v); err != nil || a.Zone() != "" {
				return fieldErr("host", "not a DNS name or IP address")
			}
		}
		x.Host = v
	}
	if v, ok, err := p.takeNonEmpty("mode"); err != nil {
		return err
	} else if ok {
		if !slices.Contains(xhttpModes, v) {
			return fieldErr("mode", "unsupported XHTTP mode")
		}
		x.Mode = v
	}
	if v, ok, err := p.takeNonEmpty("extra"); err != nil {
		return err
	} else if ok {
		extra, err := parseExtra(v, x)
		if err != nil {
			return err
		}
		x.Extra = extra
	}
	l.XHTTP = x
	return nil
}

func hasControlOrSpace(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) >= 0
}
