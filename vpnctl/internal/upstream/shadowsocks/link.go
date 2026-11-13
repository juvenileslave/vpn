// Package shadowsocks parses ss:// share links (SIP002 and the legacy fully
// base64 form) and plain or base64 subscriptions into typed candidates and
// Xray outbound configurations.
//
// The package is offline: it never downloads subscriptions, opens network
// connections or applies configurations. Only the subset described in
// docs/UPSTREAM_PARSERS.md is accepted; everything else is an explicit error.
package shadowsocks

import (
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/juvenileslave/vpn/vpnctl/internal/upstream/sharelink"
)

const (
	// MaxLinkBytes bounds the length of a single link.
	MaxLinkBytes = sharelink.MaxLinkBytes
	// MaxSubscriptionBytes bounds the raw subscription body.
	MaxSubscriptionBytes = sharelink.MaxSubscriptionBytes
	// MaxEntries bounds the number of lines in one subscription.
	MaxEntries = sharelink.MaxEntries
)

// methodSpec is one accepted Shadowsocks cipher. keySize is the Shadowsocks
// 2022 key length in bytes; 0 means a legacy AEAD password.
type methodSpec struct {
	canonical string
	keySize   int
}

// methods is the accepted subset of Xray v26.11.9 ciphers: AEAD and
// Shadowsocks 2022 only. Non-AEAD legacy ciphers are deliberately absent.
var methods = map[string]methodSpec{
	"aes-128-gcm":                   {"aes-128-gcm", 0},
	"aes-256-gcm":                   {"aes-256-gcm", 0},
	"chacha20-poly1305":             {"chacha20-poly1305", 0},
	"chacha20-ietf-poly1305":        {"chacha20-poly1305", 0},
	"2022-blake3-aes-128-gcm":       {"2022-blake3-aes-128-gcm", 16},
	"2022-blake3-aes-256-gcm":       {"2022-blake3-aes-256-gcm", 32},
	"2022-blake3-chacha20-poly1305": {"2022-blake3-chacha20-poly1305", 32},
}

// Link is a validated shadowsocks link. Label is display-only and never used
// in network settings. Password is a credential: do not log it.
type Link struct {
	Label    string
	Address  string
	Port     uint16
	Method   string
	Password string
}

// String summarises the link without credentials.
func (l *Link) String() string {
	return fmt.Sprintf("shadowsocks %s %s", l.Method,
		net.JoinHostPort(l.Address, strconv.Itoa(int(l.Port))))
}

// GoString keeps %#v from printing the password.
func (l *Link) GoString() string { return l.String() }

// ParseLink parses one ss:// link: SIP002 with base64 or percent-encoded
// userinfo, or the legacy fully base64 form. Percent-encoding is decoded
// exactly once.
func ParseLink(raw string) (*Link, error) {
	if err := sharelink.ValidateLink(raw); err != nil {
		return nil, err
	}
	rest, err := sharelink.SplitScheme(raw, "ss")
	if err != nil {
		return nil, err
	}

	rest, frag, hasFrag := strings.Cut(rest, "#")
	label, err := sharelink.ParseLabel(frag, hasFrag)
	if err != nil {
		return nil, err
	}

	rest, rawQuery, _ := strings.Cut(rest, "?")
	if err := rejectQuery(rawQuery); err != nil {
		return nil, err
	}

	var method, password, hostport string
	if at := strings.IndexByte(rest, '@'); at >= 0 {
		if strings.Count(rest, "@") != 1 {
			return nil, sharelink.Fieldf("userinfo", "ambiguous user information")
		}
		authority, path, _ := strings.Cut(rest[at+1:], "/")
		if path != "" {
			return nil, sharelink.Fieldf("uri", "unexpected URI path")
		}
		if method, password, err = parseUserinfo(rest[:at]); err != nil {
			return nil, err
		}
		hostport = authority
	} else {
		payload, ok := sharelink.DecodeBase64(rest)
		if !ok {
			return nil, sharelink.Fieldf("uri", "not a SIP002 link or base64 of method:password@host:port")
		}
		if strings.Count(payload, "@") != 1 {
			return nil, sharelink.Fieldf("uri", "legacy payload is not method:password@host:port")
		}
		credentials, host, _ := strings.Cut(payload, "@")
		if method, password, err = parseCredentials(credentials); err != nil {
			return nil, err
		}
		hostport = host
	}

	l := &Link{Label: label}
	if err := l.setCredentials(method, password); err != nil {
		return nil, err
	}
	if l.Address, l.Port, err = sharelink.ParseHostPort(hostport); err != nil {
		return nil, err
	}
	return l, nil
}

// parseUserinfo parses SIP002 userinfo: either percent-encoded
// "method:password" or base64 of it.
func parseUserinfo(raw string) (string, string, error) {
	if raw == "" {
		return "", "", sharelink.Fieldf("userinfo", "missing")
	}
	userinfo, err := sharelink.Unescape(raw)
	if err != nil {
		return "", "", sharelink.Fieldf("userinfo", "%v", err)
	}
	if strings.Contains(userinfo, ":") {
		return parseCredentials(userinfo)
	}
	decoded, ok := sharelink.DecodeBase64(userinfo)
	if !ok {
		return "", "", sharelink.Fieldf("userinfo", "neither base64 userinfo nor method:password")
	}
	return parseCredentials(decoded)
}

// parseCredentials splits "method:password" at the first colon.
func parseCredentials(s string) (string, string, error) {
	method, password, ok := strings.Cut(s, ":")
	if !ok {
		return "", "", sharelink.Fieldf("userinfo", "missing method or password")
	}
	return method, password, nil
}

// setCredentials validates the method and password and normalises the method
// to its canonical Xray name.
func (l *Link) setCredentials(method, password string) error {
	if method == "" {
		return sharelink.Fieldf("method", "missing")
	}
	if password == "" {
		return sharelink.Fieldf("password", "missing")
	}
	spec, ok := methods[strings.ToLower(method)]
	if !ok {
		return sharelink.Fieldf("method", "unsupported method")
	}
	if spec.keySize > 0 {
		if strings.Contains(password, ":") {
			return sharelink.Fieldf("password", "multi-key passwords are not supported")
		}
		key, err := base64.StdEncoding.Strict().DecodeString(password)
		if err != nil || len(key) != spec.keySize {
			return sharelink.Fieldf("password", "not a padded standard base64 key of %d bytes", spec.keySize)
		}
	} else if sharelink.HasControl(password) {
		return sharelink.Fieldf("password", "contains control characters")
	}
	l.Method = spec.canonical
	l.Password = password
	return nil
}

// rejectQuery rejects plugins and any other query parameter.
func rejectQuery(raw string) error {
	if raw == "" {
		return nil
	}
	params, err := sharelink.ParseQuery(raw)
	if err != nil {
		return err
	}
	if _, ok := params.Take("plugin"); ok {
		return sharelink.Fieldf("plugin", "plugins are not supported")
	}
	if keys := params.Keys(); len(keys) > 0 {
		return sharelink.Fieldf(keys[0], "unknown parameter")
	}
	return nil
}
