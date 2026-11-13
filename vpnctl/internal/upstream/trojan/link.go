// Package trojan parses trojan:// share links and plain or base64
// subscriptions into typed candidates and Xray outbound configurations.
//
// The package is offline: it never downloads subscriptions, opens network
// connections or applies configurations. Only the subset described in
// docs/UPSTREAM_PARSERS.md is accepted; everything else is an explicit error.
package trojan

import (
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

// Transport is the stream transport of a link. Only Xray RAW (formerly TCP) is
// supported, matching what the renderer and the pinned core accept for trojan.
type Transport string

const (
	// TransportRAW is Xray RAW, written as type=tcp in links.
	TransportRAW Transport = "raw"
)

// TLS holds the client TLS settings of a link.
type TLS struct {
	ServerName string
	ALPN       []string
}

// Link is a validated trojan link. Label is display-only and never used in
// network settings. Password is a credential: do not log it.
type Link struct {
	Label     string
	Password  string
	Address   string
	Port      uint16
	Transport Transport
	TLS       TLS
}

// String summarises the link without credentials.
func (l *Link) String() string {
	return fmt.Sprintf("trojan %s+tls %s", l.Transport,
		net.JoinHostPort(l.Address, strconv.Itoa(int(l.Port))))
}

// GoString keeps %#v from printing the password.
func (l *Link) GoString() string { return l.String() }

// unsupportedParams are parameters of other transports or of a wider TLS
// feature set that this parser deliberately rejects.
var unsupportedParams = map[string]string{
	"fp":   "uTLS fingerprints are not supported",
	"pcs":  "certificate pinning is not supported",
	"vcn":  "certificate name verification is not supported",
	"ech":  "ECH is not supported",
	"flow": "XTLS flow is not supported",
}

// transportParams apply to non-TCP transports only.
var transportParams = map[string]bool{
	"path": true, "host": true, "serviceName": true, "mode": true,
}

// ParseLink parses one trojan:// link. Percent-encoding is decoded exactly
// once.
func ParseLink(raw string) (*Link, error) {
	if err := sharelink.ValidateLink(raw); err != nil {
		return nil, err
	}
	rest, err := sharelink.SplitScheme(raw, "trojan")
	if err != nil {
		return nil, err
	}

	rest, frag, hasFrag := strings.Cut(rest, "#")
	label, err := sharelink.ParseLabel(frag, hasFrag)
	if err != nil {
		return nil, err
	}

	rest, rawQuery, _ := strings.Cut(rest, "?")
	authority, path, _ := strings.Cut(rest, "/")
	if path != "" {
		return nil, sharelink.Fieldf("uri", "unexpected URI path")
	}
	if strings.Count(authority, "@") != 1 {
		return nil, sharelink.Fieldf("password", "missing or ambiguous password")
	}
	userinfo, hostport, _ := strings.Cut(authority, "@")
	password, err := sharelink.Unescape(userinfo)
	if err != nil {
		return nil, sharelink.Fieldf("password", "%v", err)
	}
	switch {
	case password == "":
		return nil, sharelink.Fieldf("password", "missing")
	case sharelink.HasControl(password):
		return nil, sharelink.Fieldf("password", "contains control characters")
	}

	l := &Link{Label: label, Password: password, Transport: TransportRAW}
	if l.Address, l.Port, err = sharelink.ParseHostPort(hostport); err != nil {
		return nil, err
	}

	params, err := sharelink.ParseQuery(rawQuery)
	if err != nil {
		return nil, err
	}
	if err := l.applyParams(params); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *Link) applyParams(p sharelink.Params) error {
	typ, ok := p.Take("type")
	if ok && typ != "tcp" {
		return sharelink.Fieldf("type", "unsupported transport (supported: tcp)")
	}

	sec, ok := p.Take("security")
	switch {
	case !ok, sec == "tls":
	case sec == "none":
		return sharelink.Fieldf("security", "transport security is required; unencrypted links are not supported")
	default:
		return sharelink.Fieldf("security", "unsupported security (supported: tls)")
	}

	if v, ok := p.Take("allowInsecure"); ok {
		switch v {
		case "0", "false":
		case "1", "true":
			return sharelink.Fieldf("allowInsecure", "disabling certificate verification is not supported")
		default:
			return sharelink.Fieldf("allowInsecure", "invalid boolean")
		}
	}
	if v, ok := p.Take("headerType"); ok && v != "none" {
		return sharelink.Fieldf("headerType", "unsupported header obfuscation (supported: none)")
	}

	sni, hasSNI, err := p.TakeNonEmpty("sni")
	if err != nil {
		return err
	}
	peer, hasPeer, err := p.TakeNonEmpty("peer")
	if err != nil {
		return err
	}
	if hasSNI && hasPeer {
		return sharelink.Fieldf("peer", "conflicts with sni")
	}
	sniField := "sni"
	if !hasSNI {
		sni, sniField = peer, "peer"
	}
	if sni != "" {
		if !sharelink.ValidDNSName(sni) {
			return sharelink.Fieldf(sniField, "not a DNS name")
		}
		l.TLS.ServerName = strings.ToLower(sni)
	}

	alpn, _, err := p.TakeALPN()
	if err != nil {
		return err
	}
	l.TLS.ALPN = alpn

	if keys := p.Keys(); len(keys) > 0 {
		field := keys[0]
		if reason, ok := unsupportedParams[field]; ok {
			return sharelink.Fieldf(field, "%s", reason)
		}
		if transportParams[field] {
			return sharelink.Fieldf(field, "not applicable to type=tcp")
		}
		return sharelink.Fieldf(field, "unknown parameter")
	}
	return nil
}
