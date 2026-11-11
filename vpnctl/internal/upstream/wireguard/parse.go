// Package wireguard parses WireGuard client configurations in the wg-quick INI
// format and converts them to Xray wireguard outbounds.
//
// Parsing is purely offline: the package never executes configuration
// content, never runs wg or wg-quick, never creates interfaces and never
// resolves or contacts endpoints. Shell hooks and directives that change host
// behaviour outside the tunnel are rejected rather than ignored. A successful
// parse proves only that the file is well formed, not that the tunnel works.
package wireguard

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MaxConfigSize bounds the input accepted by Parse.
const MaxConfigSize = 64 << 10

const (
	minMTU     = 576
	minIPv6MTU = 1280
	maxMTU     = 65535
)

type section int

const (
	sectionNone section = iota
	sectionInterface
	sectionPeer
	sectionInvalid
)

// keySpec describes a recognised key. Keys are matched case-insensitively so
// that variants such as "postup" cannot slip past hook rejection.
type keySpec struct {
	name    string
	section section // sectionNone for keys that are always rejected
	kind    error   // non-nil: always rejected with this kind and reason
	reason  string
	list    bool // may repeat; values accumulate
}

var keySpecs = func() map[string]keySpec {
	specs := []keySpec{
		{name: "PrivateKey", section: sectionInterface},
		{name: "Address", section: sectionInterface, list: true},
		{name: "DNS", section: sectionInterface, list: true},
		{name: "MTU", section: sectionInterface},
		{name: "PublicKey", section: sectionPeer},
		{name: "PresharedKey", section: sectionPeer},
		{name: "Endpoint", section: sectionPeer},
		{name: "AllowedIPs", section: sectionPeer, list: true},
		{name: "PersistentKeepalive", section: sectionPeer},

		{name: "PreUp", kind: ErrHook, reason: "shell commands are never executed"},
		{name: "PostUp", kind: ErrHook, reason: "shell commands are never executed"},
		{name: "PreDown", kind: ErrHook, reason: "shell commands are never executed"},
		{name: "PostDown", kind: ErrHook, reason: "shell commands are never executed"},
		{name: "Table", kind: ErrUnsupported, reason: "host routing table control is not supported"},
		{name: "FwMark", kind: ErrUnsupported, reason: "firewall marks are not supported"},
		{name: "ListenPort", kind: ErrUnsupported, reason: "fixed listen port is not supported by the Xray outbound"},
		{name: "SaveConfig", kind: ErrUnsupported, reason: "writing the config back is not supported"},
	}
	m := make(map[string]keySpec, len(specs))
	for _, s := range specs {
		m[strings.ToLower(s.name)] = s
	}
	return m
}()

type peerState struct {
	line      int
	peer      Peer
	seen      map[string]bool
	hasPubKey bool
}

type parser struct {
	errs ErrorList

	cur     section
	ifLine  int
	iface   Interface
	ifSeen  map[string]bool
	mtuLine int
	peers   []*peerState

	addresses  map[netip.Addr]bool
	allowedIPs map[netip.Prefix]bool
}

// Parse validates a WireGuard client configuration. On failure it returns an
// ErrorList describing every problem found; errors never contain values.
func Parse(data []byte) (*Config, error) {
	p := &parser{
		ifSeen:     map[string]bool{},
		addresses:  map[netip.Addr]bool{},
		allowedIPs: map[netip.Prefix]bool{},
	}
	if len(data) > MaxConfigSize {
		p.fail(0, "", "", ErrInvalid, "config exceeds 64 KiB")
		return nil, p.errs
	}
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		p.fail(0, "", "", ErrSyntax, "config must be UTF-8 text without NUL bytes")
		return nil, p.errs
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))

	for i, raw := range strings.Split(string(data), "\n") {
		p.line(i+1, raw)
	}
	p.finish()
	if len(p.errs) > 0 {
		return nil, p.errs
	}

	cfg := &Config{Interface: p.iface, Peers: make([]Peer, len(p.peers))}
	for i, ps := range p.peers {
		cfg.Peers[i] = ps.peer
	}
	return cfg, nil
}

func (p *parser) fail(line int, sect, key string, kind error, reason string) {
	p.errs = append(p.errs, &Error{Line: line, Section: sect, Key: key, Kind: kind, Reason: reason})
}

func (p *parser) sectionName() string {
	switch p.cur {
	case sectionInterface:
		return "Interface"
	case sectionPeer:
		return "Peer " + strconv.Itoa(len(p.peers))
	}
	return ""
}

func (p *parser) line(n int, raw string) {
	text := strings.TrimSuffix(raw, "\r")
	if i := strings.IndexByte(text, '#'); i >= 0 {
		text = text[:i]
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return
	}

	if strings.HasPrefix(text, "[") {
		p.header(n, text)
		return
	}

	eq := strings.IndexByte(text, '=')
	if eq < 0 {
		p.fail(n, p.sectionName(), "", ErrSyntax, "expected key = value")
		return
	}
	rawKey := strings.TrimSpace(text[:eq])
	value := strings.TrimSpace(text[eq+1:])

	spec, ok := keySpecs[strings.ToLower(rawKey)]
	switch {
	case !ok:
		// The unknown name itself is not echoed: it may be a pasted key.
		p.fail(n, p.sectionName(), "", ErrUnsupported, "unknown key")
	case spec.kind != nil:
		p.fail(n, p.sectionName(), spec.name, spec.kind, spec.reason)
	case p.cur == sectionInvalid:
		// The enclosing section header was already reported.
	case p.cur == sectionNone:
		p.fail(n, "", spec.name, ErrSyntax, "key outside of a section")
	case spec.section != p.cur:
		p.fail(n, p.sectionName(), spec.name, ErrUnsupported, "key is not valid in this section")
	case p.cur == sectionInterface:
		p.interfaceKey(n, spec, value)
	default:
		p.peerKey(n, spec, value)
	}
}

func (p *parser) header(n int, text string) {
	if !strings.HasSuffix(text, "]") {
		p.cur = sectionInvalid
		p.fail(n, "", "", ErrSyntax, "malformed section header")
		return
	}
	name := strings.TrimSpace(text[1 : len(text)-1])
	switch {
	case strings.EqualFold(name, "Interface"):
		if p.ifLine != 0 {
			p.cur = sectionInvalid
			p.fail(n, "Interface", "", ErrDuplicate, "only one [Interface] section is allowed")
			return
		}
		p.cur = sectionInterface
		p.ifLine = n
	case strings.EqualFold(name, "Peer"):
		p.cur = sectionPeer
		p.peers = append(p.peers, &peerState{line: n, seen: map[string]bool{}})
	default:
		p.cur = sectionInvalid
		p.fail(n, "", "", ErrUnsupported, "unknown section")
	}
}

// once reports whether a single-valued key is seen for the first time.
func (p *parser) once(n int, seen map[string]bool, spec keySpec) bool {
	if spec.list {
		seen[spec.name] = true
		return true
	}
	if seen[spec.name] {
		p.fail(n, p.sectionName(), spec.name, ErrDuplicate, "key may appear only once per section")
		return false
	}
	seen[spec.name] = true
	return true
}

// items splits a comma-separated list, reporting empty values and items.
func (p *parser) items(n int, key, value string) []string {
	if value == "" {
		p.fail(n, p.sectionName(), key, ErrInvalid, "empty value")
		return nil
	}
	parts := strings.Split(value, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
		if parts[i] == "" {
			p.fail(n, p.sectionName(), key, ErrSyntax, "empty list item")
			return nil
		}
	}
	return parts
}

func (p *parser) interfaceKey(n int, spec keySpec, value string) {
	if !p.once(n, p.ifSeen, spec) {
		return
	}
	sect := p.sectionName()
	switch spec.name {
	case "PrivateKey":
		k, err := ParseKey(value)
		if err != nil {
			p.fail(n, sect, spec.name, ErrInvalid, err.Error())
			return
		}
		p.iface.PrivateKey = k
	case "Address":
		for _, item := range p.items(n, spec.name, value) {
			pfx, ok := parsePrefix(item)
			if !ok || pfx.Addr().IsUnspecified() {
				p.fail(n, sect, spec.name, ErrInvalid, "must be an IP address or CIDR")
				continue
			}
			if p.addresses[pfx.Addr()] {
				p.fail(n, sect, spec.name, ErrDuplicate, "address repeated")
				continue
			}
			p.addresses[pfx.Addr()] = true
			p.iface.Addresses = append(p.iface.Addresses, pfx)
		}
	case "DNS":
		for _, item := range p.items(n, spec.name, value) {
			a, err := netip.ParseAddr(item)
			if err != nil || a.Zone() != "" || a.IsUnspecified() {
				p.fail(n, sect, spec.name, ErrUnsupported, "only DNS server IP addresses are supported; search domains are rejected")
				continue
			}
			p.iface.DNS = append(p.iface.DNS, a)
		}
	case "MTU":
		mtu, err := strconv.Atoi(value)
		if err != nil || mtu < minMTU || mtu > maxMTU {
			p.fail(n, sect, spec.name, ErrInvalid, fmt.Sprintf("must be an integer from %d to %d", minMTU, maxMTU))
			return
		}
		p.iface.MTU = mtu
		p.mtuLine = n
	}
}

func (p *parser) peerKey(n int, spec keySpec, value string) {
	ps := p.peers[len(p.peers)-1]
	if !p.once(n, ps.seen, spec) {
		return
	}
	sect := p.sectionName()
	switch spec.name {
	case "PublicKey":
		k, err := ParseKey(value)
		if err != nil {
			p.fail(n, sect, spec.name, ErrInvalid, err.Error())
			return
		}
		ps.peer.PublicKey, ps.hasPubKey = k, true
	case "PresharedKey":
		k, err := ParseKey(value)
		if err != nil {
			p.fail(n, sect, spec.name, ErrInvalid, err.Error())
			return
		}
		ps.peer.PresharedKey = &k
	case "Endpoint":
		ep, reason := parseEndpoint(value)
		if reason != "" {
			p.fail(n, sect, spec.name, ErrInvalid, reason)
			return
		}
		ps.peer.Endpoint = ep
	case "AllowedIPs":
		for _, item := range p.items(n, spec.name, value) {
			pfx, ok := parsePrefix(item)
			if !ok {
				p.fail(n, sect, spec.name, ErrInvalid, "must be an IP address or CIDR")
				continue
			}
			// wg silently moves a repeated prefix to the last peer; refuse instead.
			if p.allowedIPs[pfx.Masked()] {
				p.fail(n, sect, spec.name, ErrDuplicate, "prefix already routed to a peer")
				continue
			}
			p.allowedIPs[pfx.Masked()] = true
			ps.peer.AllowedIPs = append(ps.peer.AllowedIPs, pfx)
		}
	case "PersistentKeepalive":
		if strings.EqualFold(value, "off") {
			return
		}
		ka, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			p.fail(n, sect, spec.name, ErrInvalid, "must be off or an integer from 0 to 65535")
			return
		}
		ps.peer.PersistentKeepalive = uint16(ka)
	}
}

func (p *parser) finish() {
	if p.ifLine == 0 {
		p.fail(0, "Interface", "", ErrMissing, "[Interface] section is required")
	} else {
		if !p.ifSeen["PrivateKey"] {
			p.fail(p.ifLine, "Interface", "PrivateKey", ErrMissing, "")
		}
		if !p.ifSeen["Address"] {
			p.fail(p.ifLine, "Interface", "Address", ErrMissing, "")
		}
		if p.iface.MTU != 0 && p.iface.MTU < minIPv6MTU {
			for _, a := range p.iface.Addresses {
				if a.Addr().Is6() && !a.Addr().Is4In6() {
					p.fail(p.mtuLine, "Interface", "MTU", ErrInvalid, "IPv6 addresses require MTU of at least 1280")
					break
				}
			}
		}
	}
	if len(p.peers) == 0 {
		p.fail(0, "Peer", "", ErrMissing, "at least one [Peer] section is required")
	}
	keys := map[Key]bool{}
	for i, ps := range p.peers {
		sect := "Peer " + strconv.Itoa(i+1)
		if !ps.seen["PublicKey"] {
			p.fail(ps.line, sect, "PublicKey", ErrMissing, "")
		} else if ps.hasPubKey {
			if keys[ps.peer.PublicKey] {
				p.fail(ps.line, sect, "PublicKey", ErrDuplicate, "peer public key repeated")
			}
			keys[ps.peer.PublicKey] = true
		}
		if !ps.seen["Endpoint"] {
			p.fail(ps.line, sect, "Endpoint", ErrMissing, "client peers need an endpoint")
		}
		if !ps.seen["AllowedIPs"] {
			p.fail(ps.line, sect, "AllowedIPs", ErrMissing, "")
		}
	}
}

// parsePrefix accepts a CIDR or a bare IP, which becomes a single-host prefix.
// Host bits are preserved; zones are rejected.
func parsePrefix(s string) (netip.Prefix, bool) {
	if strings.Contains(s, "/") {
		pfx, err := netip.ParsePrefix(s)
		return pfx, err == nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(a, a.BitLen()), true
}

// parseEndpoint returns a fixed reason on failure, never the value.
func parseEndpoint(s string) (Endpoint, string) {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return Endpoint{}, "must be host:port, with IPv6 literals in brackets"
	}
	portNum, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNum == 0 {
		return Endpoint{}, "port must be an integer from 1 to 65535"
	}
	if a, err := netip.ParseAddr(host); err == nil {
		switch {
		case a.Zone() != "":
			return Endpoint{}, "IPv6 zones are not supported"
		case a.IsUnspecified():
			return Endpoint{}, "unspecified address is not a valid endpoint"
		case strings.HasPrefix(s, "[") != a.Is6():
			return Endpoint{}, "brackets are allowed only around IPv6 literals"
		}
		return Endpoint{Host: a.String(), Port: uint16(portNum)}, ""
	}
	if strings.HasPrefix(s, "[") || !validHostname(host) {
		return Endpoint{}, "host must be an IP literal or a DNS name"
	}
	return Endpoint{Host: host, Port: uint16(portNum)}, ""
}

func validHostname(h string) bool {
	if len(h) == 0 || len(h) > 253 {
		return false
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	// An all-numeric last label is a malformed IPv4 address, not a name.
	last := labels[len(labels)-1]
	return strings.Trim(last, "0123456789") != ""
}
