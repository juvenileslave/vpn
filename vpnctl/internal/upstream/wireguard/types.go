package wireguard

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

// KeyLen is the length of a Curve25519 key or a preshared key in bytes.
const KeyLen = 32

const redacted = "[redacted]"

// Key is a WireGuard key. Formatting and text marshalling are redacted so that
// accidental logging does not expose it; use Base64 to obtain the value.
type Key [KeyLen]byte

// ParseKey accepts the canonical wg(8) encoding: 44 characters of padded
// standard base64 decoding to exactly 32 bytes.
func ParseKey(s string) (Key, error) {
	var k Key
	if len(s) != base64.StdEncoding.EncodedLen(KeyLen) {
		return k, errors.New("key must be 44 base64 characters")
	}
	buf := make([]byte, base64.StdEncoding.DecodedLen(len(s)))
	n, err := base64.StdEncoding.Strict().Decode(buf, []byte(s))
	if err != nil || n != KeyLen {
		return Key{}, errors.New("key is not canonical base64 of 32 bytes")
	}
	copy(k[:], buf)
	return k, nil
}

// Base64 returns the canonical encoding of the key. The result is secret for
// private and preshared keys.
func (k Key) Base64() string { return base64.StdEncoding.EncodeToString(k[:]) }

func (k Key) String() string               { return redacted }
func (k Key) GoString() string             { return redacted }
func (k Key) Format(f fmt.State, _ rune)   { _, _ = f.Write([]byte(redacted)) }
func (k Key) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// Endpoint is a peer address: an IP literal or a DNS name plus a UDP port.
type Endpoint struct {
	Host string // IP literal without brackets or zone, or a DNS name
	Port uint16
}

// String returns host:port, bracketing IPv6 literals.
func (e Endpoint) String() string {
	return net.JoinHostPort(e.Host, strconv.Itoa(int(e.Port)))
}

// IsIP reports whether Host is an IP literal rather than a DNS name.
func (e Endpoint) IsIP() bool {
	_, err := netip.ParseAddr(e.Host)
	return err == nil
}

// Interface is the local side of the tunnel.
type Interface struct {
	PrivateKey Key
	Addresses  []netip.Prefix // host bits preserved, e.g. 10.0.0.2/24
	DNS        []netip.Addr   // DNS server IPs; search domains are rejected
	MTU        int            // 0 when not set
}

// Peer is one remote WireGuard peer.
type Peer struct {
	PublicKey           Key
	PresharedKey        *Key // nil when not set
	Endpoint            Endpoint
	AllowedIPs          []netip.Prefix
	PersistentKeepalive uint16 // seconds; 0 means disabled
}

// Config is a validated client configuration. Values are preserved as written
// apart from normalisation of bare IPs to single-host prefixes.
type Config struct {
	Interface Interface
	Peers     []Peer
}
