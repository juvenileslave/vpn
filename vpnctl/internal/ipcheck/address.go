package ipcheck

import "net/netip"

var sharedPrefix = netip.MustParsePrefix("100.64.0.0/10")

// AddressInfo describes the type of an address.
type AddressInfo struct {
	// Version is 4 or 6.
	Version       int
	GlobalUnicast bool
	Private       bool
	// Shared is the RFC 6598 carrier-grade NAT range 100.64.0.0/10.
	Shared      bool
	Loopback    bool
	LinkLocal   bool
	Multicast   bool
	Unspecified bool
}

// Public reports whether the address is global unicast and neither private
// nor shared. Documentation ranges count as public: netip does not exclude
// them, and this package does not maintain a special-purpose registry.
func (i AddressInfo) Public() bool {
	return i.GlobalUnicast && !i.Private && !i.Shared
}

// Classify reports the type of addr after unmapping IPv4-mapped IPv6.
func Classify(addr netip.Addr) AddressInfo {
	addr = addr.Unmap()
	info := AddressInfo{
		Version:       6,
		GlobalUnicast: addr.IsGlobalUnicast(),
		Private:       addr.IsPrivate(),
		Shared:        sharedPrefix.Contains(addr),
		Loopback:      addr.IsLoopback(),
		LinkLocal:     addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast(),
		Multicast:     addr.IsMulticast(),
		Unspecified:   addr.IsUnspecified(),
	}
	if addr.Is4() {
		info.Version = 4
	}
	return info
}
