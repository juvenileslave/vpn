package ipcheck

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// DNSBLStatus is the outcome of one DNSBL lookup.
type DNSBLStatus string

const (
	DNSBLNotListed DNSBLStatus = "not_listed"
	DNSBLListed    DNSBLStatus = "listed"
	DNSBLUnknown   DNSBLStatus = "unknown"
)

// DNSBLResult is the outcome for one zone.
type DNSBLResult struct {
	Name   string
	Status DNSBLStatus
	// Codes are the 127.0.0.0/8 answers, including provider error codes.
	// Their meaning is zone-specific and not interpreted here.
	Codes    []netip.Addr
	Reason   string
	Duration time.Duration
}

var (
	listingPrefix = netip.MustParsePrefix("127.0.0.0/8")
	// Many providers use 127.255.255.0/24 for "query refused", "rate
	// limited" or "bad key"; such answers say nothing about the address.
	errorPrefix = netip.MustParsePrefix("127.255.255.0/24")
)

// QueryName returns the DNSBL query name for addr in zone, without a
// trailing dot: reversed octets for IPv4, reversed nibbles for IPv6.
func QueryName(addr netip.Addr, zone string) string {
	addr = addr.Unmap()
	var b strings.Builder
	const hex = "0123456789abcdef"
	if addr.Is4() {
		a := addr.As4()
		for i := 3; i >= 0; i-- {
			b.WriteString(strconv.Itoa(int(a[i])))
			b.WriteByte('.')
		}
	} else {
		a := addr.As16()
		for i := 15; i >= 0; i-- {
			b.WriteByte(hex[a[i]&0x0f])
			b.WriteByte('.')
			b.WriteByte(hex[a[i]>>4])
			b.WriteByte('.')
		}
	}
	b.WriteString(zone)
	return b.String()
}

func (c *Checker) lookup(ctx context.Context, addr netip.Addr, d DNSBL) DNSBLResult {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	start := c.now()
	// Trailing dot: an absolute name must not pick up resolver search domains.
	answers, err := c.resolver.LookupNetIP(ctx, "ip4", QueryName(addr, d.Zone)+".")
	res := classifyAnswers(answers, err)
	res.Name = d.Name
	res.Duration = c.now().Sub(start)
	return res
}

func classifyAnswers(answers []netip.Addr, err error) DNSBLResult {
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return DNSBLResult{Status: DNSBLNotListed}
		}
		return DNSBLResult{Status: DNSBLUnknown, Reason: lookupReason(err)}
	}
	if len(answers) == 0 {
		return DNSBLResult{Status: DNSBLNotListed}
	}

	var res DNSBLResult
	providerError, unexpected := false, false
	for _, a := range answers {
		a = a.Unmap()
		switch {
		case errorPrefix.Contains(a):
			providerError = true
		case listingPrefix.Contains(a):
		default:
			unexpected = true
			continue
		}
		res.Codes = append(res.Codes, a)
	}
	switch {
	case providerError:
		res.Status, res.Reason = DNSBLUnknown, "provider returned error code "+joinCodes(res.Codes)
	case unexpected:
		// Typically a hijacking or wildcarding resolver, not a listing.
		res.Status, res.Reason = DNSBLUnknown, "answer outside 127.0.0.0/8"
	default:
		res.Status, res.Reason = DNSBLListed, "listed with code "+joinCodes(res.Codes)
	}
	return res
}

func joinCodes(codes []netip.Addr) string {
	s := make([]string, len(codes))
	for i, c := range codes {
		s[i] = c.String()
	}
	return strings.Join(s, ",")
}

// lookupReason maps a resolver error to a fixed phrase; the original error
// would carry the query name and therefore the zone.
func lookupReason(err error) string {
	var dnsErr *net.DNSError
	isDNS := errors.As(err, &dnsErr)
	switch {
	case errors.Is(err, context.DeadlineExceeded), isDNS && dnsErr.IsTimeout:
		return "dns timeout"
	case errors.Is(err, context.Canceled):
		return "dns lookup canceled"
	case isDNS && dnsErr.IsTemporary:
		return "dns temporary failure"
	default:
		return "dns lookup failed"
	}
}
