// Package ipcheck classifies an exit IP address: DNSBL listings, address type
// and reachability of caller-supplied HTTP endpoints.
//
// All network access goes through the injected resolver, HTTP client or
// dialer, and only happens inside Checker.Check. Results never retain DNSBL
// zones (which may embed provider keys), request URLs or response bodies.
package ipcheck

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultTimeout bounds each DNSBL lookup and each HTTP check when
	// Config.Timeout is zero.
	DefaultTimeout = 5 * time.Second
	// MaxBodyBytes is the largest response prefix searched for a body marker.
	MaxBodyBytes = 64 << 10
)

// Verdict is the aggregate classification of an address.
type Verdict string

const (
	// Clean: the address is public, no DNSBL lists it and every HTTP check
	// matched its expectation.
	Clean Verdict = "clean"
	// Listed: at least one DNSBL returned a listing code. Takes precedence
	// over Unknown.
	Listed Verdict = "listed"
	// Unknown: no listing, but some observation failed, timed out, was
	// skipped or did not match.
	Unknown Verdict = "unknown"
)

// Resolver resolves A records. *net.Resolver satisfies it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Dialer opens connections for HTTP checks, e.g. a *net.Dialer with
// LocalAddr set to the exit's source address.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// DNSBL is one blocklist zone. Name is reported in results; Zone is not,
// because some providers embed an access key in it.
type DNSBL struct {
	Name string
	Zone string
}

// HTTPCheck is one reachability expectation.
type HTTPCheck struct {
	Name string
	// Method is GET (default) or HEAD.
	Method string
	// URL must be http or https without userinfo. It is never reported.
	URL string
	// ExpectStatus lists acceptable status codes; at least one is required.
	// Redirects are not followed, so a 3xx matches only if listed here.
	ExpectStatus []int
	// BodyContains, if set, must occur in the first MaxBodyBytes of the body.
	BodyContains string
}

// Config configures a Checker. Resolver is required when DNSBLs are set.
// HTTPClient and Dialer are mutually exclusive; with neither, a direct
// (proxy-less) transport using a zero net.Dialer is built.
type Config struct {
	Resolver   Resolver
	HTTPClient *http.Client
	Dialer     Dialer
	// Now defaults to time.Now; used for timestamps and durations only.
	Now        func() time.Time
	Timeout    time.Duration
	DNSBLs     []DNSBL
	HTTPChecks []HTTPCheck
}

// Checker runs the configured checks. It is safe for concurrent use.
type Checker struct {
	resolver Resolver
	client   *http.Client
	now      func() time.Time
	timeout  time.Duration
	dnsbls   []DNSBL
	checks   []HTTPCheck
}

// Report is the outcome of one Check.
type Report struct {
	Address netip.Addr
	Info    AddressInfo
	Verdict Verdict
	// Reasons explains every item that prevented a clean verdict.
	Reasons   []string
	DNSBL     []DNSBLResult
	HTTP      []HTTPResult
	CheckedAt time.Time
	Duration  time.Duration
}

// New validates cfg. It performs no network access.
func New(cfg Config) (*Checker, error) {
	var errs []error
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}

	if len(cfg.DNSBLs) == 0 && len(cfg.HTTPChecks) == 0 {
		fail("at least one DNSBL or HTTP check is required")
	}
	if len(cfg.DNSBLs) > 0 && cfg.Resolver == nil {
		fail("resolver is required when DNSBLs are configured")
	}
	if cfg.HTTPClient != nil && cfg.Dialer != nil {
		fail("http client and dialer are mutually exclusive")
	}
	if cfg.Timeout < 0 {
		fail("timeout must not be negative")
	}

	c := &Checker{resolver: cfg.Resolver, now: cfg.Now, timeout: cfg.Timeout}
	if c.now == nil {
		c.now = time.Now
	}
	if c.timeout == 0 {
		c.timeout = DefaultTimeout
	}

	names := map[string]bool{}
	for i, d := range cfg.DNSBLs {
		zone := strings.ToLower(strings.TrimSuffix(d.Zone, "."))
		switch {
		case d.Name == "":
			fail("dnsbls[%d]: name is required", i)
		case names["dnsbl:"+d.Name]:
			fail("dnsbls[%d]: duplicate name %q", i, d.Name)
		}
		names["dnsbl:"+d.Name] = true
		if !validZone(zone) {
			fail("dnsbls[%d]: zone is not a valid DNS name", i)
		}
		c.dnsbls = append(c.dnsbls, DNSBL{Name: d.Name, Zone: zone})
	}

	for i, hc := range cfg.HTTPChecks {
		switch {
		case hc.Name == "":
			fail("http_checks[%d]: name is required", i)
		case names["http:"+hc.Name]:
			fail("http_checks[%d]: duplicate name %q", i, hc.Name)
		}
		names["http:"+hc.Name] = true
		if hc.Method == "" {
			hc.Method = http.MethodGet
		}
		if hc.Method != http.MethodGet && hc.Method != http.MethodHead {
			fail("http_checks[%d]: method must be GET or HEAD", i)
		}
		// The URL is deliberately not echoed: its query may carry a token.
		u, err := url.Parse(hc.URL)
		switch {
		case err != nil:
			fail("http_checks[%d]: url is invalid", i)
		case u.Scheme != "http" && u.Scheme != "https":
			fail("http_checks[%d]: url scheme must be http or https", i)
		case u.Host == "":
			fail("http_checks[%d]: url host is required", i)
		case u.User != nil:
			fail("http_checks[%d]: url must not contain userinfo", i)
		}
		if len(hc.ExpectStatus) == 0 {
			fail("http_checks[%d]: expect_status is required", i)
		}
		for _, s := range hc.ExpectStatus {
			if s < 100 || s > 599 {
				fail("http_checks[%d]: status %d is out of range", i, s)
			}
		}
		if hc.BodyContains != "" && hc.Method == http.MethodHead {
			fail("http_checks[%d]: body marker requires GET", i)
		}
		if len(hc.BodyContains) > MaxBodyBytes {
			fail("http_checks[%d]: body marker exceeds %d bytes", i, MaxBodyBytes)
		}
		hc.ExpectStatus = append([]int(nil), hc.ExpectStatus...)
		c.checks = append(c.checks, hc)
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("ipcheck: invalid config: %w", errors.Join(errs...))
	}
	if len(c.checks) > 0 {
		c.client = newClient(cfg.HTTPClient, cfg.Dialer)
	}
	return c, nil
}

// newClient copies base (never mutating the caller's client) or builds a
// direct transport, then disables redirects and cookies.
func newClient(base *http.Client, dialer Dialer) *http.Client {
	var client http.Client
	if base != nil {
		client = *base
	} else {
		if dialer == nil {
			dialer = &net.Dialer{}
		}
		client.Transport = &http.Transport{
			// Proxy is nil on purpose: environment proxies would hide the exit.
			DialContext:         dialer.DialContext,
			ForceAttemptHTTP2:   true,
			DisableKeepAlives:   true,
			TLSHandshakeTimeout: DefaultTimeout,
		}
	}
	client.Jar = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &client
}

// ParseAddress parses a literal IPv4 or IPv6 address. Zones, prefixes and
// host names are rejected; IPv4-mapped IPv6 addresses are unmapped.
func ParseAddress(s string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, errors.New("ipcheck: not an IP address")
	}
	if addr.Zone() != "" {
		return netip.Addr{}, errors.New("ipcheck: zoned addresses are not supported")
	}
	return addr.Unmap(), nil
}

// Check classifies address. The error is non-nil only for invalid input, in
// which case no lookup or request is made; observation failures are reported
// in the Report and yield an Unknown verdict.
func (c *Checker) Check(ctx context.Context, address string) (Report, error) {
	addr, err := ParseAddress(address)
	if err != nil {
		return Report{}, err
	}
	start := c.now()
	r := Report{
		Address:   addr,
		Info:      Classify(addr),
		CheckedAt: start,
		DNSBL:     make([]DNSBLResult, len(c.dnsbls)),
		HTTP:      make([]HTTPResult, len(c.checks)),
	}

	var wg sync.WaitGroup
	for i, d := range c.dnsbls {
		if !r.Info.Public() {
			r.DNSBL[i] = DNSBLResult{Name: d.Name, Status: DNSBLUnknown, Reason: "skipped: address is not public"}
			continue
		}
		wg.Go(func() { r.DNSBL[i] = c.lookup(ctx, addr, d) })
	}
	for i, hc := range c.checks {
		wg.Go(func() { r.HTTP[i] = c.probe(ctx, hc) })
	}
	wg.Wait()

	r.Duration = c.now().Sub(start)
	r.Verdict, r.Reasons = aggregate(r)
	return r, nil
}

func aggregate(r Report) (Verdict, []string) {
	var reasons []string
	listed, unknown := false, false
	if !r.Info.Public() {
		unknown = true
		reasons = append(reasons, "address: not a public unicast address")
	}
	for _, d := range r.DNSBL {
		switch d.Status {
		case DNSBLNotListed:
		case DNSBLListed:
			listed = true
			reasons = append(reasons, "dnsbl "+d.Name+": "+d.Reason)
		default:
			unknown = true
			reasons = append(reasons, "dnsbl "+d.Name+": "+d.Reason)
		}
	}
	for _, h := range r.HTTP {
		if h.Status != HTTPMatched {
			unknown = true
			reasons = append(reasons, "http "+h.Name+": "+h.Reason)
		}
	}
	switch {
	case listed:
		return Listed, reasons
	case unknown:
		return Unknown, reasons
	default:
		return Clean, reasons
	}
}

func validZone(zone string) bool {
	// Leave room for the 64-byte IPv6 nibble prefix within 253 bytes.
	if zone == "" || len(zone) > 253-64 {
		return false
	}
	for _, label := range strings.Split(zone, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' && ch != '_' {
				return false
			}
		}
	}
	return true
}
