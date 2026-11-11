package ipcheck_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/juvenileslave/vpn/vpnctl/internal/ipcheck"
)

// Documentation-range addresses only (RFC 5737, RFC 3849).
const (
	testV4 = "192.0.2.10"
	testV6 = "2001:db8::1"
	zoneA  = "bl-a.example"
	zoneB  = "bl-b.example"
)

type fakeAnswer struct {
	addrs []netip.Addr
	err   error
	block bool
}

// fakeResolver answers NXDOMAIN for any name not in answers.
type fakeResolver struct {
	mu      sync.Mutex
	answers map[string]fakeAnswer
	queries []string
}

func (f *fakeResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	f.queries = append(f.queries, network+" "+host)
	a, ok := f.answers[host]
	f.mu.Unlock()
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	if a.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return a.addrs, a.err
}

func (f *fakeResolver) Queries() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.queries...)
}

// fakeClock advances one millisecond per reading.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(time.Millisecond)
	return c.t
}

func newClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func addrs(s ...string) []netip.Addr {
	out := make([]netip.Addr, len(s))
	for i, v := range s {
		out[i] = netip.MustParseAddr(v)
	}
	return out
}

func fqdn(ip, zone string) string {
	return ipcheck.QueryName(netip.MustParseAddr(ip), zone) + "."
}

func mustNew(t *testing.T, cfg ipcheck.Config) *ipcheck.Checker {
	t.Helper()
	if cfg.Now == nil {
		cfg.Now = newClock().Now
	}
	c, err := ipcheck.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func mustCheck(t *testing.T, c *ipcheck.Checker, ip string) ipcheck.Report {
	t.Helper()
	r, err := c.Check(context.Background(), ip)
	if err != nil {
		t.Fatalf("Check(%q): %v", ip, err)
	}
	return r
}

func TestQueryName(t *testing.T) {
	tests := []struct{ ip, want string }{
		{testV4, "10.2.0.192." + zoneA},
		{"::ffff:192.0.2.10", "10.2.0.192." + zoneA},
		{testV6, "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2." + zoneA},
		{"2001:db8:abcd:12::f0", "0.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.1.0.0.d.c.b.a.8.b.d.0.1.0.0.2." + zoneA},
	}
	for _, tt := range tests {
		if got := ipcheck.QueryName(netip.MustParseAddr(tt.ip), zoneA); got != tt.want {
			t.Errorf("QueryName(%s) = %q, want %q", tt.ip, got, tt.want)
		}
	}
}

func TestDNSBLClassification(t *testing.T) {
	tests := []struct {
		name      string
		answer    *fakeAnswer // nil: NXDOMAIN
		status    ipcheck.DNSBLStatus
		verdict   ipcheck.Verdict
		codes     int
		reasonHas string
	}{
		{name: "nxdomain", status: ipcheck.DNSBLNotListed, verdict: ipcheck.Clean},
		{name: "empty answer", answer: &fakeAnswer{}, status: ipcheck.DNSBLNotListed, verdict: ipcheck.Clean},
		{name: "listed", answer: &fakeAnswer{addrs: addrs("127.0.0.2")}, status: ipcheck.DNSBLListed, verdict: ipcheck.Listed, codes: 1, reasonHas: "127.0.0.2"},
		{name: "listed multiple codes", answer: &fakeAnswer{addrs: addrs("127.0.0.2", "127.0.0.4")}, status: ipcheck.DNSBLListed, verdict: ipcheck.Listed, codes: 2, reasonHas: "127.0.0.2,127.0.0.4"},
		{name: "provider error code", answer: &fakeAnswer{addrs: addrs("127.255.255.254")}, status: ipcheck.DNSBLUnknown, verdict: ipcheck.Unknown, codes: 1, reasonHas: "error code"},
		{name: "error code with listing", answer: &fakeAnswer{addrs: addrs("127.0.0.2", "127.255.255.252")}, status: ipcheck.DNSBLUnknown, verdict: ipcheck.Unknown, codes: 2, reasonHas: "error code"},
		{name: "answer outside loopback", answer: &fakeAnswer{addrs: addrs("198.51.100.7")}, status: ipcheck.DNSBLUnknown, verdict: ipcheck.Unknown, reasonHas: "outside"},
		{name: "resolver timeout", answer: &fakeAnswer{err: &net.DNSError{Err: "i/o timeout", IsTimeout: true}}, status: ipcheck.DNSBLUnknown, verdict: ipcheck.Unknown, reasonHas: "dns timeout"},
		{name: "context deadline", answer: &fakeAnswer{block: true}, status: ipcheck.DNSBLUnknown, verdict: ipcheck.Unknown, reasonHas: "dns timeout"},
		{name: "servfail", answer: &fakeAnswer{err: &net.DNSError{Err: "server misbehaving", IsTemporary: true}}, status: ipcheck.DNSBLUnknown, verdict: ipcheck.Unknown, reasonHas: "temporary"},
		{name: "other error", answer: &fakeAnswer{err: errors.New("boom " + zoneA)}, status: ipcheck.DNSBLUnknown, verdict: ipcheck.Unknown, reasonHas: "lookup failed"},
	}
	for _, tt := range tests {
		for _, ip := range []string{testV4, testV6} {
			t.Run(tt.name+"/"+ip, func(t *testing.T) {
				res := &fakeResolver{answers: map[string]fakeAnswer{}}
				if tt.answer != nil {
					res.answers[fqdn(ip, zoneA)] = *tt.answer
				}
				c := mustNew(t, ipcheck.Config{
					Resolver: res,
					Timeout:  20 * time.Millisecond,
					DNSBLs:   []ipcheck.DNSBL{{Name: "a", Zone: zoneA}},
				})
				r := mustCheck(t, c, ip)

				if q := res.Queries(); len(q) != 1 || q[0] != "ip4 "+fqdn(ip, zoneA) {
					t.Fatalf("queries = %v", q)
				}
				d := r.DNSBL[0]
				if d.Name != "a" || d.Status != tt.status || len(d.Codes) != tt.codes {
					t.Fatalf("result = %+v", d)
				}
				if r.Verdict != tt.verdict {
					t.Fatalf("verdict = %s, want %s (%v)", r.Verdict, tt.verdict, r.Reasons)
				}
				if !strings.Contains(d.Reason, tt.reasonHas) {
					t.Errorf("reason %q lacks %q", d.Reason, tt.reasonHas)
				}
				if strings.Contains(d.Reason, zoneA) || strings.Contains(strings.Join(r.Reasons, ";"), zoneA) {
					t.Errorf("zone leaked into reasons: %v", r.Reasons)
				}
				if d.Duration <= 0 || r.Duration <= 0 {
					t.Errorf("durations not recorded: %v %v", d.Duration, r.Duration)
				}
			})
		}
	}
}

func TestAddressInfo(t *testing.T) {
	tests := []struct {
		ip      string
		version int
		public  bool
		check   func(ipcheck.AddressInfo) bool
	}{
		{testV4, 4, true, func(i ipcheck.AddressInfo) bool { return i.GlobalUnicast }},
		{testV6, 6, true, func(i ipcheck.AddressInfo) bool { return i.GlobalUnicast }},
		{"10.1.2.3", 4, false, func(i ipcheck.AddressInfo) bool { return i.Private }},
		{"fd00::1", 6, false, func(i ipcheck.AddressInfo) bool { return i.Private }},
		{"100.64.0.1", 4, false, func(i ipcheck.AddressInfo) bool { return i.Shared }},
		{"127.0.0.1", 4, false, func(i ipcheck.AddressInfo) bool { return i.Loopback }},
		{"::1", 6, false, func(i ipcheck.AddressInfo) bool { return i.Loopback }},
		{"169.254.1.1", 4, false, func(i ipcheck.AddressInfo) bool { return i.LinkLocal }},
		{"fe80::1", 6, false, func(i ipcheck.AddressInfo) bool { return i.LinkLocal }},
		{"ff02::1", 6, false, func(i ipcheck.AddressInfo) bool { return i.Multicast }},
		{"224.0.0.1", 4, false, func(i ipcheck.AddressInfo) bool { return i.Multicast }},
		{"0.0.0.0", 4, false, func(i ipcheck.AddressInfo) bool { return i.Unspecified }},
		{"::", 6, false, func(i ipcheck.AddressInfo) bool { return i.Unspecified }},
		{"::ffff:10.1.2.3", 4, false, func(i ipcheck.AddressInfo) bool { return i.Private }},
	}
	for _, tt := range tests {
		info := ipcheck.Classify(netip.MustParseAddr(tt.ip))
		if info.Version != tt.version || info.Public() != tt.public || !tt.check(info) {
			t.Errorf("Classify(%s) = %+v, public=%v", tt.ip, info, info.Public())
		}
	}
}

func TestCheckRejectsNonIPBeforeLookup(t *testing.T) {
	res := &fakeResolver{}
	c := mustNew(t, ipcheck.Config{Resolver: res, DNSBLs: []ipcheck.DNSBL{{Name: "a", Zone: zoneA}}})
	for _, in := range []string{"", "exit.example", "192.0.2.10/32", " 192.0.2.10", "fe80::1%eth0", "192.0.2.256"} {
		if _, err := c.Check(context.Background(), in); err == nil {
			t.Errorf("Check(%q) succeeded", in)
		}
	}
	if q := res.Queries(); len(q) != 0 {
		t.Fatalf("lookups made for invalid input: %v", q)
	}
}

func TestNonPublicAddressIsUnknownWithoutLookup(t *testing.T) {
	res := &fakeResolver{}
	c := mustNew(t, ipcheck.Config{Resolver: res, DNSBLs: []ipcheck.DNSBL{{Name: "a", Zone: zoneA}}})
	for _, ip := range []string{"10.0.0.1", "127.0.0.1", "fe80::1"} {
		r := mustCheck(t, c, ip)
		if r.Verdict != ipcheck.Unknown || r.DNSBL[0].Status != ipcheck.DNSBLUnknown {
			t.Errorf("%s: verdict %s, dnsbl %+v", ip, r.Verdict, r.DNSBL[0])
		}
	}
	if q := res.Queries(); len(q) != 0 {
		t.Fatalf("lookups made for non-public addresses: %v", q)
	}
}

func TestAggregation(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer ok.Close()
	blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnavailableForLegalReasons)
	}))
	defer blocked.Close()

	okCheck := ipcheck.HTTPCheck{Name: "ok", URL: ok.URL, ExpectStatus: []int{200}}
	blockedCheck := ipcheck.HTTPCheck{Name: "svc", URL: blocked.URL, ExpectStatus: []int{200}}
	listed := fakeAnswer{addrs: addrs("127.0.0.2")}
	timeout := fakeAnswer{block: true}

	tests := []struct {
		name    string
		a, b    *fakeAnswer
		checks  []ipcheck.HTTPCheck
		verdict ipcheck.Verdict
		reasons []string
	}{
		{name: "all clean", checks: []ipcheck.HTTPCheck{okCheck}, verdict: ipcheck.Clean},
		{name: "one zone times out", b: &timeout, checks: []ipcheck.HTTPCheck{okCheck}, verdict: ipcheck.Unknown, reasons: []string{"dnsbl b: dns timeout"}},
		{name: "one http mismatch", checks: []ipcheck.HTTPCheck{okCheck, blockedCheck}, verdict: ipcheck.Unknown, reasons: []string{"http svc: unexpected status 451"}},
		{name: "listed beats unknown", a: &listed, b: &timeout, checks: []ipcheck.HTTPCheck{blockedCheck}, verdict: ipcheck.Listed,
			reasons: []string{"dnsbl a: listed with code 127.0.0.2", "dnsbl b: dns timeout", "http svc: unexpected status 451"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := &fakeResolver{answers: map[string]fakeAnswer{}}
			if tt.a != nil {
				res.answers[fqdn(testV4, zoneA)] = *tt.a
			}
			if tt.b != nil {
				res.answers[fqdn(testV4, zoneB)] = *tt.b
			}
			c := mustNew(t, ipcheck.Config{
				Resolver:   res,
				Timeout:    200 * time.Millisecond,
				DNSBLs:     []ipcheck.DNSBL{{Name: "a", Zone: zoneA}, {Name: "b", Zone: zoneB}},
				HTTPChecks: tt.checks,
			})
			r := mustCheck(t, c, testV4)
			if r.Verdict != tt.verdict {
				t.Fatalf("verdict = %s, want %s (%v)", r.Verdict, tt.verdict, r.Reasons)
			}
			if strings.Join(r.Reasons, "|") != strings.Join(tt.reasons, "|") {
				t.Fatalf("reasons = %q, want %q", r.Reasons, tt.reasons)
			}
			if len(r.DNSBL) != 2 || len(r.HTTP) != len(tt.checks) {
				t.Fatalf("per-item results missing: %+v", r)
			}
		})
	}
}

func TestNewValidation(t *testing.T) {
	res := &fakeResolver{}
	good := ipcheck.HTTPCheck{Name: "g", URL: "https://svc.example/", ExpectStatus: []int{200}}
	tests := map[string]ipcheck.Config{
		"empty":            {},
		"no resolver":      {DNSBLs: []ipcheck.DNSBL{{Name: "a", Zone: zoneA}}},
		"client and dial":  {HTTPClient: &http.Client{}, Dialer: &net.Dialer{}, HTTPChecks: []ipcheck.HTTPCheck{good}},
		"negative timeout": {Timeout: -1, HTTPChecks: []ipcheck.HTTPCheck{good}},
		"bad zone":         {Resolver: res, DNSBLs: []ipcheck.DNSBL{{Name: "a", Zone: "bad zone"}}},
		"empty zone":       {Resolver: res, DNSBLs: []ipcheck.DNSBL{{Name: "a"}}},
		"dup dnsbl":        {Resolver: res, DNSBLs: []ipcheck.DNSBL{{Name: "a", Zone: zoneA}, {Name: "a", Zone: zoneB}}},
		"no check name":    {HTTPChecks: []ipcheck.HTTPCheck{{URL: good.URL, ExpectStatus: []int{200}}}},
		"dup check":        {HTTPChecks: []ipcheck.HTTPCheck{good, good}},
		"bad method":       {HTTPChecks: []ipcheck.HTTPCheck{{Name: "x", Method: "POST", URL: good.URL, ExpectStatus: []int{200}}}},
		"bad scheme":       {HTTPChecks: []ipcheck.HTTPCheck{{Name: "x", URL: "ftp://svc.example/?token=s3cret", ExpectStatus: []int{200}}}},
		"userinfo":         {HTTPChecks: []ipcheck.HTTPCheck{{Name: "x", URL: "https://u:s3cret@svc.example/", ExpectStatus: []int{200}}}},
		"no status":        {HTTPChecks: []ipcheck.HTTPCheck{{Name: "x", URL: good.URL}}},
		"status range":     {HTTPChecks: []ipcheck.HTTPCheck{{Name: "x", URL: good.URL, ExpectStatus: []int{99}}}},
		"marker with head": {HTTPChecks: []ipcheck.HTTPCheck{{Name: "x", Method: "HEAD", URL: good.URL, ExpectStatus: []int{200}, BodyContains: "m"}}},
		"marker too large": {HTTPChecks: []ipcheck.HTTPCheck{{Name: "x", URL: good.URL, ExpectStatus: []int{200}, BodyContains: strings.Repeat("m", ipcheck.MaxBodyBytes+1)}}},
	}
	for name, cfg := range tests {
		_, err := ipcheck.New(cfg)
		if err == nil {
			t.Errorf("%s: New succeeded", name)
		} else if strings.Contains(err.Error(), "s3cret") {
			t.Errorf("%s: error leaks URL: %v", name, err)
		}
	}
}
