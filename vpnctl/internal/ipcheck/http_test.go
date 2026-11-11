package ipcheck_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/juvenileslave/vpn/vpnctl/internal/ipcheck"
)

func runHTTP(t *testing.T, cfg ipcheck.Config, hc ipcheck.HTTPCheck) ipcheck.HTTPResult {
	t.Helper()
	cfg.HTTPChecks = []ipcheck.HTTPCheck{hc}
	r := mustCheck(t, mustNew(t, cfg), testV4)
	if len(r.HTTP) != 1 {
		t.Fatalf("HTTP results = %+v", r.HTTP)
	}
	h := r.HTTP[0]
	if (h.Status == ipcheck.HTTPMatched) != (r.Verdict == ipcheck.Clean) {
		t.Fatalf("verdict %s inconsistent with %+v", r.Verdict, h)
	}
	if h.Duration <= 0 {
		t.Errorf("duration not recorded")
	}
	return h
}

func TestHTTPChecks(t *testing.T) {
	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetHits.Add(1)
	}))
	defer target.Close()

	marker := "service-ok"
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Write([]byte("<html>" + marker + "</html>"))
		}
	})
	mux.HandleFunc("/403", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) })
	mux.HandleFunc("/451", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnavailableForLegalReasons)
	})
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/?token=s3cret", http.StatusFound)
	})
	// Marker placed at the end of a body of the given size.
	mux.HandleFunc("/big/edge", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(strings.Repeat("x", ipcheck.MaxBodyBytes-len(marker)) + marker))
	})
	mux.HandleFunc("/big/over", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(strings.Repeat("x", ipcheck.MaxBodyBytes) + marker))
	})
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tests := []struct {
		name      string
		hc        ipcheck.HTTPCheck
		status    ipcheck.HTTPStatus
		code      int
		truncated bool
		reason    string
	}{
		{name: "200", hc: ipcheck.HTTPCheck{URL: srv.URL + "/ok", ExpectStatus: []int{200}}, status: ipcheck.HTTPMatched, code: 200},
		{name: "head", hc: ipcheck.HTTPCheck{Method: "HEAD", URL: srv.URL + "/ok", ExpectStatus: []int{200}}, status: ipcheck.HTTPMatched, code: 200},
		{name: "marker", hc: ipcheck.HTTPCheck{URL: srv.URL + "/ok", ExpectStatus: []int{200}, BodyContains: marker}, status: ipcheck.HTTPMatched, code: 200},
		{name: "marker missing", hc: ipcheck.HTTPCheck{URL: srv.URL + "/ok", ExpectStatus: []int{200}, BodyContains: "absent"}, status: ipcheck.HTTPMismatch, code: 200, reason: "body marker not found"},
		{name: "403", hc: ipcheck.HTTPCheck{URL: srv.URL + "/403", ExpectStatus: []int{200}}, status: ipcheck.HTTPMismatch, code: 403, reason: "unexpected status 403"},
		{name: "451", hc: ipcheck.HTTPCheck{URL: srv.URL + "/451", ExpectStatus: []int{200, 204}}, status: ipcheck.HTTPMismatch, code: 451, reason: "unexpected status 451"},
		{name: "403 expected", hc: ipcheck.HTTPCheck{URL: srv.URL + "/403", ExpectStatus: []int{403}}, status: ipcheck.HTTPMatched, code: 403},
		{name: "redirect refused", hc: ipcheck.HTTPCheck{URL: srv.URL + "/redirect", ExpectStatus: []int{200}}, status: ipcheck.HTTPMismatch, code: 302, reason: "redirect not followed (status 302)"},
		{name: "redirect expected", hc: ipcheck.HTTPCheck{URL: srv.URL + "/redirect", ExpectStatus: []int{302}}, status: ipcheck.HTTPMatched, code: 302},
		{name: "marker at limit", hc: ipcheck.HTTPCheck{URL: srv.URL + "/big/edge", ExpectStatus: []int{200}, BodyContains: marker}, status: ipcheck.HTTPMatched, code: 200},
		{name: "marker beyond limit", hc: ipcheck.HTTPCheck{URL: srv.URL + "/big/over", ExpectStatus: []int{200}, BodyContains: marker}, status: ipcheck.HTTPMismatch, code: 200, truncated: true, reason: "body marker not found in first 65536 bytes"},
		{name: "timeout", hc: ipcheck.HTTPCheck{URL: srv.URL + "/slow?token=s3cret", ExpectStatus: []int{200}}, status: ipcheck.HTTPError, reason: "timeout"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.hc.Name = "svc"
			h := runHTTP(t, ipcheck.Config{Timeout: 200 * time.Millisecond}, tt.hc)
			if h.Name != "svc" || h.Status != tt.status || h.StatusCode != tt.code || h.Truncated != tt.truncated || h.Reason != tt.reason {
				t.Fatalf("result = %+v", h)
			}
		})
	}
	if n := targetHits.Load(); n != 0 {
		t.Fatalf("redirect target was requested %d times", n)
	}
}

func TestHTTPErrorsAreSanitized(t *testing.T) {
	closed := httptest.NewServer(http.NotFoundHandler())
	url := closed.URL + "/path?token=s3cret"
	closed.Close()

	h := runHTTP(t, ipcheck.Config{Timeout: time.Second}, ipcheck.HTTPCheck{Name: "svc", URL: url, ExpectStatus: []int{200}})
	if h.Status != ipcheck.HTTPError || h.Reason != "connection refused" {
		t.Fatalf("result = %+v", h)
	}

	tlsSrv := httptest.NewTLSServer(http.NotFoundHandler())
	defer tlsSrv.Close()
	h = runHTTP(t, ipcheck.Config{Timeout: time.Second}, ipcheck.HTTPCheck{Name: "svc", URL: tlsSrv.URL + "/?token=s3cret", ExpectStatus: []int{200}})
	if h.Status != ipcheck.HTTPError || h.Reason != "tls certificate verification failed" {
		t.Fatalf("result = %+v", h)
	}
	for _, s := range []string{"s3cret", "127.0.0.1", "path"} {
		if strings.Contains(h.Reason, s) {
			t.Fatalf("reason %q leaks %q", h.Reason, s)
		}
	}
}

type countingDialer struct {
	calls atomic.Int32
	d     net.Dialer
}

func (c *countingDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c.calls.Add(1)
	return c.d.DialContext(ctx, network, addr)
}

func TestInjectedDialerAndClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "c", Value: "v"})
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	defer srv.Close()
	hc := ipcheck.HTTPCheck{Name: "svc", URL: srv.URL, ExpectStatus: []int{302}}

	dialer := &countingDialer{}
	if h := runHTTP(t, ipcheck.Config{Dialer: dialer}, hc); h.Status != ipcheck.HTTPMatched {
		t.Fatalf("dialer result = %+v", h)
	}
	if dialer.calls.Load() == 0 {
		t.Fatal("injected dialer was not used")
	}

	// A caller client that follows redirects must not be mutated or followed.
	client := srv.Client()
	if h := runHTTP(t, ipcheck.Config{HTTPClient: client}, hc); h.Status != ipcheck.HTTPMatched {
		t.Fatalf("client result = %+v", h)
	}
	if client.CheckRedirect != nil {
		t.Fatal("caller's client was mutated")
	}
}

func TestNewMakesNoNetworkCalls(t *testing.T) {
	dialer := &countingDialer{}
	res := &fakeResolver{}
	_, err := ipcheck.New(ipcheck.Config{
		Resolver:   res,
		Dialer:     dialer,
		DNSBLs:     []ipcheck.DNSBL{{Name: "a", Zone: zoneA}},
		HTTPChecks: []ipcheck.HTTPCheck{{Name: "svc", URL: "https://svc.example/", ExpectStatus: []int{200}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if dialer.calls.Load() != 0 || len(res.Queries()) != 0 {
		t.Fatal("New performed network access")
	}
}
