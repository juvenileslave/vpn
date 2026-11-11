package hetzner

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Synthetic token; it only exists in this test.
const testToken = "hz-test-token-0123456789abcdef"

func newTestClient(t *testing.T, h http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	c, err := New(srv.URL+"/v1", testToken, srv.Client())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, srv
}

func requireAuth(t *testing.T, w http.ResponseWriter, r *http.Request) bool {
	t.Helper()
	if r.Method != http.MethodGet {
		t.Errorf("method = %s, want GET", r.Method)
	}
	if got := r.Header.Get("Authorization"); got != "Bearer "+testToken {
		t.Errorf("Authorization header mismatch")
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	return true
}

func serverJSON(id int, name string) string {
	return fmt.Sprintf(`{"id":%d,"name":%q,"status":"running","created":"2026-01-01T00:00:00+00:00",
		"public_net":{"ipv4":{"id":%d,"ip":"192.0.2.%d","blocked":false,"dns_ptr":"x.example.com"},
		"ipv6":{"id":%d,"ip":"2001:db8:%d::/64","blocked":false,"dns_ptr":[]},"floating_ips":[]},
		"location":{"id":1,"name":"hel1"},"labels":{"role":"exit"},"unknown_field":true}`,
		id, name, id+1000, id, id+2000, id)
}

func pageMeta(page, next int) string {
	n := "null"
	if next > 0 {
		n = strconv.Itoa(next)
	}
	return fmt.Sprintf(`"meta":{"pagination":{"page":%d,"per_page":2,"previous_page":null,"next_page":%s,"last_page":3,"total_entries":5}}`, page, n)
}

func TestListServersFollowsPagination(t *testing.T) {
	var calls atomic.Int32
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(t, w, r) {
			return
		}
		calls.Add(1)
		if r.URL.Path != "/v1/servers" {
			t.Errorf("path = %q, want /v1/servers", r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("per_page") != "50" || q.Get("label_selector") != "role=exit" {
			t.Errorf("query = %q", r.URL.RawQuery)
		}
		switch q.Get("page") {
		case "1":
			fmt.Fprintf(w, `{"servers":[%s,%s],%s}`, serverJSON(1, "a"), serverJSON(2, "b"), pageMeta(1, 2))
		case "2":
			fmt.Fprintf(w, `{"servers":[%s,%s],%s}`, serverJSON(3, "c"), serverJSON(4, "d"), pageMeta(2, 3))
		case "3":
			fmt.Fprintf(w, `{"servers":[%s],%s}`, serverJSON(5, "e"), pageMeta(3, 0))
		default:
			t.Errorf("unexpected page %q", q.Get("page"))
		}
	})
	got, err := c.ListServers(context.Background(), ListOptions{LabelSelector: "role=exit"})
	if err != nil {
		t.Fatalf("ListServers: %v", err)
	}
	if len(got) != 5 || calls.Load() != 3 {
		t.Fatalf("got %d servers in %d calls, want 5 in 3", len(got), calls.Load())
	}
	s := got[0]
	if s.ID != 1 || s.Name != "a" || s.Status != "running" || s.Location.Name != "hel1" || s.Labels["role"] != "exit" {
		t.Errorf("server = %+v", s)
	}
	if s.PublicNet.IPv4 == nil || s.PublicNet.IPv4.IP != "192.0.2.1" || s.PublicNet.IPv4.ID != 1001 {
		t.Errorf("ipv4 = %+v", s.PublicNet.IPv4)
	}
	if s.PublicNet.IPv6 == nil || s.PublicNet.IPv6.IP != "2001:db8:1::/64" {
		t.Errorf("ipv6 = %+v", s.PublicNet.IPv6)
	}
	if got[4].Name != "e" {
		t.Errorf("last server = %+v", got[4])
	}
}

func TestListEmptyPage(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"primary_ips":[],%s}`, pageMeta(1, 0))
	})
	got, err := c.ListPrimaryIPs(context.Background(), ListOptions{})
	if err != nil {
		t.Fatalf("ListPrimaryIPs: %v", err)
	}
	if got == nil || len(got) != 0 {
		t.Fatalf("got %#v, want empty non-nil slice", got)
	}
}

func TestListPrimaryIPs(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(t, w, r) {
			return
		}
		if r.URL.Path != "/v1/primary_ips" || r.URL.Query().Get("name") != "exit-v4" {
			t.Errorf("request = %s", r.URL)
		}
		fmt.Fprintf(w, `{"primary_ips":[
			{"id":7,"name":"exit-v4","ip":"198.51.100.7","type":"ipv4","assignee_type":"server","assignee_id":42,
			 "auto_delete":false,"blocked":false,"location":{"name":"hel1"},"labels":{}},
			{"id":8,"name":"spare","ip":"2001:db8:8::/64","type":"ipv6","assignee_type":"server","assignee_id":null,
			 "auto_delete":true,"blocked":false,"location":{"name":"hel1"},"labels":{"k":"v"}}],%s}`, pageMeta(1, 0))
	})
	got, err := c.ListPrimaryIPs(context.Background(), ListOptions{Name: "exit-v4"})
	if err != nil {
		t.Fatalf("ListPrimaryIPs: %v", err)
	}
	if len(got) != 2 || got[0].AssigneeID == nil || *got[0].AssigneeID != 42 || got[1].AssigneeID != nil {
		t.Fatalf("got %+v", got)
	}
	if got[1].Type != "ipv6" || got[1].Labels["k"] != "v" || !got[1].AutoDelete {
		t.Errorf("got[1] = %+v", got[1])
	}
}

func TestServerAndPrimaryIPByID(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(t, w, r) {
			return
		}
		switch r.URL.Path {
		case "/v1/servers/42":
			fmt.Fprintf(w, `{"server":%s}`, serverJSON(42, "exit"))
		case "/v1/primary_ips/7":
			fmt.Fprint(w, `{"primary_ip":{"id":7,"name":"p","ip":"198.51.100.7","type":"ipv4","assignee_type":"server","assignee_id":42}}`)
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	s, err := c.Server(context.Background(), 42)
	if err != nil || s.ID != 42 || s.Name != "exit" {
		t.Fatalf("Server = %+v, %v", s, err)
	}
	ip, err := c.PrimaryIP(context.Background(), 7)
	if err != nil || ip.ID != 7 || ip.IP != "198.51.100.7" {
		t.Fatalf("PrimaryIP = %+v, %v", ip, err)
	}
	for _, id := range []int64{0, -1, 1 << 53} {
		if _, err := c.Server(context.Background(), id); err == nil {
			t.Errorf("Server(%d) succeeded", id)
		}
	}
}

func TestBasePathPreserved(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/proxy/hcloud/v1/servers/1" {
			t.Errorf("path = %q", r.URL.Path)
		}
		fmt.Fprintf(w, `{"server":%s}`, serverJSON(1, "a"))
	}))
	defer srv.Close()
	c, err := New(srv.URL+"/proxy/hcloud/v1/", testToken, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Server(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
}

func TestStatusErrors(t *testing.T) {
	cases := []struct {
		status int
		want   error
	}{
		{401, ErrUnauthorized},
		{403, ErrForbidden},
		{404, ErrNotFound},
		{429, ErrRateLimited},
		{500, ErrServer},
		{503, ErrServer},
	}
	for _, tc := range cases {
		t.Run(strconv.Itoa(tc.status), func(t *testing.T) {
			c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				// Provider message echoes the token: it must be redacted.
				fmt.Fprintf(w, `{"error":{"code":"some_code","message":"bad %s\nline"}}`, testToken)
			})
			_, err := c.Server(context.Background(), 1)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != tc.status || apiErr.Code != "some_code" {
				t.Fatalf("APIError = %+v", apiErr)
			}
			if strings.Contains(err.Error(), testToken) || strings.Contains(err.Error(), "\n") {
				t.Fatalf("error leaks token or control characters: %q", err)
			}
			for _, other := range []error{ErrUnauthorized, ErrForbidden, ErrNotFound, ErrRateLimited, ErrServer} {
				if other != tc.want && errors.Is(err, other) {
					t.Errorf("err also matches %v", other)
				}
			}
		})
	}
}

func TestErrorWithNonJSONBody(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprint(w, "<html>secret-ish proxy page</html>")
	})
	_, err := c.ListServers(context.Background(), ListOptions{})
	if !errors.Is(err, ErrServer) || strings.Contains(err.Error(), "proxy page") {
		t.Fatalf("err = %v", err)
	}
}

func TestMalformedResponses(t *testing.T) {
	ok := serverJSON(1, "a")
	cases := map[string]string{
		"invalid json":         `{"servers":[`,
		"missing servers":      `{` + pageMeta(1, 0) + `}`,
		"null servers":         `{"servers":null,` + pageMeta(1, 0) + `}`,
		"missing meta":         `{"servers":[]}`,
		"missing pagination":   `{"servers":[],"meta":{}}`,
		"wrong page":           `{"servers":[],` + pageMeta(2, 0) + `}`,
		"next page skips":      `{"servers":[` + ok + `],` + pageMeta(1, 5) + `}`,
		"next page backwards":  `{"servers":[` + ok + `],` + pageMeta(1, 1) + `}`,
		"empty page with next": `{"servers":[],` + pageMeta(1, 2) + `}`,
		"too many items":       `{"servers":[` + ok + `,` + ok + `,` + ok + `],` + pageMeta(1, 0) + `}`,
		"item without id":      `{"servers":[{"name":"a","status":"off"}],` + pageMeta(1, 0) + `}`,
		"wrong type":           `{"servers":{},` + pageMeta(1, 0) + `}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, body)
			})
			_, err := c.ListServers(context.Background(), ListOptions{})
			if !errors.Is(err, ErrMalformedResponse) {
				t.Fatalf("err = %v, want ErrMalformedResponse", err)
			}
		})
	}
}

func TestMalformedSingleResources(t *testing.T) {
	cases := map[string]string{
		"missing server": `{}`,
		"id mismatch":    `{"server":` + serverJSON(2, "b") + `}`,
		"not json":       `ok`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
			if _, err := c.Server(context.Background(), 1); !errors.Is(err, ErrMalformedResponse) {
				t.Fatalf("err = %v", err)
			}
		})
	}
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"primary_ip":{"id":7,"name":"p","ip":"198.51.100.7","type":"ipv5"}}`)
	})
	if _, err := c.PrimaryIP(context.Background(), 7); !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("PrimaryIP err = %v", err)
	}
}

func TestTruncatedBody(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		fmt.Fprint(w, `{"server":`)
	})
	if _, err := c.Server(context.Background(), 1); !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("err = %v", err)
	}
}

func TestBodyTooLarge(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"server":"`))
		w.Write([]byte(strings.Repeat("a", MaxResponseBytes)))
		w.Write([]byte(`"}`))
	})
	if _, err := c.Server(context.Background(), 1); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("err = %v", err)
	}
}

func TestRedirectRefused(t *testing.T) {
	var leaked atomic.Bool
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked.Store(true)
	}))
	defer target.Close()
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/v1/servers/1", http.StatusTemporaryRedirect)
	})
	_, err := c.Server(context.Background(), 1)
	if !errors.Is(err, ErrRedirect) {
		t.Fatalf("err = %v, want ErrRedirect", err)
	}
	if leaked.Load() {
		t.Fatal("redirect target was contacted")
	}
}

func TestNewDoesNotModifyCallerClient(t *testing.T) {
	hc := &http.Client{}
	if _, err := New(DefaultBaseURL, testToken, hc); err != nil {
		t.Fatal(err)
	}
	if hc.CheckRedirect != nil {
		t.Fatal("caller's http.Client was modified")
	}
}

func TestContextDeadline(t *testing.T) {
	release := make(chan struct{})
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	defer close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.ListServers(ctx, ListOptions{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want DeadlineExceeded", err)
	}
}

func TestNoRetry(t *testing.T) {
	var calls atomic.Int32
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	if _, err := c.ListServers(context.Background(), ListOptions{}); !errors.Is(err, ErrServer) {
		t.Fatalf("err = %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1", calls.Load())
	}
}

func TestPaginationLimit(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		fmt.Fprintf(w, `{"servers":[%s],"meta":{"pagination":{"page":%d,"per_page":50,"next_page":%d}}}`,
			serverJSON(page, "s"), page, page+1)
	})
	if _, err := c.ListServers(context.Background(), ListOptions{}); !errors.Is(err, ErrPaginationLimit) {
		t.Fatalf("err = %v", err)
	}
}

func TestNewValidation(t *testing.T) {
	hc := &http.Client{}
	bad := map[string]struct {
		url, token string
		hc         *http.Client
	}{
		"http":       {"http://api.example.com/v1", testToken, hc},
		"relative":   {"/v1", testToken, hc},
		"no host":    {"https:///v1", testToken, hc},
		"userinfo":   {"https://user:" + testToken + "@api.example.com/v1", testToken, hc},
		"query":      {"https://api.example.com/v1?x=1", testToken, hc},
		"fragment":   {"https://api.example.com/v1#x", testToken, hc},
		"no token":   {DefaultBaseURL, "", hc},
		"bad token":  {DefaultBaseURL, "abc\r\nX-Injected: 1", hc},
		"space":      {DefaultBaseURL, "abc def", hc},
		"nil client": {DefaultBaseURL, testToken, nil},
	}
	for name, tc := range bad {
		t.Run(name, func(t *testing.T) {
			_, err := New(tc.url, tc.token, tc.hc)
			if err == nil {
				t.Fatal("New succeeded")
			}
			if strings.Contains(err.Error(), testToken) {
				t.Fatalf("error leaks token: %q", err)
			}
		})
	}
}

func TestClientFormattingHidesToken(t *testing.T) {
	c, err := New(DefaultBaseURL, testToken, &http.Client{})
	if err != nil {
		t.Fatal(err)
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if s := fmt.Sprintf(verb, c); strings.Contains(s, testToken) {
			t.Errorf("%s leaks token: %q", verb, s)
		}
	}
}
