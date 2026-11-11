package cloudflare

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

// Synthetic values; they only exist in this test.
const (
	testToken  = "cf-test-token-0123456789abcdef"
	testZoneID = "0123456789abcdef0123456789abcdef"
)

func newTestClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	c, err := New(srv.URL+"/client/v4", testToken, srv.Client())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func checkRequest(t *testing.T, r *http.Request, path string) {
	t.Helper()
	if r.Method != http.MethodGet {
		t.Errorf("method = %s, want GET", r.Method)
	}
	if r.Header.Get("Authorization") != "Bearer "+testToken {
		t.Errorf("Authorization header mismatch")
	}
	if r.URL.Path != path {
		t.Errorf("path = %q, want %q", r.URL.Path, path)
	}
}

func okPage(result string, page, perPage, totalPages, count int) string {
	return fmt.Sprintf(`{"success":true,"errors":[],"messages":[],"result":%s,
		"result_info":{"page":%d,"per_page":%d,"total_pages":%d,"count":%d,"total_count":%d}}`,
		result, page, perPage, totalPages, count, count*totalPages)
}

func record(id, typ, name, content string) string {
	return fmt.Sprintf(`{"id":%q,"type":%q,"name":%q,"content":%q,"proxied":false,"ttl":300,
		"proxiable":true,"created_on":"2026-01-01T00:00:00Z","modified_on":"2026-01-01T00:00:00Z","meta":{}}`,
		id, typ, name, content)
}

func TestListDNSRecordsPagination(t *testing.T) {
	var calls atomic.Int32
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		checkRequest(t, r, "/client/v4/zones/"+testZoneID+"/dns_records")
		q := r.URL.Query()
		if q.Get("type") != "A" || q.Get("name.exact") != "exit.example.com" || q.Get("per_page") != "100" {
			t.Errorf("query = %q", r.URL.RawQuery)
		}
		switch q.Get("page") {
		case "1":
			fmt.Fprint(w, okPage("["+record("r1", "A", "exit.example.com", "192.0.2.1")+","+
				record("r2", "A", "exit.example.com", "192.0.2.2")+"]", 1, 2, 2, 2))
		case "2":
			fmt.Fprint(w, okPage("["+record("r3", "A", "exit.example.com", "192.0.2.3")+"]", 2, 2, 2, 1))
		default:
			t.Errorf("unexpected page %q", q.Get("page"))
		}
	})
	got, err := c.ListDNSRecords(context.Background(), testZoneID, DNSRecordFilter{Type: "A", Name: "exit.example.com"})
	if err != nil {
		t.Fatalf("ListDNSRecords: %v", err)
	}
	if len(got) != 3 || calls.Load() != 2 {
		t.Fatalf("got %d records in %d calls", len(got), calls.Load())
	}
	want := DNSRecord{ID: "r1", Type: "A", Name: "exit.example.com", Content: "192.0.2.1", TTL: 300}
	if got[0] != want || got[2].ID != "r3" {
		t.Errorf("records = %+v", got)
	}
}

func TestListZones(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		checkRequest(t, r, "/client/v4/zones")
		q := r.URL.Query()
		if q.Get("name") != "example.com" || q.Get("per_page") != "50" || q.Get("page") != "1" {
			t.Errorf("query = %q", r.URL.RawQuery)
		}
		fmt.Fprint(w, okPage(`[{"id":"`+testZoneID+`","name":"example.com","status":"active","paused":false,"type":"full"}]`, 1, 50, 1, 1))
	})
	got, err := c.ListZones(context.Background(), ZoneFilter{Name: "example.com"})
	if err != nil {
		t.Fatalf("ListZones: %v", err)
	}
	if len(got) != 1 || got[0] != (Zone{ID: testZoneID, Name: "example.com", Status: "active"}) {
		t.Fatalf("zones = %+v", got)
	}
}

func TestEmptyResult(t *testing.T) {
	// Cloudflare reports total_pages 0 for an empty result.
	for _, totalPages := range []int{0, 1} {
		c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, okPage(`[]`, 1, 50, totalPages, 0))
		})
		got, err := c.ListZones(context.Background(), ZoneFilter{})
		if err != nil || got == nil || len(got) != 0 {
			t.Fatalf("total_pages %d: got %#v, %v", totalPages, got, err)
		}
	}
}

func TestBasePathPreserved(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkRequest(t, r, "/edge/cf/client/v4/zones")
		fmt.Fprint(w, okPage(`[]`, 1, 50, 0, 0))
	}))
	defer srv.Close()
	c, err := New(srv.URL+"/edge/cf/client/v4/", testToken, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ListZones(context.Background(), ZoneFilter{}); err != nil {
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
		{502, ErrServer},
	}
	all := []error{ErrUnauthorized, ErrForbidden, ErrNotFound, ErrRateLimited, ErrServer, ErrUnsuccessful}
	for _, tc := range cases {
		t.Run(strconv.Itoa(tc.status), func(t *testing.T) {
			c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				// Provider message echoes the token: it must be redacted.
				fmt.Fprintf(w, `{"success":false,"errors":[{"code":10000,"message":"bad token %s\r\n"}],"messages":[],"result":null}`, testToken)
			})
			_, err := c.ListDNSRecords(context.Background(), testZoneID, DNSRecordFilter{})
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != tc.status || apiErr.Code != 10000 {
				t.Fatalf("APIError = %+v", apiErr)
			}
			if strings.Contains(err.Error(), testToken) || strings.ContainsAny(err.Error(), "\r\n") {
				t.Fatalf("error leaks token or control characters: %q", err)
			}
			for _, other := range all {
				if other != tc.want && errors.Is(err, other) {
					t.Errorf("err also matches %v", other)
				}
			}
		})
	}
}

func TestSuccessFalseOn200(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"success":false,"errors":[{"code":1003,"message":"invalid"}],"messages":[],"result":[]}`)
	})
	_, err := c.ListZones(context.Background(), ZoneFilter{})
	var apiErr *APIError
	if !errors.Is(err, ErrUnsuccessful) || !errors.As(err, &apiErr) || apiErr.Code != 1003 {
		t.Fatalf("err = %v", err)
	}
}

func TestErrorWithNonJSONBody(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, "<html>origin page</html>")
	})
	_, err := c.ListZones(context.Background(), ZoneFilter{})
	if !errors.Is(err, ErrServer) || strings.Contains(err.Error(), "origin page") {
		t.Fatalf("err = %v", err)
	}
}

func TestMalformedResponses(t *testing.T) {
	r1 := "[" + record("r1", "A", "a.example.com", "192.0.2.1") + "]"
	cases := map[string]string{
		"invalid json":        `{"success":true,"result":[`,
		"not an object":       `[]`,
		"missing success":     `{"result":[],"result_info":{"page":1,"per_page":100,"total_pages":0}}`,
		"success not bool":    `{"success":"yes","result":[],"result_info":{"page":1,"per_page":100,"total_pages":0}}`,
		"missing result":      `{"success":true,"result_info":{"page":1,"per_page":100,"total_pages":0}}`,
		"null result":         `{"success":true,"result":null,"result_info":{"page":1,"per_page":100,"total_pages":0}}`,
		"result not array":    `{"success":true,"result":{},"result_info":{"page":1,"per_page":100,"total_pages":0}}`,
		"missing result_info": `{"success":true,"result":[]}`,
		"missing total_pages": `{"success":true,"result":[],"result_info":{"page":1,"per_page":100}}`,
		"wrong page":          okPage(`[]`, 2, 100, 2, 0),
		"empty page not last": okPage(`[]`, 1, 100, 3, 0),
		"count mismatch":      okPage(r1, 1, 100, 1, 2),
		"more than per_page":  okPage(r1, 1, 0, 1, 1),
		"record without id":   okPage(`[{"type":"A","name":"a.example.com"}]`, 1, 100, 1, 1),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
			_, err := c.ListDNSRecords(context.Background(), testZoneID, DNSRecordFilter{})
			if !errors.Is(err, ErrMalformedResponse) {
				t.Fatalf("err = %v, want ErrMalformedResponse", err)
			}
		})
	}
}

func TestTruncatedBody(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		fmt.Fprint(w, `{"success":true,`)
	})
	if _, err := c.ListZones(context.Background(), ZoneFilter{}); !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("err = %v", err)
	}
}

func TestBodyTooLarge(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"success":true,"result":"`))
		w.Write([]byte(strings.Repeat("a", MaxResponseBytes)))
		w.Write([]byte(`"}`))
	})
	if _, err := c.ListZones(context.Background(), ZoneFilter{}); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("err = %v", err)
	}
}

func TestRedirectRefused(t *testing.T) {
	var leaked atomic.Bool
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked.Store(true)
	}))
	defer target.Close()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/client/v4/zones", http.StatusFound)
	})
	_, err := c.ListZones(context.Background(), ZoneFilter{})
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
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	defer close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.ListZones(ctx, ZoneFilter{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want DeadlineExceeded", err)
	}
}

func TestNoRetry(t *testing.T) {
	var calls atomic.Int32
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	})
	if _, err := c.ListZones(context.Background(), ZoneFilter{}); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("err = %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1", calls.Load())
	}
}

func TestPaginationLimit(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		fmt.Fprint(w, okPage(`[{"id":"z","name":"example.com","status":"active"}]`, page, 50, 1<<30, 1))
	})
	if _, err := c.ListZones(context.Background(), ZoneFilter{}); !errors.Is(err, ErrPaginationLimit) {
		t.Fatalf("err = %v", err)
	}
}

func TestInvalidZoneID(t *testing.T) {
	var calls atomic.Int32
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1) })
	for _, id := range []string{"", "../zones", "a/b", "abc?x=1", strings.Repeat("a", 33)} {
		if _, err := c.ListDNSRecords(context.Background(), id, DNSRecordFilter{}); err == nil {
			t.Errorf("zone ID %q accepted", id)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("invalid zone IDs reached the server %d times", calls.Load())
	}
}

func TestNewValidation(t *testing.T) {
	hc := &http.Client{}
	bad := map[string]struct {
		url, token string
		hc         *http.Client
	}{
		"http":       {"http://api.example.com/client/v4", testToken, hc},
		"relative":   {"/client/v4", testToken, hc},
		"no host":    {"https:///client/v4", testToken, hc},
		"userinfo":   {"https://user:" + testToken + "@api.example.com/client/v4", testToken, hc},
		"query":      {"https://api.example.com/client/v4?x=1", testToken, hc},
		"fragment":   {"https://api.example.com/client/v4#x", testToken, hc},
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
