package metrics

import (
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestClient starts a TLS test server and returns a client for it.
func newTestClient(t *testing.T, h http.HandlerFunc, mod func(*Options)) *Client {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	opts := Options{BaseURL: srv.URL + "/prefix", HTTPClient: srv.Client(), Timeout: 2 * time.Second}
	if mod != nil {
		mod(&opts)
	}
	c, err := NewClient(opts)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// blockUntilDone returns a handler that waits for the request to end. Its
// release cleanup runs before the server's Close because cleanups are LIFO,
// so it must be created after newTestClient.
func blockUntilDone(t *testing.T, onRequest func()) http.HandlerFunc {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	return func(w http.ResponseWriter, r *http.Request) {
		if onRequest != nil {
			onRequest()
		}
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}
}

// lateHandler lets a test register a handler after the server exists.
type lateHandler struct{ h http.HandlerFunc }

func (l *lateHandler) serve(w http.ResponseWriter, r *http.Request) { l.h(w, r) }

func respond(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		io.WriteString(w, body)
	}
}

func TestNewClientValidation(t *testing.T) {
	hc := &http.Client{}
	cases := map[string]Options{
		"empty url":    {HTTPClient: hc, Timeout: time.Second},
		"http scheme":  {BaseURL: "http://vm.example.com", HTTPClient: hc, Timeout: time.Second},
		"no host":      {BaseURL: "https:///api", HTTPClient: hc, Timeout: time.Second},
		"userinfo":     {BaseURL: "https://u:p@vm.example.com", HTTPClient: hc, Timeout: time.Second},
		"query":        {BaseURL: "https://vm.example.com/?x=1", HTTPClient: hc, Timeout: time.Second},
		"fragment":     {BaseURL: "https://vm.example.com/#f", HTTPClient: hc, Timeout: time.Second},
		"nil client":   {BaseURL: "https://vm.example.com", Timeout: time.Second},
		"zero timeout": {BaseURL: "https://vm.example.com", HTTPClient: hc},
		"negative max": {BaseURL: "https://vm.example.com", HTTPClient: hc, Timeout: time.Second, MaxBodyBytes: -1},
		"both creds": {BaseURL: "https://vm.example.com", HTTPClient: hc, Timeout: time.Second,
			BearerToken: "t", BasicAuth: &BasicAuth{Username: "u"}},
		"empty basic user": {BaseURL: "https://vm.example.com", HTTPClient: hc, Timeout: time.Second,
			BasicAuth: &BasicAuth{Password: "p"}},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewClient(opts); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	if _, err := NewClient(Options{BaseURL: "https://vm.example.com/select/0/prometheus", HTTPClient: hc, Timeout: time.Second}); err != nil {
		t.Fatalf("valid options rejected: %v", err)
	}
}

func TestQueryRequestShape(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 678_000_000, time.UTC)
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/prefix/api/v1/query" || r.URL.RawQuery != "" {
			t.Errorf("request %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization = %q", got)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if got := r.PostForm.Get("query"); got != `up{job="node"}` {
			t.Errorf("query = %q", got)
		}
		if got := r.PostForm.Get("time"); got != "1767323045.678" {
			t.Errorf("time = %q", got)
		}
		respond(200, `{"status":"success","data":{"resultType":"scalar","result":[1767323045.678,"42.5"]}}`)(w, r)
	}, func(o *Options) { o.BearerToken = "test-token" })

	res, err := c.Query(context.Background(), `up{job="node"}`, at)
	if err != nil {
		t.Fatal(err)
	}
	if res.Type != ResultScalar || res.Scalar.Value != 42.5 || !res.Scalar.Time.Equal(at) {
		t.Fatalf("result = %+v", res)
	}
}

func TestQueryOmitsZeroTimeAndUsesBasicAuth(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if _, ok := r.PostForm["time"]; ok {
			t.Error("time must be omitted for a zero instant")
		}
		if u, p, ok := r.BasicAuth(); !ok || u != "reader" || p != "secret" {
			t.Errorf("basic auth = %q %q %v", u, p, ok)
		}
		respond(200, `{"status":"success","data":{"resultType":"vector","result":[]}}`)(w, r)
	}, func(o *Options) { o.BasicAuth = &BasicAuth{Username: "reader", Password: "secret"} })
	if _, err := c.Query(context.Background(), "up", time.Time{}); err != nil {
		t.Fatal(err)
	}
}

func TestQueryVector(t *testing.T) {
	c := newTestClient(t, respond(200, `{"status":"success","warnings":["partial"],"data":{"resultType":"vector","result":[
		{"metric":{"__name__":"up","instance":"a"},"value":[1700000000,"1"]},
		{"metric":{},"value":[1700000000.5,"NaN"]},
		{"metric":{"instance":"c"},"value":[1700000001,"+Inf"]}]}}`), nil)
	res, err := c.Query(context.Background(), "up", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Type != ResultVector || len(res.Series) != 3 || len(res.Warnings) != 1 {
		t.Fatalf("result = %+v", res)
	}
	s0 := res.Series[0]
	if s0.Labels["instance"] != "a" || s0.Labels["__name__"] != "up" || len(s0.Samples) != 1 ||
		s0.Samples[0].Value != 1 || !s0.Samples[0].Time.Equal(time.Unix(1700000000, 0)) {
		t.Errorf("series 0 = %+v", s0)
	}
	if res.Series[1].Labels == nil || !math.IsNaN(res.Series[1].Samples[0].Value) ||
		!res.Series[1].Samples[0].Time.Equal(time.UnixMilli(1700000000500)) {
		t.Errorf("series 1 = %+v", res.Series[1])
	}
	if !math.IsInf(res.Series[2].Samples[0].Value, 1) {
		t.Errorf("series 2 = %+v", res.Series[2])
	}
}

func TestQueryRangeMatrix(t *testing.T) {
	start := time.Unix(1700000000, 0)
	end := start.Add(2 * time.Minute)
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/prefix/api/v1/query_range" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		f := r.PostForm
		if f.Get("start") != "1700000000.000" || f.Get("end") != "1700000120.000" || f.Get("step") != "60" || f.Get("query") != "rate(x[5m])" {
			t.Errorf("form = %v", f)
		}
		respond(200, `{"status":"success","data":{"resultType":"matrix","result":[
			{"metric":{"node":"exit-01"},"values":[[1700000000,"1"],[1700000060,"2"],[1700000120,"3"]]},
			{"metric":{"node":"relay-01"},"values":[]}]}}`)(w, r)
	}, nil)
	res, err := c.QueryRange(context.Background(), "rate(x[5m])", start, end, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if res.Type != ResultMatrix || len(res.Series) != 2 {
		t.Fatalf("result = %+v", res)
	}
	s := res.Series[0]
	if s.Labels["node"] != "exit-01" || len(s.Samples) != 3 || s.Samples[2].Value != 3 || !s.Samples[2].Time.Equal(end) {
		t.Errorf("series = %+v", s)
	}
	if len(res.Series[1].Samples) != 0 {
		t.Errorf("empty series = %+v", res.Series[1])
	}
}

func TestQueryRangeArgumentValidation(t *testing.T) {
	calls := 0
	c := newTestClient(t, func(http.ResponseWriter, *http.Request) { calls++ }, nil)
	now := time.Unix(1700000000, 0)
	ctx := context.Background()
	if _, err := c.QueryRange(ctx, " ", now, now, time.Minute); err == nil {
		t.Error("empty expression accepted")
	}
	if _, err := c.QueryRange(ctx, "up", now, now.Add(-time.Second), time.Minute); err == nil {
		t.Error("end before start accepted")
	}
	if _, err := c.QueryRange(ctx, "up", now, now, 0); err == nil {
		t.Error("zero step accepted")
	}
	if _, err := c.QueryRange(ctx, "up", time.Time{}, now, time.Minute); err == nil {
		t.Error("zero start accepted")
	}
	if _, err := c.Query(ctx, "", now); err == nil {
		t.Error("empty instant expression accepted")
	}
	if calls != 0 {
		t.Errorf("invalid arguments made %d requests", calls)
	}
}

func TestQueryRangeRejectsNonMatrix(t *testing.T) {
	c := newTestClient(t, respond(200, `{"status":"success","data":{"resultType":"vector","result":[]}}`), nil)
	now := time.Unix(1700000000, 0)
	_, err := c.QueryRange(context.Background(), "up", now, now, time.Minute)
	var rte *ResultTypeError
	if !errors.As(err, &rte) || rte.Got != "vector" {
		t.Fatalf("err = %v", err)
	}
}

func TestQueryErrors(t *testing.T) {
	const secretBody = "SECRET-BODY-CONTENT"
	cases := []struct {
		name   string
		status int
		body   string
		check  func(t *testing.T, err error)
	}{
		{"status error", 422, `{"status":"error","errorType":"execution","error":"bad\nquery"}`, func(t *testing.T, err error) {
			var e *APIError
			if !errors.As(err, &e) || e.StatusCode != 422 || e.Type != "execution" || e.Message != "bad query" {
				t.Fatalf("err = %#v", err)
			}
		}},
		{"status error with 200", 200, `{"status":"error","errorType":"bad_data","error":"x"}`, func(t *testing.T, err error) {
			var e *APIError
			if !errors.As(err, &e) || e.StatusCode != 200 {
				t.Fatalf("err = %#v", err)
			}
		}},
		{"429 plain", 429, secretBody, func(t *testing.T, err error) {
			var e *HTTPError
			if !errors.As(err, &e) || e.StatusCode != 429 {
				t.Fatalf("err = %#v", err)
			}
		}},
		{"503 plain", 503, "<html>" + secretBody + "</html>", func(t *testing.T, err error) {
			var e *HTTPError
			if !errors.As(err, &e) || e.StatusCode != 503 {
				t.Fatalf("err = %#v", err)
			}
		}},
		{"500 success envelope", 500, `{"status":"success","data":{"resultType":"vector","result":[]}}`, func(t *testing.T, err error) {
			var e *HTTPError
			if !errors.As(err, &e) || e.StatusCode != 500 {
				t.Fatalf("err = %#v", err)
			}
		}},
		{"malformed json", 200, `{"status":` + secretBody, decodeErr},
		{"truncated json", 200, `{"status":"success","data":{"resultType":"vector","result":[`, decodeErr},
		{"trailing data", 200, `{"status":"success","data":{"resultType":"vector","result":[]}} {}`, decodeErr},
		{"unknown status", 200, `{"status":"` + secretBody + `"}`, decodeErr},
		{"missing data", 200, `{"status":"success"}`, decodeErr},
		{"bad sample value", 200, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1,"` + secretBody + `"]}]}}`, decodeErr},
		{"numeric sample value", 200, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1,1]}]}}`, decodeErr},
		{"short pair", 200, `{"status":"success","data":{"resultType":"scalar","result":[1]}}`, decodeErr},
		{"bad timestamp", 200, `{"status":"success","data":{"resultType":"scalar","result":["1","1"]}}`, decodeErr},
		{"huge timestamp", 200, `{"status":"success","data":{"resultType":"scalar","result":[1e300,"1"]}}`, decodeErr},
		{"vector with values", 200, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"values":[[1,"1"]]}]}}`, decodeErr},
		{"matrix with value", 200, `{"status":"success","data":{"resultType":"matrix","result":[{"metric":{},"value":[1,"1"]}]}}`, decodeErr},
		{"null result", 200, `{"status":"success","data":{"resultType":"vector","result":null}}`, decodeErr},
		{"string result type", 200, `{"status":"success","data":{"resultType":"string","result":[1,"` + secretBody + `"]}}`, func(t *testing.T, err error) {
			var e *ResultTypeError
			if !errors.As(err, &e) || e.Got != "string" {
				t.Fatalf("err = %#v", err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestClient(t, respond(tc.status, tc.body), nil)
			_, err := c.Query(context.Background(), "up", time.Time{})
			if err == nil {
				t.Fatal("expected error")
			}
			if strings.Contains(err.Error(), secretBody) {
				t.Fatalf("error leaks response body: %v", err)
			}
			tc.check(t, err)
		})
	}
}

func decodeErr(t *testing.T, err error) {
	t.Helper()
	var e *DecodeError
	if !errors.As(err, &e) {
		t.Fatalf("err = %#v, want *DecodeError", err)
	}
}

func TestAPIErrorMessageIsTruncated(t *testing.T) {
	long := strings.Repeat("x", 10_000)
	c := newTestClient(t, respond(400, `{"status":"error","errorType":"bad_data","error":"`+long+`"}`), nil)
	_, err := c.Query(context.Background(), "up", time.Time{})
	var e *APIError
	if !errors.As(err, &e) || len([]rune(e.Message)) != maxAPIMessage+1 {
		t.Fatalf("err = %v", err)
	}
}

func TestOversizedBody(t *testing.T) {
	body := `{"status":"success","data":{"resultType":"vector","result":[]}}`
	limit := int64(len(body))
	exact := newTestClient(t, respond(200, body), func(o *Options) { o.MaxBodyBytes = limit })
	if _, err := exact.Query(context.Background(), "up", time.Time{}); err != nil {
		t.Fatalf("body at limit rejected: %v", err)
	}
	over := newTestClient(t, respond(200, body+" "), func(o *Options) { o.MaxBodyBytes = limit })
	_, err := over.Query(context.Background(), "up", time.Time{})
	var e *BodyTooLargeError
	if !errors.As(err, &e) || e.Limit != limit {
		t.Fatalf("err = %v", err)
	}
}

func TestTimeout(t *testing.T) {
	l := &lateHandler{}
	c := newTestClient(t, l.serve, func(o *Options) { o.Timeout = 50 * time.Millisecond })
	l.h = blockUntilDone(t, nil)
	_, err := c.Query(context.Background(), "up", time.Time{})
	var re *RequestError
	if !errors.As(err, &re) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
}

func TestCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	l := &lateHandler{}
	c := newTestClient(t, l.serve, nil)
	l.h = blockUntilDone(t, cancel)
	_, err := c.Query(ctx, "up", time.Time{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

func TestNoRetries(t *testing.T) {
	calls := 0
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		respond(503, "")(w, r)
	}, nil)
	if _, err := c.Query(context.Background(), "up", time.Time{}); err == nil {
		t.Fatal("expected error")
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}
}
