package globalping

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testToken = "gp-test-token-5f1c"
	testUA    = "vpnctl-test/1.0"
	testID    = "Mz3aB7xQ9kLp2Rt"
	rawMarker = "RAW-BODY-MARKER"
)

func newTLSServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func newClient(t *testing.T, srv *httptest.Server, mutate func(*Config)) *Client {
	t.Helper()
	cfg := Config{
		BaseURL:    srv.URL + "/api",
		Token:      testToken,
		HTTPClient: srv.Client(),
		UserAgent:  testUA,
		MaxWait:    5 * time.Second,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	io.WriteString(w, body)
}

func created(w http.ResponseWriter, location, body string) {
	w.Header().Set("Location", location)
	writeJSON(w, http.StatusAccepted, body)
}

func measurementJSON(status string, results string) string {
	return fmt.Sprintf(`{"id":%q,"type":"http","status":%q,"createdAt":"2026-11-10T10:00:00.000Z",
		"updatedAt":"2026-11-10T10:00:01.000Z","target":"example.com","probesCount":2,
		"locations":[{"country":"RU"}],"limit":2,"futureField":{"x":1},"results":[%s]}`, testID, status, results)
}

const probeJSON = `{"continent":"EU","region":"Eastern Europe","country":"RU","state":null,"city":"Moscow",
	"asn":64500,"network":"Example Net","latitude":55.75,"longitude":37.62,"tags":["eyeball-network"],"resolvers":["private"]}`

var finishedResult = `{"probe":` + probeJSON + `,"result":{"status":"finished",
	"rawHeaders":"Set-Cookie: ` + rawMarker + `","rawBody":"` + rawMarker + `","rawOutput":"HTTP/1.1 200\n` + rawMarker + `",
	"truncated":false,"headers":{"set-cookie":["` + rawMarker + `"]},"statusCode":200,"statusCodeName":"OK",
	"resolvedAddress":"192.0.2.10","timings":{"total":120,"dns":10,"tcp":20,"tls":30,"firstByte":40,"download":20},
	"tls":{"protocol":"TLSv1.3","cipherName":"TLS_AES_128_GCM_SHA256","authorized":true,
	"createdAt":"2026-01-01T00:00:00.000Z","expiresAt":"2027-01-01T00:00:00.000Z",
	"subject":{"CN":"example.com","alt":"DNS:example.com"},"issuer":{"C":"US","O":"Example CA","CN":"Example CA R1"},
	"keyType":"EC","keyBits":256,"serialNumber":"01:02","fingerprint256":"AA:BB","publicKey":"04:AB"}}}`

var failedResult = `{"probe":` + probeJSON + `,"result":{"status":"failed","failureSource":"target",
	"rawOutput":"connect ETIMEDOUT ` + rawMarker + `"}}`

func TestCreateAndWaitHTTPMeasurement(t *testing.T) {
	var (
		mu       sync.Mutex
		gets     []time.Time
		lastResp time.Time
		gaps     []time.Duration
	)
	srv := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+testToken {
			t.Errorf("Authorization = %q", got)
		}
		if got := r.Header.Get("User-Agent"); got != testUA {
			t.Errorf("User-Agent = %q", got)
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/measurements":
			if ct := r.Header.Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type = %q", ct)
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode request: %v", err)
			}
			want := map[string]any{
				"type":      "http",
				"target":    "example.com",
				"locations": []any{map[string]any{"country": "RU"}},
				"limit":     float64(2),
				"measurementOptions": map[string]any{
					"protocol":  "HTTPS",
					"port":      float64(8443),
					"ipVersion": float64(4),
					"request":   map[string]any{"method": "GET", "path": "/health", "query": "a=1", "host": "example.org"},
				},
			}
			if fmt.Sprint(body) != fmt.Sprint(want) {
				t.Errorf("request body\n got %v\nwant %v", body, want)
			}
			w.Header().Set("X-RateLimit-Limit", "250")
			w.Header().Set("X-RateLimit-Consumed", "2")
			w.Header().Set("X-RateLimit-Remaining", "248")
			w.Header().Set("X-RateLimit-Reset", "3000")
			created(w, "https://"+r.Host+"/api/v1/measurements/"+testID, `{"id":"`+testID+`","probesCount":2}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/measurements/"+testID:
			mu.Lock()
			now := time.Now()
			if !lastResp.IsZero() {
				gaps = append(gaps, now.Sub(lastResp))
			}
			gets = append(gets, now)
			n := len(gets)
			mu.Unlock()
			if n == 1 {
				writeJSON(w, http.StatusOK, measurementJSON("in-progress",
					`{"probe":`+probeJSON+`,"result":{"status":"in-progress","rawOutput":""}}`))
			} else {
				writeJSON(w, http.StatusOK, measurementJSON("finished", finishedResult+","+failedResult))
			}
			mu.Lock()
			lastResp = time.Now()
			mu.Unlock()
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusTeapot)
		}
	})
	c := newClient(t, srv, nil)
	ctx := context.Background()

	cm, err := c.CreateHTTPMeasurement(ctx, HTTPMeasurementRequest{
		Target: "example.com", Limit: 2, Protocol: ProtocolHTTPS, Port: 8443, IPVersion: 4,
		Method: http.MethodGet, Path: "/health", Query: "a=1", Host: "example.org",
	})
	if err != nil {
		t.Fatalf("CreateHTTPMeasurement: %v", err)
	}
	if cm.ID != testID || cm.ProbesCount != 2 || cm.Location != srv.URL+"/api/v1/measurements/"+testID {
		t.Errorf("created = %+v", cm)
	}
	if cm.RateLimit.Limit != 250 || cm.RateLimit.Remaining != 248 || cm.RateLimit.Reset != 3000*time.Second || cm.RateLimit.CreditsRemaining != -1 {
		t.Errorf("rate limit = %+v", cm.RateLimit)
	}

	m, err := c.WaitMeasurement(ctx, cm.ID)
	if err != nil {
		t.Fatalf("WaitMeasurement: %v", err)
	}
	mu.Lock()
	if len(gets) != 2 {
		t.Errorf("GET count = %d, want 2", len(gets))
	}
	for _, g := range gaps {
		if g < DefaultPollInterval {
			t.Errorf("poll gap %s < %s", g, DefaultPollInterval)
		}
	}
	mu.Unlock()

	if m.Status != StatusFinished || m.Target != "example.com" || m.ProbesCount != 2 || len(m.Results) != 2 {
		t.Fatalf("measurement = %+v", m)
	}
	if !m.CreatedAt.Equal(time.Date(2026, 11, 10, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("CreatedAt = %s", m.CreatedAt)
	}
	ok := m.Results[0]
	if ok.Probe.Country != "RU" || ok.Probe.City != "Moscow" || ok.Probe.ASN != 64500 || ok.Probe.State != "" ||
		ok.Probe.Network != "Example Net" || len(ok.Probe.Tags) != 1 {
		t.Errorf("probe = %+v", ok.Probe)
	}
	h := ok.HTTP
	if h.Status != TestFinished || h.StatusCode != 200 || h.StatusCodeName != "OK" || h.ResolvedAddress != "192.0.2.10" {
		t.Errorf("http result = %+v", h)
	}
	tm := h.Timings
	if tm == nil || tm.Total != 120*time.Millisecond || tm.DNS == nil || *tm.DNS != 10*time.Millisecond ||
		tm.TLS == nil || *tm.TLS != 30*time.Millisecond || tm.FirstByte != 40*time.Millisecond {
		t.Errorf("timings = %+v", tm)
	}
	if h.TLS == nil || !h.TLS.Authorized || h.TLS.Protocol != "TLSv1.3" || h.TLS.SubjectCN != "example.com" ||
		h.TLS.IssuerO != "Example CA" || h.TLS.KeyType != "EC" || h.TLS.KeyBits != 256 {
		t.Errorf("tls = %+v", h.TLS)
	}
	failed := m.Results[1].HTTP
	if failed.Status != TestFailed || failed.FailureSource != "target" || failed.Timings != nil || failed.StatusCode != 0 {
		t.Errorf("failed result = %+v", failed)
	}
	if dump := fmt.Sprintf("%+v %+v %+v", m, *h.Timings, *h.TLS); strings.Contains(dump, rawMarker) {
		t.Errorf("raw response data leaked into the model: %s", dump)
	}
}

func TestWaitStopsOnUnknownFinalStatusAndEmptyResults(t *testing.T) {
	srv := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, measurementJSON("aborted", ""))
	})
	m, err := newClient(t, srv, nil).WaitMeasurement(context.Background(), testID)
	if err != nil {
		t.Fatalf("WaitMeasurement: %v", err)
	}
	if m.Status != "aborted" || len(m.Results) != 0 {
		t.Errorf("measurement = %+v", m)
	}
}

func TestAPIErrors(t *testing.T) {
	cases := []struct {
		status int
		typ    string
		want   error
	}{
		{http.StatusBadRequest, "validation_error", ErrBadRequest},
		{http.StatusForbidden, "insufficient_permissions", ErrForbidden},
		{http.StatusNotFound, "not_found", ErrNotFound},
		{http.StatusUnprocessableEntity, "no_probes_found", ErrNoProbes},
		{http.StatusTooManyRequests, "rate_limit_exceeded", ErrRateLimited},
		{http.StatusInternalServerError, "api_error", ErrServer},
		{http.StatusServiceUnavailable, "", ErrServer},
		{http.StatusUnauthorized, "unauthorized", ErrUnexpectedStatus},
	}
	for _, tc := range cases {
		for _, method := range []string{http.MethodPost, http.MethodGet} {
			t.Run(fmt.Sprintf("%s_%d", method, tc.status), func(t *testing.T) {
				var hits atomic.Int32
				srv := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)
					w.Header().Set("Retry-After", "7")
					w.Header().Set("X-RateLimit-Remaining", "0")
					body := `{"error":{"type":"` + tc.typ + `","message":"secret detail example.com"}}`
					if tc.typ == "" {
						body = "<html>upstream down</html>"
					}
					writeJSON(w, tc.status, body)
				})
				c := newClient(t, srv, nil)
				var err error
				if method == http.MethodPost {
					_, err = c.CreateHTTPMeasurement(context.Background(), HTTPMeasurementRequest{Target: "example.com"})
				} else {
					_, err = c.WaitMeasurement(context.Background(), testID)
				}
				if !errors.Is(err, tc.want) {
					t.Fatalf("err = %v, want %v", err, tc.want)
				}
				var apiErr *APIError
				if !errors.As(err, &apiErr) {
					t.Fatalf("err %T is not *APIError", err)
				}
				if apiErr.StatusCode != tc.status || apiErr.Type != tc.typ || apiErr.RetryAfter != 7*time.Second || apiErr.RateLimit.Remaining != 0 {
					t.Errorf("APIError = %+v", apiErr)
				}
				if strings.Contains(err.Error(), "secret detail") {
					t.Errorf("error leaks server message: %v", err)
				}
				if n := hits.Load(); n != 1 {
					t.Errorf("requests = %d, want exactly 1 (no retries)", n)
				}
			})
		}
	}
}

func TestMalformedCreateResponses(t *testing.T) {
	cases := map[string]struct {
		location string
		body     string
	}{
		"invalid json":      {"/api/v1/measurements/" + testID, `{"id":`},
		"not json":          {"/api/v1/measurements/" + testID, `<html>`},
		"trailing data":     {"/api/v1/measurements/" + testID, `{"id":"` + testID + `","probesCount":1}{}`},
		"missing id":        {"/api/v1/measurements/" + testID, `{"probesCount":1}`},
		"invalid id":        {"/api/v1/measurements/" + testID, `{"id":"../x","probesCount":1}`},
		"missing probes":    {"/api/v1/measurements/" + testID, `{"id":"` + testID + `"}`},
		"missing Location":  {"", `{"id":"` + testID + `","probesCount":1}`},
		"foreign Location":  {"https://attacker.example/api/v1/measurements/" + testID, `{"id":"` + testID + `","probesCount":1}`},
		"mismatch Location": {"/api/v1/measurements/other", `{"id":"` + testID + `","probesCount":1}`},
		"no prefix":         {"/v1/measurements/" + testID, `{"id":"` + testID + `","probesCount":1}`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
				if tc.location != "" {
					w.Header().Set("Location", tc.location)
				}
				writeJSON(w, http.StatusAccepted, tc.body)
			})
			_, err := newClient(t, srv, nil).CreateHTTPMeasurement(context.Background(), HTTPMeasurementRequest{Target: "example.com"})
			if !errors.Is(err, ErrMalformedResponse) {
				t.Fatalf("err = %v, want ErrMalformedResponse", err)
			}
			if strings.Contains(err.Error(), "attacker") {
				t.Errorf("error echoes server data: %v", err)
			}
		})
	}
}

func TestCreateRelativeLocationAndNon202(t *testing.T) {
	srv := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		created(w, "/api/v1/measurements/"+testID, `{"id":"`+testID+`","probesCount":1}`)
	})
	srv200 := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, `{"id":"`+testID+`","probesCount":1}`)
	})
	if _, err := newClient(t, srv, nil).CreateHTTPMeasurement(context.Background(), HTTPMeasurementRequest{Target: "example.com"}); err != nil {
		t.Fatalf("relative Location: %v", err)
	}
	_, err := newClient(t, srv200, nil).CreateHTTPMeasurement(context.Background(), HTTPMeasurementRequest{Target: "example.com"})
	if !errors.Is(err, ErrUnexpectedStatus) {
		t.Fatalf("err = %v, want ErrUnexpectedStatus", err)
	}
}

func TestMalformedMeasurementResponses(t *testing.T) {
	cases := map[string]string{
		"truncated":         measurementJSON("finished", finishedResult)[:200],
		"wrong id":          strings.Replace(measurementJSON("finished", ""), testID, "otherID", 1),
		"wrong type":        strings.Replace(measurementJSON("finished", ""), `"type":"http"`, `"type":"ping"`, 1),
		"missing status":    strings.Replace(measurementJSON("finished", ""), `"status":"finished",`, ``, 1),
		"missing results":   strings.Replace(measurementJSON("finished", ""), `,"results":[]`, ``, 1),
		"no timings":        measurementJSON("finished", strings.Replace(finishedResult, `"timings":`, `"x":`, 1)),
		"partial timings":   measurementJSON("finished", strings.Replace(finishedResult, `"total":120,`, ``, 1)),
		"no status code":    measurementJSON("finished", strings.Replace(finishedResult, `"statusCode":200,`, ``, 1)),
		"no result status":  measurementJSON("finished", `{"probe":`+probeJSON+`,"result":{}}`),
		"wrong field types": measurementJSON("finished", strings.Replace(finishedResult, `"statusCode":200`, `"statusCode":"200"`, 1)),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			srv := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, http.StatusOK, body)
			})
			_, err := newClient(t, srv, nil).Measurement(context.Background(), testID)
			if !errors.Is(err, ErrMalformedResponse) {
				t.Fatalf("err = %v, want ErrMalformedResponse", err)
			}
		})
	}
}

func TestResponseTooLarge(t *testing.T) {
	srv := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/api/v1/measurements/"+testID)
		w.WriteHeader(http.StatusAccepted)
		io.WriteString(w, `{"id":"`+testID+`","probesCount":1,"pad":"`+strings.Repeat("x", maxSmallBodyBytes)+`"}`)
	})
	_, err := newClient(t, srv, nil).CreateHTTPMeasurement(context.Background(), HTTPMeasurementRequest{Target: "example.com"})
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("err = %v, want ErrResponseTooLarge", err)
	}
}

func TestCancellation(t *testing.T) {
	inProgress := func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, measurementJSON("in-progress", ""))
	}

	t.Run("cancel while waiting between polls", func(t *testing.T) {
		var hits atomic.Int32
		srv := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			inProgress(w, r)
		})
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		_, err := newClient(t, srv, nil).WaitMeasurement(ctx, testID)
		if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrStillInProgress) {
			t.Fatalf("err = %v, want caller deadline", err)
		}
		if n := hits.Load(); n != 1 {
			t.Errorf("requests = %d, want 1", n)
		}
	})

	t.Run("cancel during request", func(t *testing.T) {
		release := make(chan struct{})
		srv := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-release:
			}
		})
		defer close(release)
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(50*time.Millisecond, cancel)
		_, err := newClient(t, srv, nil).Measurement(ctx, testID)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	})

	t.Run("max wait", func(t *testing.T) {
		var hits atomic.Int32
		srv := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			inProgress(w, r)
		})
		c := newClient(t, srv, func(cfg *Config) { cfg.MaxWait = 1200 * time.Millisecond })
		start := time.Now()
		_, err := c.WaitMeasurement(context.Background(), testID)
		if !errors.Is(err, ErrStillInProgress) || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v, want ErrStillInProgress", err)
		}
		// Polls at 0, 500 and 1000 ms: never more than two requests per second.
		if n, elapsed := hits.Load(), time.Since(start); float64(n) > 1+2*elapsed.Seconds() || n > 3 {
			t.Errorf("%d requests in %s", n, elapsed)
		}
	})
}

func TestRedirectRefused(t *testing.T) {
	var foreignHits atomic.Int32
	foreign := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		foreignHits.Add(1)
		if strings.Contains(r.Header.Get("Authorization"), testToken) {
			t.Errorf("token sent to redirect target")
		}
		writeJSON(w, http.StatusOK, measurementJSON("finished", ""))
	})
	for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			srv := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, foreign.URL+r.URL.Path, status)
			})
			c := newClient(t, srv, func(cfg *Config) {
				// The same pool trusts both test servers, so only the redirect
				// policy can prevent the second request.
				cfg.HTTPClient = foreign.Client()
				cfg.HTTPClient.Transport.(*http.Transport).TLSClientConfig.RootCAs.AddCert(srv.Certificate())
				cfg.HTTPClient.CheckRedirect = nil
			})
			if _, err := c.Measurement(context.Background(), testID); !errors.Is(err, ErrRedirect) {
				t.Fatalf("GET err = %v, want ErrRedirect", err)
			}
			if _, err := c.CreateHTTPMeasurement(context.Background(), HTTPMeasurementRequest{Target: "example.com"}); !errors.Is(err, ErrRedirect) {
				t.Fatalf("POST err = %v, want ErrRedirect", err)
			}
		})
	}
	if n := foreignHits.Load(); n != 0 {
		t.Errorf("redirect target received %d requests", n)
	}
}

func TestTokenRedaction(t *testing.T) {
	srv := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		writeJSON(w, http.StatusForbidden, `{"error":{"type":"`+auth+`","message":"bad token `+auth+`","params":{"token":"`+auth+`"}}}`)
	})
	c := newClient(t, srv, nil)
	_, err := c.CreateHTTPMeasurement(context.Background(), HTTPMeasurementRequest{Target: "example.com"})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
	var apiErr *APIError
	errors.As(err, &apiErr)
	for _, s := range []string{err.Error(), fmt.Sprintf("%+v %#v", apiErr, apiErr), fmt.Sprintf("%+v %#v", c, c)} {
		if strings.Contains(s, testToken) {
			t.Errorf("token leaked: %s", s)
		}
	}

	srv.Close()
	_, err = c.Measurement(context.Background(), testID)
	if err == nil || strings.Contains(err.Error(), testToken) {
		t.Errorf("transport error = %v", err)
	}

	noToken := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Header["Authorization"]; ok {
			t.Errorf("Authorization sent without a configured token")
		}
		writeJSON(w, http.StatusOK, measurementJSON("finished", ""))
	})
	if _, err := newClient(t, noToken, func(cfg *Config) { cfg.Token = "" }).Measurement(context.Background(), testID); err != nil {
		t.Fatalf("Measurement without token: %v", err)
	}
}

func TestNewValidation(t *testing.T) {
	insecure := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	cases := map[string]Config{
		"http scheme":       {BaseURL: "http://api.example.com", UserAgent: testUA},
		"userinfo":          {BaseURL: "https://user:pass@api.example.com", UserAgent: testUA},
		"query":             {BaseURL: "https://api.example.com?x=1", UserAgent: testUA},
		"no host":           {BaseURL: "https:///v1", UserAgent: testUA},
		"no user agent":     {BaseURL: "https://api.example.com"},
		"multiline agent":   {BaseURL: "https://api.example.com", UserAgent: "a\r\nX-Evil: 1"},
		"token whitespace":  {BaseURL: "https://api.example.com", UserAgent: testUA, Token: "abc def"},
		"fast polling":      {BaseURL: "https://api.example.com", UserAgent: testUA, PollInterval: 100 * time.Millisecond},
		"negative max wait": {BaseURL: "https://api.example.com", UserAgent: testUA, MaxWait: -time.Second},
		"tls bypass":        {BaseURL: "https://api.example.com", UserAgent: testUA, HTTPClient: insecure},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := New(cfg)
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("err = %v, want ErrInvalidConfig", err)
			}
			if strings.Contains(err.Error(), "pass") {
				t.Errorf("error echoes userinfo: %v", err)
			}
		})
	}

	c, err := New(Config{UserAgent: testUA})
	if err != nil {
		t.Fatalf("defaults: %v", err)
	}
	if c.base.String() != DefaultBaseURL || c.pollInterval != DefaultPollInterval || c.maxWait != DefaultMaxWait || c.http.Timeout != DefaultHTTPTimeout {
		t.Errorf("defaults = %v %s %s %s", c.base, c.pollInterval, c.maxWait, c.http.Timeout)
	}
}

func TestRequestValidation(t *testing.T) {
	var hits atomic.Int32
	srv := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) { hits.Add(1) })
	c := newClient(t, srv, nil)
	cases := map[string]HTTPMeasurementRequest{
		"empty target":      {},
		"url target":        {Target: "https://example.com/"},
		"target with port":  {Target: "example.com:443"},
		"limit too high":    {Target: "example.com", Limit: MaxLimit + 1},
		"negative limit":    {Target: "example.com", Limit: -1},
		"bad protocol":      {Target: "example.com", Protocol: "QUIC"},
		"bad port":          {Target: "example.com", Port: 70000},
		"ip version for ip": {Target: "192.0.2.1", IPVersion: 4},
		"bad ip version":    {Target: "example.com", IPVersion: 5},
		"bad method":        {Target: "example.com", Method: http.MethodPost},
		"relative path":     {Target: "example.com", Path: "health"},
		"query prefix":      {Target: "example.com", Query: "?a=1"},
		"header injection":  {Target: "example.com", Host: "a\r\nb"},
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := c.CreateHTTPMeasurement(context.Background(), req); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("err = %v, want ErrInvalidRequest", err)
			}
		})
	}
	for _, id := range []string{"", "..", "a/b", strings.Repeat("a", maxIDLength+1)} {
		if _, err := c.Measurement(context.Background(), id); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("Measurement(%q) err = %v, want ErrInvalidRequest", id, err)
		}
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("invalid requests reached the server %d times", n)
	}
}
