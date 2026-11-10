package remnawave

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testToken = "test-token-7f3a9c"

// Distinctive values the client must never surface.
const (
	secretTrojan   = "trojan-secret-41b2"
	secretSS       = "ss-secret-9d0e"
	secretVless    = "0f1e2d3c-4b5a-4968-8776-655443322110"
	secretShort    = "shortsecret77"
	secretSubURL   = "https://sub.example.test/shortsecret77"
	secretEmail    = "person@example.test"
	secretProxyURL = "http://proxyuser:proxypass@proxy.example.test:8080"
	secretAddress  = "203.0.113.77"
	secretMessage  = "internal failure detail 5c1e"
)

// userJSON renders a user as returned by Remnawave 3.4.10, including every
// secret-bearing field. onlineAt is inserted verbatim: a JSON value or "" to
// omit the key.
func userJSON(id int, onlineAt string) string {
	online := ""
	if onlineAt != "" {
		online = `"onlineAt": ` + onlineAt + `,`
	}
	return fmt.Sprintf(`{
		"id": %d,
		"shortUuid": %q,
		"username": "user-%d",
		"status": "ACTIVE",
		"trafficLimitBytes": 107374182400,
		"trafficLimitStrategy": "MONTH",
		"expireAt": "2027-01-02T03:04:05.000Z",
		"telegramId": null,
		"email": %q,
		"description": null,
		"tag": null,
		"hwidDeviceLimit": null,
		"externalSquadUuid": null,
		"trojanPassword": %q,
		"vlessUuid": %q,
		"ssPassword": %q,
		"lastTriggeredThreshold": 0,
		"subRevokedAt": null,
		"lastTrafficResetAt": null,
		"createdAt": "2026-01-01T00:00:00.000Z",
		"updatedAt": "2026-01-01T00:00:00.000Z",
		"subscriptionUrl": %q,
		"activeInternalSquads": [{"uuid": "00000000-0000-4000-8000-0000000000aa", "name": "Default"}],
		"userTraffic": {
			"usedTrafficBytes": %d,
			"lifetimeUsedTrafficBytes": 5000000000,
			%s
			"firstConnectedAt": null,
			"lastConnectedNodeUuid": null
		},
		"futureField": {"nested": [1, 2, 3]}
	}`, id, secretShort, id, secretEmail, secretTrojan, secretVless, secretSS, secretSubURL, id*1000, online)
}

func nodeJSON(uuid string, connected, disabled bool, used string) string {
	return fmt.Sprintf(`{
		"uuid": %q, "id": 1, "name": "exit-%s", "address": %q, "port": 2222,
		"proxyUrl": %q, "isConnected": %t, "isDisabled": %t, "isConnecting": false,
		"lastStatusChange": null, "lastStatusMessage": %q,
		"isTrafficTrackingActive": false, "trafficResetDay": null,
		"trafficLimitBytes": null, "trafficUsedBytes": %s, "notifyPercent": null,
		"viewPosition": 1, "countryCode": "NL", "consumptionMultiplier": 1,
		"nodeConsumptionMultiplier": 1, "tags": [], "integrationUuids": [], "ips": [],
		"createdAt": "2026-01-01T00:00:00.000Z", "updatedAt": "2026-01-01T00:00:00.000Z",
		"configProfile": {"activeConfigProfileUuid": null, "activeInbounds": []},
		"providerUuid": null, "provider": null, "activePluginUuid": null,
		"system": null, "versions": null, "xrayUptime": 0, "usersOnline": 3, "note": null
	}`, uuid, uuid[len(uuid)-1:], secretAddress, secretProxyURL, connected, disabled, secretMessage, used)
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// newServer starts a TLS server whose handler requires the bearer token,
// like the panel does, and returns a client that trusts its certificate.
func newServer(t *testing.T, basePath string, h http.HandlerFunc, opts ...Option) (*Client, *httptest.Server) {
	t.Helper()
	prefix := strings.TrimSuffix(basePath, "/")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			writeJSON(w, http.StatusUnauthorized, `{"message":"Unauthorized","errorCode":"E401"}`)
			return
		}
		if !strings.HasPrefix(r.URL.Path, prefix+"/api/") {
			writeJSON(w, http.StatusNotFound, `{"message":"Cannot GET","errorCode":"E000"}`)
			return
		}
		r.URL.Path = strings.TrimPrefix(r.URL.Path, prefix)
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	return newClient(t, srv, basePath, testToken, opts...), srv
}

func newClient(t *testing.T, srv *httptest.Server, basePath, token string, opts ...Option) *Client {
	t.Helper()
	u, err := url.Parse(srv.URL + basePath)
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(u, token, srv.Client(), opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func assertNoLeak(t *testing.T, s string) {
	t.Helper()
	for _, secret := range []string{testToken, secretTrojan, secretSS, secretVless, secretShort,
		secretSubURL, secretEmail, secretProxyURL, secretAddress, secretMessage} {
		if strings.Contains(s, secret) {
			t.Errorf("output leaks %q: %s", secret, s)
		}
	}
}

func TestListUsersPagination(t *testing.T) {
	const total = 5
	c, _ := newServer(t, "/panel", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/users" {
			writeJSON(w, http.StatusNotFound, `{"errorCode":"E000"}`)
			return
		}
		start, err1 := strconv.Atoi(r.URL.Query().Get("start"))
		size, err2 := strconv.Atoi(r.URL.Query().Get("size"))
		if err1 != nil || err2 != nil || start < 0 || size < 1 || size > 1000 {
			writeJSON(w, http.StatusBadRequest, `{"errorCode":"E000"}`)
			return
		}
		var items []string
		for i := start; i < start+size && i < total; i++ {
			items = append(items, userJSON(i+1, `"2026-11-01T10:00:00.000Z"`))
		}
		writeJSON(w, http.StatusOK, `{"response":{"users":[`+strings.Join(items, ",")+`],"total":`+strconv.Itoa(total)+`}}`)
	})

	var ids []int64
	for start := 0; ; start += 2 {
		page, err := c.ListUsers(context.Background(), start, 2)
		if err != nil {
			t.Fatalf("ListUsers(%d): %v", start, err)
		}
		if page.Total != total {
			t.Fatalf("Total = %d, want %d", page.Total, total)
		}
		if len(page.Users) == 0 {
			if start < total {
				t.Fatalf("empty page at start=%d", start)
			}
			break
		}
		for _, u := range page.Users {
			ids = append(ids, u.ID)
		}
	}
	if fmt.Sprint(ids) != "[1 2 3 4 5]" {
		t.Fatalf("collected ids %v", ids)
	}

	page, err := c.ListUsers(context.Background(), 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	u := page.Users[0]
	wantExpire := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
	if u.ID != 2 || u.Username != "user-2" || u.Status != UserStatusActive || !u.Status.Known() ||
		!u.ExpireAt.Equal(wantExpire) || u.Usage.UsedBytes != 2000 ||
		u.Usage.LimitBytes != 107374182400 || u.Usage.LifetimeUsedBytes != 5000000000 {
		t.Fatalf("unexpected user %+v", u)
	}
	if u.OnlineAt == nil || !u.OnlineAt.Equal(time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)) {
		t.Fatalf("OnlineAt = %v", u.OnlineAt)
	}
	if u.FirstConnectedAt != nil {
		t.Fatalf("FirstConnectedAt = %v, want nil", u.FirstConnectedAt)
	}
	assertNoLeak(t, fmt.Sprintf("%+v %#v", page, page))
}

func TestListUsersEmptyPage(t *testing.T) {
	c, _ := newServer(t, "", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, `{"response":{"users":[],"total":0}}`)
	})
	page, err := c.ListUsers(context.Background(), 0, 25)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 0 || page.Users == nil || len(page.Users) != 0 {
		t.Fatalf("page = %#v", page)
	}
}

func TestListUsersRejectsInvalidArgumentsWithoutRequest(t *testing.T) {
	var hits atomic.Int32
	c, _ := newServer(t, "", func(w http.ResponseWriter, r *http.Request) { hits.Add(1) })
	for _, tc := range []struct{ start, size int }{{-1, 10}, {0, 0}, {0, 1001}} {
		if _, err := c.ListUsers(context.Background(), tc.start, tc.size); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("ListUsers(%d, %d) err = %v", tc.start, tc.size, err)
		}
	}
	if _, err := c.User(context.Background(), 0); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("User(0) err = %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("server received %d requests", hits.Load())
	}
}

func TestUserNullableTimestamps(t *testing.T) {
	bodies := map[string]string{
		"/api/users/1": userJSON(1, `null`),
		"/api/users/2": userJSON(2, ``),
		"/api/users/3": userJSON(3, `"2026-11-09T08:07:06.5Z"`),
	}
	c, _ := newServer(t, "/a/b/", func(w http.ResponseWriter, r *http.Request) {
		body, ok := bodies[r.URL.Path]
		if !ok {
			writeJSON(w, http.StatusNotFound, `{"errorCode":"A063"}`)
			return
		}
		writeJSON(w, http.StatusOK, `{"response":`+body+`}`)
	})
	for id, wantOnline := range map[int64]bool{1: false, 2: false, 3: true} {
		u, err := c.User(context.Background(), id)
		if err != nil {
			t.Fatalf("User(%d): %v", id, err)
		}
		if u.ID != id || (u.OnlineAt != nil) != wantOnline {
			t.Errorf("User(%d) = %+v", id, u)
		}
		assertNoLeak(t, fmt.Sprintf("%+v %#v", u, u))
	}
}

func TestListNodes(t *testing.T) {
	c, _ := newServer(t, "", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/nodes" {
			writeJSON(w, http.StatusNotFound, `{"errorCode":"A011"}`)
			return
		}
		writeJSON(w, http.StatusOK, `{"response":[`+
			nodeJSON("00000000-0000-4000-8000-000000000001", true, false, "123456")+`,`+
			nodeJSON("00000000-0000-4000-8000-000000000002", false, false, "null")+`,`+
			nodeJSON("00000000-0000-4000-8000-000000000003", true, true, "null")+`]}`)
	})
	nodes, err := c.ListNodes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 3 {
		t.Fatalf("got %d nodes", len(nodes))
	}
	want := []NodeStatus{NodeStatusConnected, NodeStatusDisconnected, NodeStatusDisabled}
	for i, n := range nodes {
		if n.Status != want[i] || n.CountryCode != "NL" || n.UsersOnline != 3 || n.LastStatusChange != nil {
			t.Errorf("nodes[%d] = %+v", i, n)
		}
	}
	if nodes[0].Usage.UsedBytes == nil || *nodes[0].Usage.UsedBytes != 123456 || nodes[0].Usage.LimitBytes != nil {
		t.Errorf("nodes[0].Usage = %+v", nodes[0].Usage)
	}
	if nodes[1].Usage.UsedBytes != nil {
		t.Errorf("nodes[1].Usage.UsedBytes = %v, want nil", *nodes[1].Usage.UsedBytes)
	}
	assertNoLeak(t, fmt.Sprintf("%+v %#v", nodes, nodes))
}

func TestMalformedResponses(t *testing.T) {
	user := userJSON(1, `null`)
	cases := map[string]struct {
		path, contentType, body string
	}{
		"truncated":         {"/api/users", "application/json", `{"response":{"users":[` + user[:200]},
		"invalid JSON":      {"/api/users", "application/json", `{"response": nope}`},
		"empty body":        {"/api/users", "application/json", ``},
		"trailing data":     {"/api/users", "application/json", `{"response":{"users":[],"total":0}} {}`},
		"no envelope":       {"/api/users", "application/json", `{"users":[],"total":0}`},
		"null response":     {"/api/users", "application/json", `{"response":null}`},
		"array envelope":    {"/api/users", "application/json", `[]`},
		"users null":        {"/api/users", "application/json", `{"response":{"users":null,"total":0}}`},
		"missing total":     {"/api/users", "application/json", `{"response":{"users":[]}}`},
		"wrong total type":  {"/api/users", "application/json", `{"response":{"users":[],"total":"5"}}`},
		"fractional total":  {"/api/users", "application/json", `{"response":{"users":[],"total":1.5}}`},
		"missing user id":   {"/api/users", "application/json", `{"response":{"users":[{"username":"x"}],"total":1}}`},
		"bad timestamp":     {"/api/users/1", "application/json", `{"response":` + strings.Replace(user, "2027-01-02T03:04:05.000Z", secretMessage, 1) + `}`},
		"missing traffic":   {"/api/users/1", "application/json", `{"response":{"id":1,"username":"u","status":"ACTIVE","expireAt":"2027-01-01T00:00:00Z","trafficLimitBytes":0}}`},
		"html":              {"/api/users", "text/html", `<html>` + secretMessage + `</html>`},
		"nodes not array":   {"/api/nodes", "application/json", `{"response":{"uuid":"x"}}`},
		"node missing flag": {"/api/nodes", "application/json", `{"response":[{"uuid":"x","name":"n","isConnected":true}]}`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c, _ := newServer(t, "", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				_, _ = w.Write([]byte(tc.body))
			})
			var err error
			switch tc.path {
			case "/api/users":
				_, err = c.ListUsers(context.Background(), 0, 10)
			case "/api/users/1":
				_, err = c.User(context.Background(), 1)
			default:
				_, err = c.ListNodes(context.Background())
			}
			if !errors.Is(err, ErrMalformedResponse) {
				t.Fatalf("err = %v, want ErrMalformedResponse", err)
			}
			assertNoLeak(t, err.Error())
		})
	}
}

func TestHTTPErrors(t *testing.T) {
	cases := []struct {
		status   int
		body     string
		sentinel error
		code     string
	}{
		{400, `{"message":"` + secretMessage + `","errorCode":"A063"}`, ErrBadRequest, "A063"},
		{401, `{"message":"` + secretMessage + `","errorCode":"E401"}`, ErrUnauthorized, "E401"},
		{403, `{"message":"Forbidden","errorCode":"E403"}`, ErrForbidden, "E403"},
		{404, `{"timestamp":"2026-11-10T00:00:00Z","path":"/api/users/9","message":"User not found","errorCode":"A025"}`, ErrNotFound, "A025"},
		{409, `{"errorCode":"A999"}`, ErrUnexpectedStatus, "A999"},
		{429, `{"errorCode":"` + secretMessage + `"}`, ErrRateLimited, ""},
		{500, `{"message":"Internal server error","errorCode":"E500"}`, ErrServer, "E500"},
		{502, `<html>` + secretMessage + `</html>`, ErrServer, ""},
		{503, `{"errorCode":"E500"` + strings.Repeat(" ", 100<<10) + `}`, ErrServer, ""},
	}
	for _, tc := range cases {
		t.Run(strconv.Itoa(tc.status), func(t *testing.T) {
			c, _ := newServer(t, "", func(w http.ResponseWriter, r *http.Request) {
				if tc.status == 429 {
					w.Header().Set("Retry-After", "7")
				}
				ct := "application/json"
				if strings.HasPrefix(tc.body, "<") {
					ct = "text/html"
				}
				w.Header().Set("Content-Type", ct)
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			})
			_, err := c.User(context.Background(), 9)
			if !errors.Is(err, tc.sentinel) {
				t.Fatalf("err = %v, want %v", err, tc.sentinel)
			}
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != tc.status || apiErr.Code != tc.code {
				t.Fatalf("APIError = %+v", apiErr)
			}
			if tc.status == 429 && apiErr.RetryAfter != 7*time.Second {
				t.Errorf("RetryAfter = %v", apiErr.RetryAfter)
			}
			assertNoLeak(t, err.Error())
		})
	}
}

func TestWrongTokenIsUnauthorized(t *testing.T) {
	_, srv := newServer(t, "", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, `{"response":[]}`)
	})
	c := newClient(t, srv, "", "wrong-token")
	if _, err := c.ListNodes(context.Background()); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v", err)
	}
}

func TestResponseBodyLimit(t *testing.T) {
	big := `{"response":{"users":[],"total":0,"pad":"` + strings.Repeat("x", 4096) + `"}}`
	for _, chunked := range []bool{false, true} {
		t.Run(fmt.Sprintf("chunked=%t", chunked), func(t *testing.T) {
			c, _ := newServer(t, "", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if !chunked {
					w.Header().Set("Content-Length", strconv.Itoa(len(big)))
				}
				for i := 0; i < len(big); i += 512 {
					_, _ = w.Write([]byte(big[i:min(i+512, len(big))]))
					if chunked {
						w.(http.Flusher).Flush()
					}
				}
			}, WithMaxResponseBytes(1024))
			if _, err := c.ListUsers(context.Background(), 0, 1); !errors.Is(err, ErrResponseTooLarge) {
				t.Fatalf("err = %v, want ErrResponseTooLarge", err)
			}
		})
	}

	c, _ := newServer(t, "", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, big)
	}, WithMaxResponseBytes(int64(len(big))))
	if _, err := c.ListUsers(context.Background(), 0, 1); err != nil {
		t.Fatalf("body at the limit: %v", err)
	}
}

func TestCancellationAndDeadline(t *testing.T) {
	started := make(chan struct{}, 2)
	c, _ := newServer(t, "", func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-r.Context().Done()
	})

	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-started; cancel() }()
	if _, err := c.ListNodes(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: err = %v", err)
	}

	ctx, cancel2 := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel2()
	begin := time.Now()
	_, err := c.ListUsers(ctx, 0, 1)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline: err = %v", err)
	}
	if time.Since(begin) > 5*time.Second {
		t.Fatalf("deadline not respected: %v", time.Since(begin))
	}

	done, cancel3 := context.WithCancel(context.Background())
	cancel3()
	if _, err := c.User(done, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled: err = %v", err)
	}
}

func TestRedirectIsRefused(t *testing.T) {
	var targetHits atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		writeJSON(w, http.StatusOK, `{"response":[]}`)
	}))
	defer target.Close()

	for _, status := range []int{301, 302, 307, 308} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			c, _ := newServer(t, "", func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target.URL+"/api/nodes?leak="+secretMessage, status)
			})
			_, err := c.ListNodes(context.Background())
			if !errors.Is(err, ErrRedirect) {
				t.Fatalf("err = %v, want ErrRedirect", err)
			}
			if strings.Contains(err.Error(), target.URL) {
				t.Errorf("error repeats redirect location: %v", err)
			}
			assertNoLeak(t, err.Error())
		})
	}
	if n := targetHits.Load(); n != 0 {
		t.Fatalf("redirect target received %d requests", n)
	}
}

func TestTLSVerification(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, `{"response":[]}`)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)

	// A client that does not trust the test CA must fail the handshake.
	c, err := New(u, testToken, &http.Client{Transport: &http.Transport{}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.ListNodes(context.Background())
	if err == nil {
		t.Fatal("untrusted certificate accepted")
	}
	assertNoLeak(t, err.Error())

	insecure := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	if _, err := New(u, testToken, insecure); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("insecure transport: err = %v", err)
	}
}

func TestNewValidation(t *testing.T) {
	good, _ := url.Parse("https://panel.example.test/prefix")
	hc := &http.Client{}
	cases := map[string]struct {
		raw   string
		token string
		hc    *http.Client
	}{
		"http scheme":    {"http://panel.example.test", testToken, hc},
		"no host":        {"https:///api", testToken, hc},
		"userinfo":       {"https://admin:pass-5c1e@panel.example.test", testToken, hc},
		"query":          {"https://panel.example.test/?a=b", testToken, hc},
		"fragment":       {"https://panel.example.test/#x", testToken, hc},
		"relative":       {"/panel", testToken, hc},
		"empty token":    {good.String(), "", hc},
		"token newline":  {good.String(), "abc\r\nX-Evil: 1", hc},
		"token space":    {good.String(), "Bearer abc", hc},
		"nil httpclient": {good.String(), testToken, nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			u, err := url.Parse(tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			_, err = New(u, tc.token, tc.hc)
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("err = %v, want ErrInvalidConfig", err)
			}
			assertNoLeak(t, err.Error())
			if strings.Contains(err.Error(), "pass-5c1e") {
				t.Errorf("error leaks userinfo: %v", err)
			}
		})
	}
	if _, err := New(nil, testToken, hc); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("nil URL: err = %v", err)
	}
	if _, err := New(good, testToken, hc, WithMaxResponseBytes(0)); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("zero limit: err = %v", err)
	}

	c, err := New(good, testToken, hc)
	if err != nil {
		t.Fatal(err)
	}
	if hc.CheckRedirect != nil {
		t.Error("New mutated the caller's http.Client")
	}
	assertNoLeak(t, fmt.Sprintf("%v %+v %#v %s", c, c, c, c))
}
