package telegram

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const testToken = "123456:TEST-fake_token"

func newTestClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	base, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(testToken, &http.Client{}, WithBaseURL(base))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, srv
}

func jsonHandler(t *testing.T, body string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, body)
	}
}

func TestGetMeUsesTokenPathAndHeaders(t *testing.T) {
	var path, method, accept string
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		path, method, accept = r.URL.Path, r.Method, r.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true,"result":{"id":42,"is_bot":true,"username":"vpn_bot"}}`)
	})
	me, err := c.GetMe(context.Background())
	if err != nil {
		t.Fatalf("GetMe: %v", err)
	}
	if want := "/bot" + testToken + "/getMe"; path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
	if method != http.MethodGet || accept != "application/json" {
		t.Errorf("method = %q, accept = %q", method, accept)
	}
	if me.ID != 42 || !me.IsBot || me.Username != "vpn_bot" {
		t.Errorf("bot = %+v", me)
	}
}

func TestGetMeRejectsNonBot(t *testing.T) {
	c, _ := newTestClient(t, jsonHandler(t, `{"ok":true,"result":{"id":42,"is_bot":false}}`))
	if _, err := c.GetMe(context.Background()); !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("err = %v, want ErrMalformedResponse", err)
	}
}

func TestGetUpdatesSendsParametersAndIgnoresMalformedEntries(t *testing.T) {
	var query url.Values
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true,"result":[
			{"update_id":10,"message":{"message_id":1,"from":{"id":7,"is_bot":false,"username":"op"},"chat":{"id":7,"type":"private","title":"dm"},"text":"/help","date":"2026-11-13T10:00:00Z"}},
			{"update_id":11},
			{"update_id":12,"message":{"message_id":2,"from":{"id":"bad"}}},
			{"message":{"message_id":3}},
			{"update_id":13,"message":{"message_id":3,"from":{"id":8},"chat":{"id":-100,"type":"supergroup"}}}
		]}`)
	})
	updates, err := c.GetUpdates(context.Background(), UpdatesRequest{
		Offset: 9, Limit: 100, Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("GetUpdates: %v", err)
	}
	wantQuery := map[string]string{
		"offset": "9", "limit": "100", "timeout": "2", "allowed_updates": `["message"]`,
	}
	for key, want := range wantQuery {
		if got := query.Get(key); got != want {
			t.Errorf("query %s = %q, want %q", key, got, want)
		}
	}
	if len(updates) != 4 {
		t.Fatalf("updates = %+v, want 4 entries", updates)
	}
	ids := []int64{10, 11, 12, 13}
	for i, id := range ids {
		if updates[i].ID != id {
			t.Errorf("updates[%d].ID = %d, want %d", i, updates[i].ID, id)
		}
	}
	msg := updates[0].Message
	if msg == nil || msg.ID != 1 || msg.Text != "/help" || msg.From == nil || msg.From.ID != 7 ||
		msg.Chat == nil || msg.Chat.ID != 7 || msg.Chat.Type != ChatPrivate || msg.Chat.Title != "dm" ||
		!msg.Date.Equal(time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("first message = %+v", msg)
	}
	if updates[1].Message != nil || updates[2].Message != nil {
		t.Errorf("malformed updates must have no message: %+v %+v", updates[1], updates[2])
	}
	if updates[3].Message == nil || updates[3].Message.Text != "" {
		t.Errorf("third message = %+v", updates[3].Message)
	}
}

func TestGetUpdatesValidatesArguments(t *testing.T) {
	c, _ := newTestClient(t, jsonHandler(t, `{"ok":true,"result":[]}`))
	tests := []UpdatesRequest{
		{Offset: -1, Limit: 1},
		{Offset: 0, Limit: 0},
		{Offset: 0, Limit: MaxUpdatesLimit + 1},
		{Offset: 0, Limit: 1, Timeout: -time.Second},
		{Offset: 0, Limit: 1, Timeout: MaxPollTimeout + time.Second},
	}
	for _, req := range tests {
		if _, err := c.GetUpdates(context.Background(), req); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("GetUpdates(%+v) err = %v, want ErrInvalidArgument", req, err)
		}
	}
}

func TestGetUpdatesEmptyResultIsNotNil(t *testing.T) {
	c, _ := newTestClient(t, jsonHandler(t, `{"ok":true,"result":[]}`))
	updates, err := c.GetUpdates(context.Background(), UpdatesRequest{Offset: 0, Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if updates == nil || len(updates) != 0 {
		t.Errorf("updates = %#v, want empty non-nil slice", updates)
	}
}

func TestSendMessagePostsPlainText(t *testing.T) {
	var path, method, contentType string
	var body map[string]any
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		path, method, contentType = r.URL.Path, r.Method, r.Header.Get("Content-Type")
		data, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(data, &body); err != nil {
			t.Errorf("request body is not JSON: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true,"result":{"message_id":5}}`)
	})
	if err := c.SendMessage(context.Background(), -100500, `a <b> & "c"`); err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	if want := "/bot" + testToken + "/sendMessage"; path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
	if method != http.MethodPost || contentType != "application/json" {
		t.Errorf("method = %q, content type = %q", method, contentType)
	}
	if got, ok := body["chat_id"].(float64); !ok || int64(got) != -100500 {
		t.Errorf("chat_id = %v", body["chat_id"])
	}
	if body["text"] != `a <b> & "c"` {
		t.Errorf("text = %v", body["text"])
	}
	if body["disable_web_page_preview"] != true {
		t.Errorf("disable_web_page_preview = %v", body["disable_web_page_preview"])
	}
	if _, ok := body["parse_mode"]; ok {
		t.Error("plain-text messages must not set parse_mode")
	}
}

func TestSendMessageValidatesArguments(t *testing.T) {
	c, _ := newTestClient(t, jsonHandler(t, `{"ok":true,"result":{"message_id":5}}`))
	long := strings.Repeat("a", MaxMessageUnits+1)
	wide := strings.Repeat("😀", MaxMessageUnits/2+1)
	for name, err := range map[string]error{
		"zero chat":      c.SendMessage(context.Background(), 0, "x"),
		"empty text":     c.SendMessage(context.Background(), 1, ""),
		"long text":      c.SendMessage(context.Background(), 1, long),
		"surrogate-wide": c.SendMessage(context.Background(), 1, wide),
	} {
		if !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s err = %v, want ErrInvalidArgument", name, err)
		}
	}
	if err := c.SendMessage(context.Background(), 1, strings.Repeat("a", MaxMessageUnits)); err != nil {
		t.Errorf("text at the limit: %v", err)
	}
}

func TestErrorMapping(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       string
		want       error
		retryAfter time.Duration
	}{
		{"400", 400, `{"ok":false,"error_code":400,"description":"Bad Request"}`, ErrBadRequest, 0},
		{"401", 401, `{"ok":false,"error_code":401,"description":"Unauthorized token 123456:TEST-fake_token"}`, ErrUnauthorized, 0},
		{"403", 403, `{"ok":false,"error_code":403,"description":"Forbidden"}`, ErrForbidden, 0},
		{"404", 404, `{"ok":false,"error_code":404,"description":"Not Found"}`, ErrNotFound, 0},
		{"429", 429, `{"ok":false,"error_code":429,"description":"Too Many Requests","parameters":{"retry_after":3}}`, ErrRateLimited, 3 * time.Second},
		{"429 header", 429, `{"ok":false,"error_code":429}`, ErrRateLimited, 7 * time.Second},
		{"500", 500, `{"ok":false,"error_code":500,"description":"Internal"}`, ErrServer, 0},
		{"503 without json", 503, `upstream`, ErrServer, 0},
		{"200 not ok", 200, `{"ok":false,"error_code":400,"description":"Bad"}`, ErrBadRequest, 0},
		{"302", 302, `{"ok":false,"error_code":302}`, ErrUnexpectedStatus, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if tt.name == "429 header" {
					w.Header().Set("Retry-After", "7")
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				io.WriteString(w, tt.body)
			})
			_, err := c.GetMe(context.Background())
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if strings.Contains(err.Error(), testToken) || strings.Contains(err.Error(), "Unauthorized token") {
				t.Errorf("error leaks server content: %v", err)
			}
			var apiErr *Error
			if errors.As(err, &apiErr) && tt.retryAfter > 0 && apiErr.RetryAfter != tt.retryAfter {
				t.Errorf("retry after = %s, want %s", apiErr.RetryAfter, tt.retryAfter)
			}
		})
	}
}

func TestRedirectIsNotFollowed(t *testing.T) {
	var hits int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
	}))
	defer target.Close()
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	})
	if _, err := c.GetMe(context.Background()); !errors.Is(err, ErrUnexpectedStatus) {
		t.Fatalf("err = %v, want ErrUnexpectedStatus", err)
	}
	if hits != 0 {
		t.Errorf("redirect target was requested %d times", hits)
	}
}

func TestMalformedResponses(t *testing.T) {
	tests := map[string]http.HandlerFunc{
		"not json": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `not json`)
		},
		"trailing data":  jsonHandler(t, `{"ok":true,"result":{}} {"ok":true}`),
		"missing result": jsonHandler(t, `{"ok":true}`),
		"null result":    jsonHandler(t, `{"ok":true,"result":null}`),
		"wrong content type": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, `{"ok":true,"result":{"id":1,"is_bot":true}}`)
		},
		"empty body": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
		},
	}
	for name, handler := range tests {
		t.Run(name, func(t *testing.T) {
			c, _ := newTestClient(t, handler)
			if _, err := c.GetMe(context.Background()); !errors.Is(err, ErrMalformedResponse) {
				t.Fatalf("err = %v, want ErrMalformedResponse", err)
			}
		})
	}
}

func TestResponseTooLarge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true,"result":{"id":1,"is_bot":true,"username":"a very long name"}}`)
	}))
	defer srv.Close()
	base, _ := url.Parse(srv.URL)
	c, err := New(testToken, &http.Client{}, WithBaseURL(base), WithMaxResponseBytes(16))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetMe(context.Background()); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("err = %v, want ErrResponseTooLarge", err)
	}
}

func TestTransportErrorHidesToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	base, _ := url.Parse(srv.URL)
	srv.Close()
	c, err := New(testToken, &http.Client{}, WithBaseURL(base))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.GetMe(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), testToken) {
		t.Fatalf("transport error leaks the token: %v", err)
	}
}

func TestContextCancellation(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.GetMe(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestNewValidatesConfiguration(t *testing.T) {
	loopback, _ := url.Parse("http://127.0.0.1:8081")
	remote, _ := url.Parse("http://bot.example.com")
	withPath, _ := url.Parse("https://bot.example.com/api")
	withUser, _ := url.Parse("https://user:pw@bot.example.com")
	withQuery, _ := url.Parse("https://bot.example.com?x=1")
	for name, token := range map[string]string{
		"empty":     "",
		"no colon":  "123456",
		"space":     "123456:token with space",
		"slash":     "123456:abc/def",
		"long":      "123456:" + strings.Repeat("a", 129),
		"non-digit": "abc:def",
	} {
		if _, err := New(token, &http.Client{}); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s token err = %v, want ErrInvalidConfig", name, err)
		} else if strings.Contains(err.Error(), token) && token != "" {
			t.Errorf("%s token error leaks the token", name)
		}
	}
	if _, err := New(testToken, nil); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("nil client err = %v", err)
	}
	for name, base := range map[string]*url.URL{
		"remote http": remote,
		"path":        withPath,
		"userinfo":    withUser,
		"query":       withQuery,
		"nil":         nil,
	} {
		if _, err := New(testToken, &http.Client{}, WithBaseURL(base)); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s base err = %v, want ErrInvalidConfig", name, err)
		}
	}
	if _, err := New(testToken, &http.Client{}, WithBaseURL(loopback)); err != nil {
		t.Errorf("loopback http base: %v", err)
	}
	insecure := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	if _, err := New(testToken, insecure); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("insecure TLS err = %v, want ErrInvalidConfig", err)
	}
}

func TestClientStringRedactsToken(t *testing.T) {
	c, err := New(testToken, &http.Client{})
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		got := fmt.Sprintf(format, c)
		if strings.Contains(got, testToken) {
			t.Errorf("%s leaks the token: %s", format, got)
		}
	}
}

func TestUTF16LengthAndTruncate(t *testing.T) {
	if got := UTF16Length("abc😀"); got != 5 {
		t.Errorf("UTF16Length = %d, want 5", got)
	}
	if got := Truncate("short", 10); got != "short" {
		t.Errorf("Truncate(short) = %q", got)
	}
	long := strings.Repeat("a", 5000)
	got := Truncate(long, MaxMessageUnits)
	if n := UTF16Length(got); n > MaxMessageUnits {
		t.Errorf("truncated length = %d, limit %d", n, MaxMessageUnits)
	}
	if !strings.HasSuffix(got, TruncationMarker) {
		t.Errorf("truncated text has no marker: %q", got[len(got)-30:])
	}
	emoji := strings.Repeat("😀", 3000)
	got = Truncate(emoji, MaxMessageUnits)
	if n := UTF16Length(got); n > MaxMessageUnits {
		t.Errorf("emoji truncated length = %d", n)
	}
	if !strings.HasSuffix(got, TruncationMarker) {
		t.Error("emoji truncation has no marker")
	}
	if got := Truncate(long, 5); UTF16Length(got) > 5 {
		t.Errorf("tiny limit produced %q", got)
	}
}
