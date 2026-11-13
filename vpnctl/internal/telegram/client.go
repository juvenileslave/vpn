package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"time"
)

const (
	// DefaultBaseURL is the official Telegram Bot API endpoint.
	DefaultBaseURL = "https://api.telegram.org"

	// MaxUpdatesLimit is the largest getUpdates limit accepted by the Bot API.
	MaxUpdatesLimit = 100

	// MaxPollTimeout is the longest getUpdates long-poll wait this client sends.
	MaxPollTimeout = 60 * time.Second

	// DefaultMaxResponseBytes bounds a decoded Bot API response.
	DefaultMaxResponseBytes int64 = 4 << 20

	maxPollSeconds = 60
)

var (
	tokenPattern  = regexp.MustCompile(`^[0-9]{1,19}:[A-Za-z0-9_-]{1,128}$`)
	methodPattern = regexp.MustCompile(`^[a-zA-Z]{1,32}$`)
)

// Client is a concurrent-safe Telegram Bot API client.
type Client struct {
	base     *url.URL
	token    string
	http     *http.Client
	maxBytes int64
}

// Option customises a Client.
type Option func(*Client) error

// WithBaseURL replaces the official Bot API endpoint. An http URL is accepted
// only for a loopback host, for a self-hosted Bot API server or a test fake.
func WithBaseURL(base *url.URL) Option {
	return func(c *Client) error {
		u, err := normalizeBase(base)
		if err != nil {
			return err
		}
		c.base = u
		return nil
	}
}

// WithMaxResponseBytes sets the maximum accepted response body size.
func WithMaxResponseBytes(n int64) Option {
	return func(c *Client) error {
		if n <= 0 {
			return fmt.Errorf("%w: max response bytes must be positive", ErrInvalidConfig)
		}
		c.maxBytes = n
		return nil
	}
}

// New returns a client for token. The token format is checked before any
// request, so it cannot inject path segments. httpClient is required and is
// copied; redirects are not followed, because the request URL contains the
// token. New performs no network I/O.
func New(token string, httpClient *http.Client, opts ...Option) (*Client, error) {
	if !tokenPattern.MatchString(token) {
		return nil, fmt.Errorf("%w: bot token must look like <digits>:<secret>", ErrInvalidConfig)
	}
	if httpClient == nil {
		return nil, fmt.Errorf("%w: HTTP client is required", ErrInvalidConfig)
	}
	if t, ok := httpClient.Transport.(*http.Transport); ok && t.TLSClientConfig != nil && t.TLSClientConfig.InsecureSkipVerify {
		return nil, fmt.Errorf("%w: TLS certificate verification must not be disabled", ErrInvalidConfig)
	}
	base, err := normalizeBase(&url.URL{Scheme: "https", Host: "api.telegram.org"})
	if err != nil {
		return nil, err
	}
	hc := *httpClient
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	c := &Client{base: base, token: token, http: &hc, maxBytes: DefaultMaxResponseBytes}
	for _, opt := range opts {
		if err := opt(c); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func normalizeBase(base *url.URL) (*url.URL, error) {
	if base == nil {
		return nil, fmt.Errorf("%w: base URL is required", ErrInvalidConfig)
	}
	if base.Opaque != "" {
		return nil, fmt.Errorf("%w: base URL must be hierarchical", ErrInvalidConfig)
	}
	switch base.Scheme {
	case "https":
	case "http":
		host := base.Hostname()
		if !isLoopbackHost(host) {
			return nil, fmt.Errorf("%w: http base URL must use a loopback host", ErrInvalidConfig)
		}
	default:
		return nil, fmt.Errorf("%w: base URL must use https or loopback http", ErrInvalidConfig)
	}
	switch {
	case base.Hostname() == "":
		return nil, fmt.Errorf("%w: base URL must have a host", ErrInvalidConfig)
	case base.User != nil:
		return nil, fmt.Errorf("%w: base URL must not contain userinfo", ErrInvalidConfig)
	case base.Path != "" && base.Path != "/":
		return nil, fmt.Errorf("%w: base URL must not contain a path", ErrInvalidConfig)
	case base.RawQuery != "" || base.ForceQuery || base.Fragment != "":
		return nil, fmt.Errorf("%w: base URL must not contain a query or fragment", ErrInvalidConfig)
	}
	u := *base
	u.Path = ""
	u.RawPath = ""
	u.User = nil
	return &u, nil
}

func isLoopbackHost(host string) bool {
	if host == "" {
		return false
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.IsLoopback()
	}
	return host == "localhost"
}

// String hides the token from fmt verbs such as %v and %+v.
func (c *Client) String() string { return "telegram.Client{token: redacted}" }

// GoString hides the token from %#v.
func (c *Client) GoString() string { return c.String() }

// User is a Telegram user or bot.
type User struct {
	ID       int64
	IsBot    bool
	Username string
}

// Chat is the chat a message belongs to.
type Chat struct {
	ID    int64
	Type  string
	Title string
}

// Chat type values used by the bot.
const (
	ChatPrivate    = "private"
	ChatGroup      = "group"
	ChatSupergroup = "supergroup"
	ChatChannel    = "channel"
)

// Message is one incoming message. From and Chat are nil when the update did
// not carry them.
type Message struct {
	ID   int64
	From *User
	Chat *Chat
	Text string
	Date time.Time
}

// Update is one getUpdates entry. Message is nil for updates the bot ignores.
type Update struct {
	ID      int64
	Message *Message
}

// UpdatesRequest holds the getUpdates parameters.
type UpdatesRequest struct {
	// Offset is the first update ID to return; 0 requests all pending updates.
	Offset int64
	// Limit must be from 1 through MaxUpdatesLimit.
	Limit int
	// Timeout is the long-poll wait; 0 requests a short poll.
	Timeout time.Duration
}

// GetMe validates the token and returns the bot identity.
func (c *Client) GetMe(ctx context.Context) (User, error) {
	const method = "getMe"
	raw, err := c.call(ctx, method, http.MethodGet, nil, nil)
	if err != nil {
		return User{}, err
	}
	var w struct {
		ID       *int64  `json:"id"`
		IsBot    *bool   `json:"is_bot"`
		Username *string `json:"username"`
	}
	if err := decodeJSON(raw, &w, "getMe result"); err != nil {
		return User{}, err
	}
	if w.ID == nil || *w.ID <= 0 || w.IsBot == nil || !*w.IsBot {
		return User{}, malformed("getMe result: missing bot identity")
	}
	u := User{ID: *w.ID, IsBot: true}
	if w.Username != nil {
		u.Username = *w.Username
	}
	return u, nil
}

// GetUpdates returns pending updates. Only message updates are requested.
func (c *Client) GetUpdates(ctx context.Context, req UpdatesRequest) ([]Update, error) {
	const method = "getUpdates"
	if req.Offset < 0 {
		return nil, fmt.Errorf("telegram: %s: %w: offset must not be negative", method, ErrInvalidArgument)
	}
	if req.Limit < 1 || req.Limit > MaxUpdatesLimit {
		return nil, fmt.Errorf("telegram: %s: %w: limit must be between 1 and %d", method, ErrInvalidArgument, MaxUpdatesLimit)
	}
	if req.Timeout < 0 || req.Timeout > MaxPollTimeout {
		return nil, fmt.Errorf("telegram: %s: %w: timeout must be between 0 and %s", method, ErrInvalidArgument, MaxPollTimeout)
	}
	q := url.Values{}
	q.Set("offset", strconv.FormatInt(req.Offset, 10))
	q.Set("limit", strconv.Itoa(req.Limit))
	q.Set("timeout", strconv.Itoa(int(req.Timeout/time.Second)))
	q.Set("allowed_updates", `["message"]`)
	raw, err := c.call(ctx, method, http.MethodGet, q, nil)
	if err != nil {
		return nil, err
	}
	var items []json.RawMessage
	if err := decodeJSON(raw, &items, "getUpdates result"); err != nil {
		return nil, err
	}
	updates := make([]Update, 0, len(items))
	for _, item := range items {
		var head struct {
			UpdateID *int64 `json:"update_id"`
		}
		if err := json.Unmarshal(item, &head); err != nil || head.UpdateID == nil || *head.UpdateID <= 0 {
			// Without a usable update ID the bot cannot advance its offset.
			continue
		}
		u := Update{ID: *head.UpdateID}
		var w struct {
			Message *wireMessage `json:"message"`
		}
		if err := json.Unmarshal(item, &w); err == nil && w.Message != nil {
			u.Message = w.Message.message()
		}
		updates = append(updates, u)
	}
	return updates, nil
}

// SendMessage sends a plain-text message. text must be non-empty and fit in
// MaxMessageUnits UTF-16 code units; call Truncate to shorten longer output.
func (c *Client) SendMessage(ctx context.Context, chatID int64, text string) error {
	const method = "sendMessage"
	if chatID == 0 {
		return fmt.Errorf("telegram: %s: %w: chat ID must be non-zero", method, ErrInvalidArgument)
	}
	if text == "" {
		return fmt.Errorf("telegram: %s: %w: text must not be empty", method, ErrInvalidArgument)
	}
	if n := UTF16Length(text); n > MaxMessageUnits {
		return fmt.Errorf("telegram: %s: %w: text has %d UTF-16 units, limit is %d", method, ErrInvalidArgument, n, MaxMessageUnits)
	}
	payload := struct {
		ChatID                int64  `json:"chat_id"`
		Text                  string `json:"text"`
		DisableWebPagePreview bool   `json:"disable_web_page_preview"`
	}{ChatID: chatID, Text: text, DisableWebPagePreview: true}
	if _, err := c.call(ctx, method, http.MethodPost, nil, payload); err != nil {
		return err
	}
	return nil
}

type wireUser struct {
	ID       *int64  `json:"id"`
	IsBot    *bool   `json:"is_bot"`
	Username *string `json:"username"`
}

type wireChat struct {
	ID    *int64  `json:"id"`
	Type  *string `json:"type"`
	Title *string `json:"title"`
}

type wireMessage struct {
	MessageID *int64     `json:"message_id"`
	From      *wireUser  `json:"from"`
	Chat      *wireChat  `json:"chat"`
	Text      *string    `json:"text"`
	Date      *time.Time `json:"date"`
}

func (w *wireMessage) message() *Message {
	m := &Message{}
	if w.MessageID != nil {
		m.ID = *w.MessageID
	}
	if w.From != nil && w.From.ID != nil {
		m.From = &User{ID: *w.From.ID}
		if w.From.IsBot != nil {
			m.From.IsBot = *w.From.IsBot
		}
		if w.From.Username != nil {
			m.From.Username = *w.From.Username
		}
	}
	if w.Chat != nil && w.Chat.ID != nil && w.Chat.Type != nil {
		m.Chat = &Chat{ID: *w.Chat.ID, Type: *w.Chat.Type}
		if w.Chat.Title != nil {
			m.Chat.Title = *w.Chat.Title
		}
	}
	if w.Text != nil {
		m.Text = *w.Text
	}
	if w.Date != nil {
		m.Date = *w.Date
	}
	return m
}

type envelope struct {
	OK         bool            `json:"ok"`
	Result     json.RawMessage `json:"result"`
	ErrorCode  int             `json:"error_code"`
	Parameters *struct {
		RetryAfter int `json:"retry_after"`
	} `json:"parameters"`
}

func (c *Client) call(ctx context.Context, method, httpMethod string, query url.Values, payload any) (json.RawMessage, error) {
	if ctx == nil {
		return nil, fmt.Errorf("telegram: %s: %w: context is required", method, ErrInvalidArgument)
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, fmt.Errorf("telegram: %s: %w", method, ctxErr)
	}
	if !methodPattern.MatchString(method) {
		return nil, fmt.Errorf("telegram: %s: %w: invalid method name", method, ErrInvalidArgument)
	}
	u := *c.base
	u.Path = "/bot" + c.token + "/" + method
	u.RawQuery = query.Encode()

	var requestBody io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("telegram: %s: %w: encode request", method, ErrInvalidArgument)
		}
		requestBody = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, httpMethod, u.String(), requestBody)
	if err != nil {
		return nil, fmt.Errorf("telegram: %s: %w: build request", method, ErrInvalidArgument)
	}
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			// url.Error repeats the request URL, which contains the token.
			err = uerr.Err
		}
		if ctxErr := ctx.Err(); ctxErr != nil && !errors.Is(err, ctxErr) {
			err = fmt.Errorf("%w (%w)", ctxErr, err)
		}
		return nil, fmt.Errorf("telegram: %s: %w", method, err)
	}
	defer resp.Body.Close()

	if resp.ContentLength > c.maxBytes {
		return nil, fmt.Errorf("telegram: %s: %w (limit %d bytes)", method, ErrResponseTooLarge, c.maxBytes)
	}
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBytes+1))
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("telegram: %s: %w", method, ctxErr)
		}
		return nil, fmt.Errorf("telegram: %s: read response: %w", method, err)
	}
	if int64(len(respBody)) > c.maxBytes {
		return nil, fmt.Errorf("telegram: %s: %w (limit %d bytes)", method, ErrResponseTooLarge, c.maxBytes)
	}

	var env envelope
	decodeErr := decodeJSON(respBody, &env, "envelope")
	success := resp.StatusCode >= 200 && resp.StatusCode <= 299
	if !success || (decodeErr == nil && !env.OK) {
		return nil, newError(method, resp, &env, decodeErr)
	}
	if decodeErr != nil {
		return nil, fmt.Errorf("telegram: %s: %w", method, decodeErr)
	}
	if mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		return nil, fmt.Errorf("telegram: %s: %w: content type is not application/json", method, ErrMalformedResponse)
	}
	if len(env.Result) == 0 || string(env.Result) == "null" {
		return nil, fmt.Errorf("telegram: %s: %w", method, malformed("envelope: missing result"))
	}
	return env.Result, nil
}

func newError(method string, resp *http.Response, env *envelope, decodeErr error) error {
	e := &Error{Method: method, StatusCode: resp.StatusCode}
	if decodeErr == nil {
		e.Code = env.ErrorCode
		if env.Parameters != nil && env.Parameters.RetryAfter > 0 {
			e.RetryAfter = time.Duration(env.Parameters.RetryAfter) * time.Second
		}
	}
	if e.RetryAfter == 0 {
		if secs, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && secs > 0 {
			e.RetryAfter = time.Duration(secs) * time.Second
		}
	}
	return e
}

// decodeJSON decodes exactly one JSON value. Errors describe the problem
// without quoting the response content.
func decodeJSON(data []byte, v any, what string) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(v); err != nil {
		var syn *json.SyntaxError
		var typ *json.UnmarshalTypeError
		switch {
		case errors.Is(err, io.EOF):
			return malformed("%s: empty body", what)
		case errors.Is(err, io.ErrUnexpectedEOF):
			return malformed("%s: truncated JSON", what)
		case errors.As(err, &syn):
			return malformed("%s: invalid JSON at offset %d", what, syn.Offset)
		case errors.As(err, &typ):
			if typ.Field != "" {
				return malformed("%s: field %q has an unexpected type", what, typ.Field)
			}
			return malformed("%s: unexpected JSON type", what)
		default:
			return malformed("%s: invalid value", what)
		}
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return malformed("%s: unexpected data after JSON value", what)
	}
	return nil
}
