package bot

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/juvenileslave/vpn/vpnctl/internal/config"
	"github.com/juvenileslave/vpn/vpnctl/internal/remnawave"
	"github.com/juvenileslave/vpn/vpnctl/internal/store"
	"github.com/juvenileslave/vpn/vpnctl/internal/telegram"
)

type sentReply struct {
	chatID int64
	text   string
}

type fakeAPI struct {
	mu         sync.Mutex
	me         telegram.User
	meErr      error
	getUpdates func(ctx context.Context, req telegram.UpdatesRequest) ([]telegram.Update, error)
	sendHook   func(ctx context.Context, chatID int64, text string) error
	calls      []telegram.UpdatesRequest
	sent       []sentReply
}

func (f *fakeAPI) GetMe(context.Context) (telegram.User, error) {
	if f.meErr != nil {
		return telegram.User{}, f.meErr
	}
	if f.me.ID == 0 {
		return telegram.User{ID: 1, IsBot: true, Username: "vpn_bot"}, nil
	}
	return f.me, nil
}

func (f *fakeAPI) GetUpdates(ctx context.Context, req telegram.UpdatesRequest) ([]telegram.Update, error) {
	f.mu.Lock()
	f.calls = append(f.calls, req)
	hook := f.getUpdates
	f.mu.Unlock()
	if hook != nil {
		return hook(ctx, req)
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func (f *fakeAPI) SendMessage(ctx context.Context, chatID int64, text string) error {
	f.mu.Lock()
	f.sent = append(f.sent, sentReply{chatID: chatID, text: text})
	hook := f.sendHook
	f.mu.Unlock()
	if hook != nil {
		return hook(ctx, chatID, text)
	}
	return nil
}

func (f *fakeAPI) sentReplies() []sentReply {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]sentReply(nil), f.sent...)
}

func (f *fakeAPI) pollCalls() []telegram.UpdatesRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]telegram.UpdatesRequest(nil), f.calls...)
}

type fakePanel struct {
	nodes    []remnawave.Node
	nodesErr error
	page     remnawave.UsersPage
	usersErr error
	user     remnawave.User
	userErr  error

	mu         sync.Mutex
	nodesCalls int
	usersCalls []struct{ start, size int }
	userCalls  []int64
}

func (f *fakePanel) ListNodes(context.Context) ([]remnawave.Node, error) {
	f.mu.Lock()
	f.nodesCalls++
	f.mu.Unlock()
	return f.nodes, f.nodesErr
}

func (f *fakePanel) ListUsers(_ context.Context, start, size int) (remnawave.UsersPage, error) {
	f.mu.Lock()
	f.usersCalls = append(f.usersCalls, struct{ start, size int }{start, size})
	f.mu.Unlock()
	return f.page, f.usersErr
}

func (f *fakePanel) User(_ context.Context, id int64) (remnawave.User, error) {
	f.mu.Lock()
	f.userCalls = append(f.userCalls, id)
	f.mu.Unlock()
	return f.user, f.userErr
}

type fakeState struct {
	offset   int64
	claimErr error
}

func (s *fakeState) BotOffset(context.Context) (int64, error) { return s.offset, nil }

func (s *fakeState) ClaimBotUpdate(context.Context, int64) (bool, error) {
	return false, s.claimErr
}

func defaultOperators() []config.Operator {
	return []config.Operator{{ID: 7, Role: config.RoleAdmin}}
}

func privateMessage(updateID, userID, chatID int64, text string) telegram.Update {
	return telegram.Update{ID: updateID, Message: &telegram.Message{
		ID:   updateID,
		From: &telegram.User{ID: userID},
		Chat: &telegram.Chat{ID: chatID, Type: telegram.ChatPrivate},
		Text: text,
	}}
}

func newTestBot(t *testing.T, api API, panel Panel, state State, operators []config.Operator, chats []int64) *Bot {
	t.Helper()
	b, err := New(Config{Operators: operators, ChatIDs: chats}, api, panel, state, WithPollTimeout(time.Second))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	b.sleep = func(context.Context, time.Duration) error { return nil }
	return b
}

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(context.Background(), t.TempDir()+"/state.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func batchSource(batches ...[]telegram.Update) func(context.Context, telegram.UpdatesRequest) ([]telegram.Update, error) {
	var mu sync.Mutex
	next := 0
	return func(ctx context.Context, req telegram.UpdatesRequest) ([]telegram.Update, error) {
		mu.Lock()
		if next < len(batches) {
			batch := batches[next]
			next++
			mu.Unlock()
			return batch, nil
		}
		mu.Unlock()
		<-ctx.Done()
		return nil, ctx.Err()
	}
}

func runInBackground(t *testing.T, b *Bot, ctx context.Context) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- b.Run(ctx) }()
	return done
}

func waitFor(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func stopBot(t *testing.T, cancel context.CancelFunc, done <-chan error) error {
	t.Helper()
	cancel()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("bot did not stop after cancellation")
		return nil
	}
}

func TestRunValidatesTokenBeforePolling(t *testing.T) {
	api := &fakeAPI{meErr: &telegram.Error{Method: "getMe", StatusCode: 401}}
	b := newTestBot(t, api, &fakePanel{}, newTestStore(t), defaultOperators(), nil)
	err := b.Run(context.Background())
	if !errors.Is(err, telegram.ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
	if got := api.pollCalls(); len(got) != 0 {
		t.Errorf("getUpdates called %d times after a failed getMe", len(got))
	}
}

func TestUnknownSenderIsConsumedWithoutReply(t *testing.T) {
	api := &fakeAPI{getUpdates: batchSource([]telegram.Update{
		privateMessage(50, 999, 999, "/status"),
	})}
	state := newTestStore(t)
	b := newTestBot(t, api, &fakePanel{}, state, defaultOperators(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := runInBackground(t, b, ctx)
	waitFor(t, "offset persistence", func() bool {
		offset, _ := state.BotOffset(context.Background())
		return offset == 51
	})
	if err := stopBot(t, cancel, done); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := api.sentReplies(); len(got) != 0 {
		t.Errorf("unknown sender received %+v", got)
	}
	if b.ignored != 1 {
		t.Errorf("ignored = %d, want 1", b.ignored)
	}
}

func TestGroupChatRequiresExplicitAllow(t *testing.T) {
	group := telegram.Update{ID: 60, Message: &telegram.Message{
		From: &telegram.User{ID: 7},
		Chat: &telegram.Chat{ID: -100, Type: telegram.ChatSupergroup},
		Text: "/help",
	}}
	api := &fakeAPI{getUpdates: batchSource([]telegram.Update{group})}
	b := newTestBot(t, api, &fakePanel{}, newTestStore(t), defaultOperators(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := runInBackground(t, b, ctx)
	waitFor(t, "group update consumption", func() bool { return len(api.pollCalls()) >= 1 })
	time.Sleep(20 * time.Millisecond)
	if err := stopBot(t, cancel, done); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := api.sentReplies(); len(got) != 0 {
		t.Errorf("group chat received %+v without being configured", got)
	}

	api = &fakeAPI{getUpdates: batchSource([]telegram.Update{group})}
	b = newTestBot(t, api, &fakePanel{}, newTestStore(t), defaultOperators(), []int64{-100})
	ctx, cancel = context.WithCancel(context.Background())
	done = runInBackground(t, b, ctx)
	waitFor(t, "configured group reply", func() bool { return len(api.sentReplies()) == 1 })
	if err := stopBot(t, cancel, done); err != nil {
		t.Fatalf("Run: %v", err)
	}
	replies := api.sentReplies()
	if replies[0].chatID != -100 {
		t.Errorf("reply chat = %d, want -100", replies[0].chatID)
	}
}

func TestMalformedUpdatesAreIgnored(t *testing.T) {
	updates := []telegram.Update{
		{ID: 70},
		{ID: 71, Message: &telegram.Message{Text: "/help", Chat: &telegram.Chat{ID: 7, Type: telegram.ChatPrivate}}},
		{ID: 72, Message: &telegram.Message{From: &telegram.User{ID: 7}, Chat: &telegram.Chat{ID: 7, Type: telegram.ChatPrivate}}},
		{ID: 73, Message: &telegram.Message{From: &telegram.User{ID: 7, IsBot: true}, Chat: &telegram.Chat{ID: 7, Type: telegram.ChatPrivate}, Text: "/help"}},
	}
	api := &fakeAPI{getUpdates: batchSource(updates)}
	state := newTestStore(t)
	b := newTestBot(t, api, &fakePanel{}, state, defaultOperators(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := runInBackground(t, b, ctx)
	waitFor(t, "all updates consumed", func() bool {
		offset, _ := state.BotOffset(context.Background())
		return offset == 74
	})
	if err := stopBot(t, cancel, done); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := api.sentReplies(); len(got) != 0 {
		t.Errorf("malformed updates received replies: %+v", got)
	}
	if b.ignored != 4 {
		t.Errorf("ignored = %d, want 4", b.ignored)
	}
}

func TestDuplicateUpdateIsAnsweredOnce(t *testing.T) {
	update := privateMessage(80, 7, 7, "/help")
	api := &fakeAPI{getUpdates: batchSource([]telegram.Update{update, update})}
	b := newTestBot(t, api, &fakePanel{}, newTestStore(t), defaultOperators(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := runInBackground(t, b, ctx)
	waitFor(t, "single reply", func() bool { return len(api.sentReplies()) >= 1 })
	time.Sleep(20 * time.Millisecond)
	if err := stopBot(t, cancel, done); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := api.sentReplies(); len(got) != 1 {
		t.Errorf("duplicate update answered %d times", len(got))
	}
}

func TestRestartResumesOffsetAndIgnoresReplay(t *testing.T) {
	update := privateMessage(100, 7, 7, "/help")
	state := newTestStore(t)
	api1 := &fakeAPI{getUpdates: batchSource([]telegram.Update{update})}
	b1 := newTestBot(t, api1, &fakePanel{}, state, defaultOperators(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := runInBackground(t, b1, ctx)
	waitFor(t, "first reply", func() bool { return len(api1.sentReplies()) == 1 })
	waitFor(t, "offset persisted", func() bool {
		offset, _ := state.BotOffset(context.Background())
		return offset == 101
	})
	if err := stopBot(t, cancel, done); err != nil {
		t.Fatalf("first Run: %v", err)
	}

	api2 := &fakeAPI{getUpdates: batchSource([]telegram.Update{update})}
	b2 := newTestBot(t, api2, &fakePanel{}, state, defaultOperators(), nil)
	ctx, cancel = context.WithCancel(context.Background())
	done = runInBackground(t, b2, ctx)
	waitFor(t, "restart poll", func() bool { return len(api2.pollCalls()) >= 1 })
	time.Sleep(30 * time.Millisecond)
	if err := stopBot(t, cancel, done); err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if got := api2.pollCalls()[0].Offset; got != 101 {
		t.Errorf("restart offset = %d, want 101", got)
	}
	if got := api2.sentReplies(); len(got) != 0 {
		t.Errorf("replayed update answered again: %+v", got)
	}
}

func TestContextCancellationStopsCleanly(t *testing.T) {
	api := &fakeAPI{}
	b := newTestBot(t, api, &fakePanel{}, newTestStore(t), defaultOperators(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := runInBackground(t, b, ctx)
	waitFor(t, "first poll", func() bool { return len(api.pollCalls()) >= 1 })
	if err := stopBot(t, cancel, done); err != nil {
		t.Fatalf("Run after cancellation = %v, want nil", err)
	}
}

func TestTelegramUnauthorizedReplyStopsTheProcess(t *testing.T) {
	api := &fakeAPI{
		getUpdates: batchSource([]telegram.Update{privateMessage(110, 7, 7, "/help")}),
		sendHook: func(context.Context, int64, string) error {
			return &telegram.Error{Method: "sendMessage", StatusCode: 401}
		},
	}
	b := newTestBot(t, api, &fakePanel{}, newTestStore(t), defaultOperators(), nil)
	err := b.Run(context.Background())
	if !errors.Is(err, telegram.ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
	if got := api.pollCalls(); len(got) != 1 {
		t.Errorf("polled %d times after 401", len(got))
	}
}

func TestSendRateLimitHonorsRetryAfter(t *testing.T) {
	var sleeps []time.Duration
	var mu sync.Mutex
	attempts := 0
	api := &fakeAPI{
		getUpdates: batchSource([]telegram.Update{privateMessage(120, 7, 7, "/help")}),
		sendHook: func(context.Context, int64, string) error {
			mu.Lock()
			defer mu.Unlock()
			attempts++
			if attempts == 1 {
				return &telegram.Error{Method: "sendMessage", StatusCode: 429, RetryAfter: 2 * time.Second}
			}
			return nil
		},
	}
	b := newTestBot(t, api, &fakePanel{}, newTestStore(t), defaultOperators(), nil)
	b.sleep = func(_ context.Context, d time.Duration) error {
		mu.Lock()
		sleeps = append(sleeps, d)
		mu.Unlock()
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := runInBackground(t, b, ctx)
	waitFor(t, "send retry", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return attempts == 2
	})
	if err := stopBot(t, cancel, done); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(sleeps) != 1 || sleeps[0] != 2*time.Second {
		t.Errorf("sleeps = %v, want [2s]", sleeps)
	}
}

func TestPollRateLimitWaitIsBounded(t *testing.T) {
	var sleeps []time.Duration
	var mu sync.Mutex
	first := true
	api := &fakeAPI{getUpdates: func(ctx context.Context, req telegram.UpdatesRequest) ([]telegram.Update, error) {
		mu.Lock()
		wasFirst := first
		first = false
		mu.Unlock()
		if wasFirst {
			return nil, &telegram.Error{Method: "getUpdates", StatusCode: 429, RetryAfter: time.Hour}
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	b := newTestBot(t, api, &fakePanel{}, newTestStore(t), defaultOperators(), nil)
	b.sleep = func(_ context.Context, d time.Duration) error {
		mu.Lock()
		sleeps = append(sleeps, d)
		mu.Unlock()
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := runInBackground(t, b, ctx)
	waitFor(t, "bounded poll wait", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(sleeps) == 1
	})
	if err := stopBot(t, cancel, done); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if sleeps[0] != maxRetryWait {
		t.Errorf("sleep = %s, want %s", sleeps[0], maxRetryWait)
	}
}

func TestClaimErrorStopsWithoutAdvancingOffset(t *testing.T) {
	api := &fakeAPI{getUpdates: batchSource([]telegram.Update{privateMessage(130, 7, 7, "/help")})}
	state := &fakeState{claimErr: errors.New("database is locked")}
	b := newTestBot(t, api, &fakePanel{}, state, defaultOperators(), nil)
	err := b.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "claim Telegram update") {
		t.Fatalf("Run err = %v, want a claim error", err)
	}
	if got := api.pollCalls(); len(got) != 1 {
		t.Errorf("polled %d times", len(got))
	}
	if state.offset != 0 {
		t.Errorf("offset = %d, want 0", state.offset)
	}
}

func TestNewValidatesConfiguration(t *testing.T) {
	api := &fakeAPI{}
	panel := &fakePanel{}
	state := newTestStore(t)
	tests := map[string]func() (*Bot, error){
		"nil api":       func() (*Bot, error) { return New(Config{Operators: defaultOperators()}, nil, panel, state) },
		"nil panel":     func() (*Bot, error) { return New(Config{Operators: defaultOperators()}, api, nil, state) },
		"nil state":     func() (*Bot, error) { return New(Config{Operators: defaultOperators()}, api, panel, nil) },
		"no operators":  func() (*Bot, error) { return New(Config{}, api, panel, state) },
		"zero operator": func() (*Bot, error) { return New(Config{Operators: []config.Operator{{ID: 0}}}, api, panel, state) },
		"bad role": func() (*Bot, error) {
			return New(Config{Operators: []config.Operator{{ID: 1, Role: "root"}}}, api, panel, state)
		},
		"duplicate operator": func() (*Bot, error) {
			return New(Config{Operators: []config.Operator{{ID: 1, Role: config.RoleAdmin}, {ID: 1, Role: config.RoleViewer}}}, api, panel, state)
		},
		"zero chat": func() (*Bot, error) {
			return New(Config{Operators: defaultOperators(), ChatIDs: []int64{0}}, api, panel, state)
		},
		"duplicate chat": func() (*Bot, error) {
			return New(Config{Operators: defaultOperators(), ChatIDs: []int64{5, 5}}, api, panel, state)
		},
		"bad poll timeout": func() (*Bot, error) {
			return New(Config{Operators: defaultOperators()}, api, panel, state, WithPollTimeout(0))
		},
		"bad panel timeout": func() (*Bot, error) {
			return New(Config{Operators: defaultOperators()}, api, panel, state, WithPanelTimeout(0))
		},
	}
	for name, build := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := build(); !errors.Is(err, ErrInvalidConfig) {
				t.Errorf("err = %v, want ErrInvalidConfig", err)
			}
		})
	}
}
