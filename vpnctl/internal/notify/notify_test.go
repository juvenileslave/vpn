package notify

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/juvenileslave/vpn/vpnctl/internal/config"
	"github.com/juvenileslave/vpn/vpnctl/internal/telegram"
)

var _ Sink = (*BotSink)(nil)

type sentMessage struct {
	chatID int64
	text   string
}

type fakeSender struct {
	mu      sync.Mutex
	sent    []sentMessage
	err     error
	failFor int64
	block   chan struct{}
	entered chan struct{}
}

func (f *fakeSender) SendMessage(ctx context.Context, chatID int64, text string) error {
	if f.entered != nil {
		select {
		case f.entered <- struct{}{}:
		default:
		}
	}
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, sentMessage{chatID: chatID, text: text})
	if f.err != nil && (f.failFor == 0 || f.failFor == chatID) {
		return f.err
	}
	return nil
}

func (f *fakeSender) messages() []sentMessage {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]sentMessage(nil), f.sent...)
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func testAlert() Alert {
	return Alert{
		ID:       "node-lost:exit-01",
		Severity: SeverityCritical,
		Message:  "узел не отвечает",
	}
}

func newSink(t *testing.T, sender Sender, opts ...Option) *BotSink {
	t.Helper()
	base := []Option{WithRateLimit(0, 0), WithClock(newFakeClock().Now)}
	s, err := NewBotSink(sender, []int64{1, 2}, append(base, opts...)...)
	if err != nil {
		t.Fatalf("NewBotSink: %v", err)
	}
	return s
}

func TestBotSinkDeliversToEveryAdmin(t *testing.T) {
	fake := &fakeSender{}
	s := newSink(t, fake)
	if err := s.Send(context.Background(), testAlert()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	msgs := fake.messages()
	if len(msgs) != 2 {
		t.Fatalf("sent %d messages, want 2", len(msgs))
	}
	if msgs[0].chatID != 1 || msgs[1].chatID != 2 {
		t.Errorf("chat IDs = %d, %d", msgs[0].chatID, msgs[1].chatID)
	}
	want := "[critical] node-lost:exit-01: узел не отвечает"
	if msgs[0].text != want || msgs[1].text != want {
		t.Errorf("text = %q, want %q", msgs[0].text, want)
	}
}

func TestBotSinkTruncatesLongMessage(t *testing.T) {
	fake := &fakeSender{}
	s := newSink(t, fake)
	a := testAlert()
	a.Message = strings.Repeat("я", 5000)
	if err := s.Send(context.Background(), a); err != nil {
		t.Fatalf("Send: %v", err)
	}
	msgs := fake.messages()
	if len(msgs) != 2 {
		t.Fatalf("sent %d messages", len(msgs))
	}
	if n := telegram.UTF16Length(msgs[0].text); n > telegram.MaxMessageUnits {
		t.Errorf("message has %d UTF-16 units", n)
	}
	if !strings.HasSuffix(msgs[0].text, telegram.TruncationMarker) {
		t.Error("truncated message has no marker")
	}
}

func TestDedupeSuppressesRepeatsAndExpires(t *testing.T) {
	fake := &fakeSender{}
	clock := newFakeClock()
	s, err := NewBotSink(fake, []int64{1},
		WithRateLimit(0, 0), WithClock(clock.Now), WithDedupe(time.Minute, 8))
	if err != nil {
		t.Fatal(err)
	}
	a := testAlert()
	for range 2 {
		if err := s.Send(context.Background(), a); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}
	if got := len(fake.messages()); got != 1 {
		t.Fatalf("delivered %d times, want 1", got)
	}
	clock.Advance(59 * time.Second)
	if err := s.Send(context.Background(), a); err != nil {
		t.Fatalf("Send before expiry: %v", err)
	}
	if got := len(fake.messages()); got != 1 {
		t.Fatalf("delivered %d times before expiry, want 1", got)
	}
	clock.Advance(2 * time.Second)
	if err := s.Send(context.Background(), a); err != nil {
		t.Fatalf("Send after expiry: %v", err)
	}
	if got := len(fake.messages()); got != 2 {
		t.Fatalf("delivered %d times after expiry, want 2", got)
	}
}

func TestDedupeKeySeparatesConditions(t *testing.T) {
	fake := &fakeSender{}
	s := newSink(t, fake)
	first := testAlert()
	second := testAlert()
	second.DedupeKey = "node-lost:exit-01:first-seen"
	third := testAlert()
	third.ID = "node-lost:exit-02"
	third.DedupeKey = first.ID
	for _, a := range []Alert{first, second, third} {
		if err := s.Send(context.Background(), a); err != nil {
			t.Fatalf("Send(%s): %v", a.ID, err)
		}
	}
	// Two distinct keys survive dedupe; the third alert reuses the first key.
	if got := len(fake.messages()); got != 4 {
		t.Errorf("delivered %d messages, want 4", got)
	}
}

func TestDeliveryFailureIsReturnedAndRetryable(t *testing.T) {
	errBoom := errors.New("boom")
	fake := &fakeSender{err: errBoom}
	s := newSink(t, fake)
	err := s.Send(context.Background(), testAlert())
	if err == nil || !errors.Is(err, errBoom) {
		t.Fatalf("Send err = %v, want wrapped boom", err)
	}
	if !strings.Contains(err.Error(), "node-lost:exit-01") {
		t.Errorf("error does not name the alert: %v", err)
	}
	fake.mu.Lock()
	fake.err = nil
	fake.mu.Unlock()
	if err := s.Send(context.Background(), testAlert()); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if got := len(fake.messages()); got != 4 {
		t.Errorf("attempts = %d, want 4", got)
	}
}

func TestPartialDeliveryFailureTriesEveryRecipient(t *testing.T) {
	errBoom := errors.New("boom")
	fake := &fakeSender{err: errBoom, failFor: 1}
	s := newSink(t, fake)
	err := s.Send(context.Background(), testAlert())
	if !errors.Is(err, errBoom) {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
	if got := len(fake.messages()); got != 2 {
		t.Errorf("attempts = %d, want 2", got)
	}
}

func TestQueueBoundRejectsInsteadOfBuffering(t *testing.T) {
	fake := &fakeSender{block: make(chan struct{}), entered: make(chan struct{}, 1)}
	s := newSink(t, fake, WithQueue(1))
	first := make(chan error, 1)
	go func() { first <- s.Send(context.Background(), testAlert()) }()
	<-fake.entered

	second := testAlert()
	second.ID = "node-lost:exit-02"
	if err := s.Send(context.Background(), second); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("second Send err = %v, want ErrQueueFull", err)
	}
	close(fake.block)
	if err := <-first; err != nil {
		t.Fatalf("first Send: %v", err)
	}
}

func TestRateLimitReturnsBoundedError(t *testing.T) {
	fake := &fakeSender{}
	clock := newFakeClock()
	s, err := NewBotSink(fake, []int64{1},
		WithClock(clock.Now), WithRateLimit(time.Second, 100*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Send(context.Background(), testAlert()); err != nil {
		t.Fatalf("first Send: %v", err)
	}
	second := testAlert()
	second.ID = "node-lost:exit-02"
	if err := s.Send(context.Background(), second); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("second Send err = %v, want ErrRateLimited", err)
	}
	clock.Advance(2 * time.Second)
	if err := s.Send(context.Background(), second); err != nil {
		t.Fatalf("Send after rate window: %v", err)
	}
}

func TestRateWaitHonorsContextDeadline(t *testing.T) {
	fake := &fakeSender{}
	s, err := NewBotSink(fake, []int64{1},
		WithRateLimit(time.Hour, 2*time.Hour), WithClock(newFakeClock().Now))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Send(context.Background(), testAlert()); err != nil {
		t.Fatalf("first Send: %v", err)
	}
	second := testAlert()
	second.ID = "node-lost:exit-02"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := s.Send(ctx, second); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second Send err = %v, want context.DeadlineExceeded", err)
	}
}

func TestCanceledContext(t *testing.T) {
	s := newSink(t, &fakeSender{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Send(ctx, testAlert()); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestConcurrentDuplicateIsDeliveredOnce(t *testing.T) {
	fake := &fakeSender{}
	s := newSink(t, fake)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.Send(context.Background(), testAlert()); err != nil {
				t.Errorf("Send: %v", err)
			}
		}()
	}
	wg.Wait()
	if got := len(fake.messages()); got != 2 {
		t.Errorf("delivered %d messages for one recipient set, want 2", got)
	}
}

func TestDedupeMemoryIsBounded(t *testing.T) {
	fake := &fakeSender{}
	clock := newFakeClock()
	s, err := NewBotSink(fake, []int64{1},
		WithRateLimit(0, 0), WithClock(clock.Now), WithDedupe(0, 2))
	if err != nil {
		t.Fatal(err)
	}
	for i := range 10 {
		a := testAlert()
		a.ID = "alert-" + string(rune('a'+i))
		if err := s.Send(context.Background(), a); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}
	s.mu.Lock()
	got := len(s.seen)
	s.mu.Unlock()
	if got > 2 {
		t.Errorf("retained %d dedupe entries, want at most 2", got)
	}
}

func TestAlertValidation(t *testing.T) {
	tests := map[string]func(*Alert){
		"empty id":         func(a *Alert) { a.ID = "" },
		"bad id":           func(a *Alert) { a.ID = "alert with space" },
		"unknown severity": func(a *Alert) { a.Severity = "fatal" },
		"empty message":    func(a *Alert) { a.Message = " " },
		"nul message":      func(a *Alert) { a.Message = "a\x00b" },
		"bad dedupe key":   func(a *Alert) { a.DedupeKey = "../x" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			a := testAlert()
			mutate(&a)
			if err := a.Validate(); !errors.Is(err, ErrInvalidAlert) {
				t.Errorf("err = %v, want ErrInvalidAlert", err)
			}
		})
	}
	if err := testAlert().Validate(); err != nil {
		t.Errorf("valid alert: %v", err)
	}
}

func TestNewAdminSinkAlertsOnlyAdmins(t *testing.T) {
	fake := &fakeSender{}
	operators := []config.Operator{
		{ID: 10, Role: config.RoleAdmin},
		{ID: 11, Role: config.RoleViewer},
		{ID: 12, Role: config.RoleAdmin},
	}
	s, err := NewAdminSink(fake, operators, WithRateLimit(0, 0), WithClock(newFakeClock().Now))
	if err != nil {
		t.Fatalf("NewAdminSink: %v", err)
	}
	if err := s.Send(context.Background(), testAlert()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	msgs := fake.messages()
	if len(msgs) != 2 || msgs[0].chatID != 10 || msgs[1].chatID != 12 {
		t.Fatalf("alerts went to %+v, want admins 10 and 12", msgs)
	}
	if _, err := NewAdminSink(fake, []config.Operator{{ID: 11, Role: config.RoleViewer}}); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("viewer-only list err = %v, want ErrInvalidConfig", err)
	}
}

func TestNewBotSinkRejectsInvalidConfiguration(t *testing.T) {
	sender := &fakeSender{}
	tests := map[string]func() (*BotSink, error){
		"nil sender":     func() (*BotSink, error) { return NewBotSink(nil, []int64{1}) },
		"no recipients":  func() (*BotSink, error) { return NewBotSink(sender, nil) },
		"zero recipient": func() (*BotSink, error) { return NewBotSink(sender, []int64{0}) },
		"duplicate":      func() (*BotSink, error) { return NewBotSink(sender, []int64{1, 1}) },
		"negative rate":  func() (*BotSink, error) { return NewBotSink(sender, []int64{1}, WithRateLimit(-1, 0)) },
		"bad dedupe":     func() (*BotSink, error) { return NewBotSink(sender, []int64{1}, WithDedupe(0, 0)) },
		"bad queue":      func() (*BotSink, error) { return NewBotSink(sender, []int64{1}, WithQueue(0)) },
		"nil clock":      func() (*BotSink, error) { return NewBotSink(sender, []int64{1}, WithClock(nil)) },
	}
	for name, build := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := build(); !errors.Is(err, ErrInvalidConfig) {
				t.Errorf("err = %v, want ErrInvalidConfig", err)
			}
		})
	}
}
