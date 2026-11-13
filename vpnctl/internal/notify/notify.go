// Package notify defines the alert sink contract used by later vpnctl
// components and a Telegram implementation that sends to admin operators.
//
// A sink is deliberately small: it accepts one bounded alert and returns
// delivery failures to the caller. It keeps no durable state.
package notify

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/juvenileslave/vpn/vpnctl/internal/config"
	"github.com/juvenileslave/vpn/vpnctl/internal/telegram"
)

// Severity is the operator-facing importance of an alert.
type Severity string

// Alert severities.
const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// Errors returned by a sink. Match them with errors.Is.
var (
	ErrInvalidConfig = errors.New("notify: invalid configuration")
	ErrInvalidAlert  = errors.New("notify: invalid alert")
	ErrQueueFull     = errors.New("notify: delivery queue is full")
	ErrRateLimited   = errors.New("notify: rate limit wait is too long")
)

// Alert is one notification. ID is the stable identity of the condition;
// DedupeKey suppresses repeats of the same condition and defaults to ID.
type Alert struct {
	ID        string
	Severity  Severity
	Message   string
	DedupeKey string
}

// Sink accepts alerts for delivery.
type Sink interface {
	// Send delivers a. A deduplicated alert returns nil without delivery.
	Send(ctx context.Context, a Alert) error
}

// Sender is the subset of telegram.Client the bot sink needs.
type Sender interface {
	SendMessage(ctx context.Context, chatID int64, text string) error
}

var alertIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// Validate reports whether a can be sent by any Sink.
func (a Alert) Validate() error {
	invalid := func(format string, args ...any) error {
		return fmt.Errorf("%w: "+format, append([]any{ErrInvalidAlert}, args...)...)
	}
	switch {
	case !alertIDPattern.MatchString(a.ID):
		return invalid("alert ID must match %s", alertIDPattern)
	case a.Severity != SeverityInfo && a.Severity != SeverityWarning && a.Severity != SeverityCritical:
		return invalid("severity must be info, warning or critical")
	case strings.TrimSpace(a.Message) == "":
		return invalid("message must not be empty")
	case strings.ContainsRune(a.Message, 0):
		return invalid("message must not contain NUL bytes")
	case a.DedupeKey != "" && !alertIDPattern.MatchString(a.DedupeKey):
		return invalid("dedupe key must be empty or match %s", alertIDPattern)
	}
	return nil
}

// Option customises a BotSink.
type Option func(*BotSink) error

// WithRateLimit sets the minimum interval between deliveries and the longest
// wait a caller may experience before ErrRateLimited is returned.
func WithRateLimit(interval, maxWait time.Duration) Option {
	return func(s *BotSink) error {
		if interval < 0 || maxWait < 0 {
			return fmt.Errorf("%w: rate limit durations must not be negative", ErrInvalidConfig)
		}
		s.interval, s.maxWait = interval, maxWait
		return nil
	}
}

// WithDedupe sets the suppression window and the maximum number of remembered
// keys. Memory stays bounded even when callers use unbounded keys.
func WithDedupe(ttl time.Duration, maxEntries int) Option {
	return func(s *BotSink) error {
		if ttl < 0 || maxEntries < 1 {
			return fmt.Errorf("%w: dedupe TTL must not be negative and entries must be positive", ErrInvalidConfig)
		}
		s.dedupeTTL, s.maxSeen = ttl, maxEntries
		return nil
	}
}

// WithQueue sets the number of alert deliveries allowed in flight. Send
// returns ErrQueueFull instead of buffering when the bound is reached.
func WithQueue(max int) Option {
	return func(s *BotSink) error {
		if max < 1 {
			return fmt.Errorf("%w: queue size must be positive", ErrInvalidConfig)
		}
		s.pending = make(chan struct{}, max)
		return nil
	}
}

// WithClock replaces the clock, for tests.
func WithClock(now func() time.Time) Option {
	return func(s *BotSink) error {
		if now == nil {
			return fmt.Errorf("%w: clock is required", ErrInvalidConfig)
		}
		s.now = now
		return nil
	}
}

type dedupeEntry struct {
	at       time.Time
	inflight bool
}

// BotSink delivers alerts as plain-text Telegram messages to a fixed list of
// chat IDs, normally the admin operators. It deduplicates by key, rate-limits
// delivery and bounds concurrent in-flight sends.
type BotSink struct {
	sender     Sender
	recipients []int64

	interval  time.Duration
	maxWait   time.Duration
	dedupeTTL time.Duration
	maxSeen   int
	now       func() time.Time
	pending   chan struct{}

	mu   sync.Mutex
	next time.Time
	seen map[string]dedupeEntry
}

// NewAdminSink returns a sink that alerts only the configured admin operators.
// Viewer IDs are skipped; an operator list without admins is invalid.
func NewAdminSink(sender Sender, operators []config.Operator, opts ...Option) (*BotSink, error) {
	recipients := make([]int64, 0, len(operators))
	for _, op := range operators {
		if op.Role == config.RoleAdmin {
			recipients = append(recipients, op.ID)
		}
	}
	if len(recipients) == 0 {
		return nil, fmt.Errorf("%w: at least one admin operator is required", ErrInvalidConfig)
	}
	return NewBotSink(sender, recipients, opts...)
}

// NewBotSink returns a sink that sends to recipients. Delivery is synchronous:
// each Send returns the combined result of every recipient.
func NewBotSink(sender Sender, recipients []int64, opts ...Option) (*BotSink, error) {
	if sender == nil {
		return nil, fmt.Errorf("%w: sender is required", ErrInvalidConfig)
	}
	if len(recipients) == 0 {
		return nil, fmt.Errorf("%w: at least one recipient is required", ErrInvalidConfig)
	}
	seenIDs := make(map[int64]bool, len(recipients))
	unique := make([]int64, 0, len(recipients))
	for _, id := range recipients {
		if id == 0 {
			return nil, fmt.Errorf("%w: recipient chat ID must be non-zero", ErrInvalidConfig)
		}
		if seenIDs[id] {
			return nil, fmt.Errorf("%w: duplicate recipient chat ID", ErrInvalidConfig)
		}
		seenIDs[id] = true
		unique = append(unique, id)
	}
	s := &BotSink{
		sender:     sender,
		recipients: unique,
		interval:   time.Second,
		maxWait:    5 * time.Second,
		dedupeTTL:  5 * time.Minute,
		maxSeen:    512,
		now:        time.Now,
		pending:    make(chan struct{}, 32),
		seen:       make(map[string]dedupeEntry),
	}
	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Send delivers a unless its dedupe key is already in flight or was delivered
// within the dedupe window. A failed delivery releases the key, so the caller
// can retry it.
func (s *BotSink) Send(ctx context.Context, a Alert) error {
	if err := a.Validate(); err != nil {
		return err
	}
	if ctx == nil {
		return fmt.Errorf("%w: context is required", ErrInvalidAlert)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	key := a.DedupeKey
	if key == "" {
		key = a.ID
	}
	if s.suppress(key) {
		return nil
	}

	select {
	case s.pending <- struct{}{}:
	default:
		s.release(key)
		return ErrQueueFull
	}
	defer func() { <-s.pending }()

	if err := s.waitTurn(ctx); err != nil {
		s.release(key)
		return err
	}

	text := telegram.Truncate("["+string(a.Severity)+"] "+a.ID+": "+a.Message, telegram.MaxMessageUnits)
	var failures []error
	for _, chatID := range s.recipients {
		if err := s.sender.SendMessage(ctx, chatID, text); err != nil {
			failures = append(failures, err)
		}
	}
	if len(failures) > 0 {
		s.release(key)
		return fmt.Errorf("notify: deliver %q: %w", a.ID, errors.Join(failures...))
	}
	s.confirm(key)
	return nil
}

// suppress reserves key for this call. It returns true when another delivery
// is in flight or the key was delivered inside the dedupe window.
func (s *BotSink) suppress(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if e, ok := s.seen[key]; ok {
		if e.inflight || now.Sub(e.at) < s.dedupeTTL {
			return true
		}
	}
	s.seen[key] = dedupeEntry{at: now, inflight: true}
	s.pruneLocked(now)
	return false
}

func (s *BotSink) confirm(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen[key] = dedupeEntry{at: s.now()}
}

func (s *BotSink) release(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.seen, key)
}

func (s *BotSink) pruneLocked(now time.Time) {
	if len(s.seen) <= s.maxSeen {
		return
	}
	for key, e := range s.seen {
		if !e.inflight && now.Sub(e.at) >= s.dedupeTTL {
			delete(s.seen, key)
		}
	}
	for len(s.seen) > s.maxSeen {
		var oldestKey string
		var oldest time.Time
		for key, e := range s.seen {
			if e.inflight {
				continue
			}
			if oldestKey == "" || e.at.Before(oldest) {
				oldestKey, oldest = key, e.at
			}
		}
		if oldestKey == "" {
			return
		}
		delete(s.seen, oldestKey)
	}
}

func (s *BotSink) waitTurn(ctx context.Context) error {
	s.mu.Lock()
	now := s.now()
	start := now
	if s.next.After(now) {
		start = s.next
	}
	wait := start.Sub(now)
	if wait > s.maxWait {
		s.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrRateLimited, wait.Round(time.Millisecond))
	}
	s.next = start.Add(s.interval)
	s.mu.Unlock()

	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
