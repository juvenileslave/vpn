// Package bot implements the read-only vpnctl Telegram bot and its long-poll
// runner. It answers an allowlisted operator with panel and node state, never
// changes the panel and persists its update offset in the state store.
//
// See docs/TELEGRAM_BOT.md for the operator-facing contract.
package bot

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/juvenileslave/vpn/vpnctl/internal/config"
	"github.com/juvenileslave/vpn/vpnctl/internal/remnawave"
	"github.com/juvenileslave/vpn/vpnctl/internal/telegram"
)

// Errors returned by New and Run. Match them with errors.Is.
var (
	ErrInvalidConfig = errors.New("bot: invalid configuration")
)

const (
	updatesLimit = 100
	maxNodeLines = 20
	usersPage    = 100

	defaultPollTimeout  = 25 * time.Second
	pollContextMargin   = 15 * time.Second
	defaultPanelTimeout = 10 * time.Second
	defaultAPITimeout   = 15 * time.Second
	defaultRetryWait    = time.Second
	maxRetryWait        = 30 * time.Second
	sendAttempts        = 2
	initialBackoff      = time.Second
	maxBackoff          = 30 * time.Second
)

// API is the Telegram transport used by the bot.
type API interface {
	GetMe(ctx context.Context) (telegram.User, error)
	GetUpdates(ctx context.Context, req telegram.UpdatesRequest) ([]telegram.Update, error)
	SendMessage(ctx context.Context, chatID int64, text string) error
}

// Panel is the read-only panel surface used by the bot.
type Panel interface {
	ListNodes(ctx context.Context) ([]remnawave.Node, error)
	ListUsers(ctx context.Context, start, size int) (remnawave.UsersPage, error)
	User(ctx context.Context, id int64) (remnawave.User, error)
}

// State is the persisted bot state used to resume updates.
type State interface {
	BotOffset(ctx context.Context) (int64, error)
	ClaimBotUpdate(ctx context.Context, updateID int64) (bool, error)
}

// Config is the validated operator allowlist and chat policy.
type Config struct {
	Operators []config.Operator
	ChatIDs   []int64
}

// Option customises a Bot.
type Option func(*Bot) error

// WithLogger sets the logger. A nil logger discards every record.
func WithLogger(log *slog.Logger) Option {
	return func(b *Bot) error {
		if log == nil {
			log = slog.New(slog.NewTextHandler(io.Discard, nil))
		}
		b.log = log
		return nil
	}
}

// WithPollTimeout sets the getUpdates long-poll wait.
func WithPollTimeout(d time.Duration) Option {
	return func(b *Bot) error {
		if d <= 0 || d > telegram.MaxPollTimeout {
			return fmt.Errorf("%w: poll timeout must be positive and at most %s", ErrInvalidConfig, telegram.MaxPollTimeout)
		}
		b.pollTimeout = d
		return nil
	}
}

// WithPanelTimeout bounds one panel request made for a command.
func WithPanelTimeout(d time.Duration) Option {
	return func(b *Bot) error {
		if d <= 0 {
			return fmt.Errorf("%w: panel timeout must be positive", ErrInvalidConfig)
		}
		b.panelTimeout = d
		return nil
	}
}

// Bot answers allowlisted operators and consumes every other update silently.
type Bot struct {
	api   API
	panel Panel
	state State
	log   *slog.Logger

	operators map[int64]config.Role
	chats     map[int64]bool

	pollTimeout  time.Duration
	panelTimeout time.Duration
	sleep        func(ctx context.Context, d time.Duration) error

	ignored int64
}

// New validates dependencies and the allowlist.
func New(cfg Config, api API, panel Panel, state State, opts ...Option) (*Bot, error) {
	switch {
	case api == nil:
		return nil, fmt.Errorf("%w: Telegram API is required", ErrInvalidConfig)
	case panel == nil:
		return nil, fmt.Errorf("%w: panel client is required", ErrInvalidConfig)
	case state == nil:
		return nil, fmt.Errorf("%w: state store is required", ErrInvalidConfig)
	case len(cfg.Operators) == 0:
		return nil, fmt.Errorf("%w: at least one operator is required", ErrInvalidConfig)
	}
	b := &Bot{
		api:          api,
		panel:        panel,
		state:        state,
		log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		operators:    make(map[int64]config.Role, len(cfg.Operators)),
		chats:        make(map[int64]bool, len(cfg.ChatIDs)),
		pollTimeout:  defaultPollTimeout,
		panelTimeout: defaultPanelTimeout,
		sleep:        sleepContext,
	}
	for _, op := range cfg.Operators {
		if op.ID <= 0 {
			return nil, fmt.Errorf("%w: operator ID must be positive", ErrInvalidConfig)
		}
		if op.Role != config.RoleAdmin && op.Role != config.RoleViewer {
			return nil, fmt.Errorf("%w: unknown operator role", ErrInvalidConfig)
		}
		if _, dup := b.operators[op.ID]; dup {
			return nil, fmt.Errorf("%w: duplicate operator ID", ErrInvalidConfig)
		}
		b.operators[op.ID] = op.Role
	}
	for _, id := range cfg.ChatIDs {
		if id == 0 {
			return nil, fmt.Errorf("%w: chat ID must be non-zero", ErrInvalidConfig)
		}
		if b.chats[id] {
			return nil, fmt.Errorf("%w: duplicate chat ID", ErrInvalidConfig)
		}
		b.chats[id] = true
	}
	for _, opt := range opts {
		if err := opt(b); err != nil {
			return nil, err
		}
	}
	return b, nil
}

// Run validates the token, then polls until ctx is canceled. A Telegram 401
// is returned as a typed error; cancellation returns nil after the current
// poll and update claim finish. The caller owns the store and closes it.
func (b *Bot) Run(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: context is required", ErrInvalidConfig)
	}
	if err := ctx.Err(); err != nil {
		return nil
	}
	meCtx, cancelMe := context.WithTimeout(ctx, defaultAPITimeout)
	me, err := b.api.GetMe(meCtx)
	cancelMe()
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("bot: validate token: %w", err)
	}
	b.log.Info("telegram bot authenticated", "username", me.Username)

	offset, err := b.state.BotOffset(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("bot: read update offset: %w", err)
	}
	b.log.Info("telegram bot polling", "offset", offset)

	var backoff time.Duration
	for {
		if ctx.Err() != nil {
			b.log.Info("telegram bot stopped", "ignored_updates", b.ignored)
			return nil
		}
		updates, err := b.poll(ctx, offset)
		if err != nil {
			if ctx.Err() != nil {
				b.log.Info("telegram bot stopped", "ignored_updates", b.ignored)
				return nil
			}
			var apiErr *telegram.Error
			if errors.As(err, &apiErr) && errors.Is(err, telegram.ErrUnauthorized) {
				return fmt.Errorf("bot: %w", err)
			}
			if errors.Is(err, telegram.ErrRateLimited) {
				wait := retryDelay(apiErr)
				b.log.Warn("telegram rate limited", "wait", wait)
				if err := b.sleep(ctx, wait); err != nil {
					b.log.Info("telegram bot stopped", "ignored_updates", b.ignored)
					return nil
				}
				continue
			}
			backoff = nextBackoff(backoff)
			b.log.Warn("telegram poll failed", "error", err, "backoff", backoff)
			if err := b.sleep(ctx, backoff); err != nil {
				b.log.Info("telegram bot stopped", "ignored_updates", b.ignored)
				return nil
			}
			continue
		}
		backoff = 0

		for _, update := range updates {
			if update.ID <= 0 {
				continue
			}
			claimed, err := b.state.ClaimBotUpdate(ctx, update.ID)
			if err != nil {
				if ctx.Err() != nil {
					b.log.Info("telegram bot stopped", "ignored_updates", b.ignored)
					return nil
				}
				// The offset is the bot's only durable cursor. A store failure
				// is not retried in a tight loop: stop and let the operator
				// inspect the database.
				return fmt.Errorf("bot: claim Telegram update: %w", err)
			}
			if update.ID+1 > offset {
				offset = update.ID + 1
			}
			if !claimed {
				b.log.Debug("telegram duplicate update ignored")
				continue
			}
			if err := b.handle(ctx, update); err != nil {
				if errors.Is(err, telegram.ErrUnauthorized) {
					return fmt.Errorf("bot: %w", err)
				}
				if ctx.Err() != nil {
					b.log.Info("telegram bot stopped", "ignored_updates", b.ignored)
					return nil
				}
				b.log.Warn("telegram update handling failed", "error", err)
			}
		}
	}
}

func (b *Bot) poll(ctx context.Context, offset int64) ([]telegram.Update, error) {
	pollCtx, cancel := context.WithTimeout(ctx, b.pollTimeout+pollContextMargin)
	defer cancel()
	return b.api.GetUpdates(pollCtx, telegram.UpdatesRequest{
		Offset:  offset,
		Limit:   updatesLimit,
		Timeout: b.pollTimeout,
	})
}

// send truncates the reply and retries a 429 once after the requested bounded
// wait. Every other delivery failure is returned.
func (b *Bot) send(ctx context.Context, chatID int64, text string) error {
	text = telegram.Truncate(text, telegram.MaxMessageUnits)
	if text == "" {
		return nil
	}
	var lastErr error
	for attempt := range sendAttempts {
		attemptCtx, cancel := context.WithTimeout(ctx, defaultAPITimeout)
		err := b.api.SendMessage(attemptCtx, chatID, text)
		cancel()
		if err == nil {
			return nil
		}
		lastErr = err
		var apiErr *telegram.Error
		if errors.As(err, &apiErr) && errors.Is(err, telegram.ErrRateLimited) && attempt+1 < sendAttempts {
			wait := retryDelay(apiErr)
			b.log.Warn("telegram send rate limited", "wait", wait)
			if err := b.sleep(ctx, wait); err != nil {
				return err
			}
			continue
		}
		return err
	}
	return lastErr
}

func retryDelay(apiErr *telegram.Error) time.Duration {
	wait := defaultRetryWait
	if apiErr != nil && apiErr.RetryAfter > 0 {
		wait = apiErr.RetryAfter
	}
	if wait > maxRetryWait {
		wait = maxRetryWait
	}
	return wait
}

func nextBackoff(current time.Duration) time.Duration {
	if current == 0 {
		return initialBackoff
	}
	current *= 2
	if current > maxBackoff {
		return maxBackoff
	}
	return current
}

func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
