// Package alerts runs a stateful metric-rule worker: it evaluates the
// accepted threshold rules on a schedule, persists per-rule state across
// restarts and queues notifications in SQLite before delivering them through
// the accepted notification sink.
//
// The package never queries VictoriaMetrics itself and never talks to
// Telegram directly: it consumes metrics.Querier and notify.Sink.
package alerts

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/juvenileslave/vpn/vpnctl/internal/metrics"
	"github.com/juvenileslave/vpn/vpnctl/internal/notify"
	"github.com/juvenileslave/vpn/vpnctl/internal/store"
)

// Errors returned by NewWorker and Run. Match them with errors.Is.
var (
	// ErrInvalidConfig marks an unusable worker configuration.
	ErrInvalidConfig = errors.New("alerts: invalid configuration")
	// ErrRulesInvalid is kept for callers that distinguish rule failures.
	ErrRulesInvalid = errors.New("alerts: invalid rules")
)

const (
	// maxMessageRunes bounds a rendered notification before the sink.
	maxMessageRunes = 1024
	// outboxLease bounds how long a claimed delivery is hidden from other
	// workers if this process dies mid-send.
	outboxLease = 10 * time.Minute
	// maxRunLease bounds the single-worker lease so a crashed process cannot
	// block a healthy worker for longer than this after a long interval.
	maxRunLease = 10 * time.Minute
	// maxInterval bounds the evaluation period and keeps timer arithmetic
	// well inside the time.Duration range.
	maxInterval = 24 * time.Hour
)

// Config is a validated worker configuration.
type Config struct {
	// Interval is the fixed evaluation period.
	Interval time.Duration
	// Jitter is added uniformly in [0, Jitter] to each interval.
	Jitter time.Duration
	// Grace delays the transition to unknown so that a short gap in data
	// does not page. Zero means an immediate unknown state.
	Grace time.Duration
	// FlapSamples is the consecutive firing sample count. Minimum 1.
	FlapSamples int
	// Retention is how long a deleted rule's state and delivered outbox rows
	// are kept.
	Retention time.Duration
	// OutboxMaxAge is the maximum age of an undelivered notification.
	OutboxMaxAge time.Duration
	// RetryBase and RetryMax define bounded exponential delivery backoff.
	RetryBase time.Duration
	RetryMax  time.Duration
	// MaxAttempts bounds delivery attempts per notification.
	MaxAttempts int
	// Scope names the observation scope shown in messages.
	Scope string
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// Log receives worker diagnostics; nil discards them.
	Log *slog.Logger
}

// Result summarises one evaluation cycle.
type Result struct {
	// Skipped is true when another cycle or worker instance held the run lock.
	Skipped bool
	// Evaluated is the number of rules queried in this cycle.
	Evaluated int
	Firing    int
	OK        int
	Unknown   int
	// Notified is the number of outbox rows inserted by this cycle.
	Notified int
	// Delivered is the number of notifications the sink accepted.
	Delivered int
	// Undelivered is the number of failed delivery attempts in this cycle.
	Undelivered int
	// PendingOutbox and ExpiredOutbox describe the durable queue after the cycle.
	PendingOutbox int
	ExpiredOutbox int
}

// Worker evaluates rules and dispatches alerts. It is safe for concurrent use;
// a second concurrent Cycle is skipped instead of overlapping.
type Worker struct {
	store   *store.Store
	querier metrics.Querier
	sink    notify.Sink
	rules   []metrics.Rule
	byName  map[string]metrics.Rule
	cfg     Config
	owner   string
	log     *slog.Logger
	now     func() time.Time
	busy    chan struct{}
}

// LoadRulesFile reads a rules file and returns the validated rule set.
func LoadRulesFile(path string) ([]metrics.Rule, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("%w: rules path is required", ErrInvalidConfig)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("alerts: read rules: %w", err)
	}
	defer f.Close()
	return metrics.LoadRules(f)
}

// NewWorker validates cfg and rules without issuing any query. Every rule
// problem is reported through metrics.ValidationError.
func NewWorker(st *store.Store, q metrics.Querier, sink notify.Sink, rules []metrics.Rule, cfg Config) (*Worker, error) {
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}
	switch {
	case st == nil:
		add("state store is required")
	case q == nil:
		add("metrics querier is required")
	case sink == nil:
		add("notification sink is required")
	}
	if cfg.Interval <= 0 {
		add("interval must be positive")
	}
	if cfg.Interval > maxInterval {
		add("interval must not exceed %s", maxInterval)
	}
	if cfg.Jitter < 0 {
		add("jitter must not be negative")
	}
	if cfg.Jitter > cfg.Interval {
		add("jitter must not exceed the interval")
	}
	if cfg.Grace < 0 {
		add("grace must not be negative")
	}
	if cfg.FlapSamples < 1 || cfg.FlapSamples > 1000 {
		add("flap samples must be from 1 through 1000")
	}
	if cfg.Retention <= 0 {
		add("retention must be positive")
	}
	if cfg.OutboxMaxAge <= 0 {
		add("outbox maximum age must be positive")
	}
	if cfg.RetryBase <= 0 {
		add("retry base must be positive")
	}
	if cfg.RetryMax < cfg.RetryBase {
		add("retry maximum must not be less than retry base")
	}
	if cfg.MaxAttempts < 1 || cfg.MaxAttempts > 100 {
		add("maximum attempts must be from 1 through 100")
	}
	if !validScope(cfg.Scope) {
		add("scope must match %s", scopePattern)
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrInvalidConfig, strings.Join(problems, "; "))
	}
	if err := metrics.ValidateRules(rules); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRulesInvalid, err)
	}
	owner, err := newOwner()
	if err != nil {
		return nil, err
	}
	byName := make(map[string]metrics.Rule, len(rules))
	for _, r := range rules {
		byName[r.Name] = r
	}
	cfg.Log = normalizeLogger(cfg.Log)
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Worker{
		store:   st,
		querier: q,
		sink:    sink,
		rules:   rules,
		byName:  byName,
		cfg:     cfg,
		owner:   owner,
		log:     cfg.Log,
		now:     now,
		busy:    make(chan struct{}, 1),
	}, nil
}

// Run evaluates immediately and then every configured interval until the
// context is cancelled. Cancellation is a clean shutdown and returns nil.
func (w *Worker) Run(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: context is required", ErrInvalidConfig)
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		res, err := w.Cycle(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			w.log.Error("alert cycle failed", "error", err)
		} else if !res.Skipped {
			w.log.Info("alert cycle",
				"evaluated", res.Evaluated, "firing", res.Firing,
				"unknown", res.Unknown, "notified", res.Notified,
				"delivered", res.Delivered, "undelivered", res.Undelivered,
				"pending_outbox", res.PendingOutbox, "expired_outbox", res.ExpiredOutbox)
		}
		timer := time.NewTimer(w.nextDelay())
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

// Cycle performs one evaluation, transition and delivery pass. The run lock,
// state transitions and outbox claims are transactional, so a second worker
// pointing at the same database cannot duplicate a notification.
func (w *Worker) Cycle(ctx context.Context) (Result, error) {
	if ctx == nil {
		return Result{}, fmt.Errorf("%w: context is required", ErrInvalidConfig)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	select {
	case w.busy <- struct{}{}:
		defer func() { <-w.busy }()
	default:
		return Result{Skipped: true}, nil
	}

	now := w.now()
	owned, err := w.store.ClaimAlertRun(ctx, w.owner, now, w.lease())
	if err != nil {
		return Result{}, err
	}
	if !owned {
		return Result{Skipped: true}, nil
	}
	defer func() {
		if err := w.store.ReleaseAlertRun(context.WithoutCancel(ctx), w.owner); err != nil {
			w.log.Warn("release alert run lock", "error", err)
		}
	}()

	res := Result{}
	evaluated, err := metrics.Evaluate(ctx, w.querier, w.rules, now)
	if err != nil {
		return res, err
	}
	res.Evaluated = len(evaluated)
	for _, a := range evaluated {
		switch a.State {
		case metrics.StateFiring:
			res.Firing++
		case metrics.StateOK:
			res.OK++
		default:
			res.Unknown++
		}
	}

	muted, err := w.activeMutes(ctx, now)
	if err != nil {
		return res, err
	}
	states, err := w.store.ListAlertStates(ctx)
	if err != nil {
		return res, err
	}
	byRule := make(map[string]store.AlertState, len(states))
	for _, st := range states {
		byRule[st.Rule] = st
	}

	for _, a := range evaluated {
		rule := w.byName[a.Rule]
		cur, exists := byRule[a.Rule]
		var next store.AlertState
		var event store.AlertEvent
		if exists {
			next, event = decide(&cur, a, rule, w.cfg, now)
		} else {
			next, event = decide(nil, a, rule, w.cfg, now)
		}
		var out *store.AlertOutbox
		if event != "" && !muted[a.Rule] {
			out = w.makeOutbox(next, event, unknownReason(a.Err), now)
		}
		revision := int64(0)
		if exists {
			revision = cur.Revision
		}
		_, inserted, err := w.store.CommitAlertTransition(ctx, revision, next, out)
		switch {
		case errors.Is(err, store.ErrConflict):
			// Another writer advanced the rule; retry on the next cycle.
			continue
		case err != nil:
			return res, err
		case inserted:
			res.Notified++
		}
	}

	present := make(map[string]bool, len(evaluated))
	for _, a := range evaluated {
		present[a.Rule] = true
	}
	for _, rule := range sortedKeys(byRule) {
		if present[rule] {
			continue
		}
		st := byRule[rule]
		if !st.MissingSince.IsZero() {
			continue
		}
		next := st
		next.MissingSince = now
		var out *store.AlertOutbox
		if !muted[rule] {
			out = w.makeOutbox(next, store.EventRemoved, "", now)
		}
		if _, inserted, err := w.store.CommitAlertTransition(ctx, st.Revision, next, out); err != nil {
			if errors.Is(err, store.ErrConflict) {
				continue
			}
			return res, err
		} else if inserted {
			res.Notified++
		}
	}

	cutoff := now.Add(-w.cfg.Retention)
	if _, err := w.store.ExpireAlertOutbox(ctx, now, w.cfg.MaxAttempts); err != nil {
		return res, err
	}
	if _, err := w.store.PruneAlertOutbox(ctx, cutoff, cutoff); err != nil {
		return res, err
	}
	if _, err := w.store.DeleteAlertStatesMissingBefore(ctx, cutoff); err != nil {
		return res, err
	}
	if err := w.deliver(ctx, &res, now); err != nil {
		return res, err
	}
	res.PendingOutbox, res.ExpiredOutbox, err = w.store.AlertOutboxStatus(ctx, now)
	if err != nil {
		return res, err
	}
	return res, nil
}

// deliver drains due outbox rows. Each claimed row is attempted exactly once
// per pass; a failure schedules bounded exponential backoff.
func (w *Worker) deliver(ctx context.Context, res *Result, now time.Time) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		rec, ok, err := w.store.ClaimAlertOutbox(ctx, now, outboxLease, w.cfg.MaxAttempts)
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		alert := notify.Alert{
			ID:        rec.DedupeKey,
			Severity:  notify.Severity(rec.Severity),
			Message:   rec.Message,
			DedupeKey: attemptDedupeKey(rec),
		}
		if err := w.sink.Send(ctx, alert); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			abandon := rec.Attempts >= w.cfg.MaxAttempts
			next := now.Add(w.backoff(rec.Attempts))
			if ferr := w.store.RecordAlertFailure(ctx, rec.ID, now, next, abandon); ferr != nil {
				return ferr
			}
			res.Undelivered++
			w.log.Warn("alert delivery failed",
				"rule", rec.Rule, "event", rec.Event, "attempt", rec.Attempts,
				"abandoned", abandon, "error", err)
			continue
		}
		if err := w.store.MarkAlertDelivered(ctx, rec.ID, now); err != nil {
			return err
		}
		res.Delivered++
	}
}

func (w *Worker) activeMutes(ctx context.Context, now time.Time) (map[string]bool, error) {
	mutes, err := w.store.ListAlertMutes(ctx)
	if err != nil {
		return nil, err
	}
	active := make(map[string]bool, len(mutes))
	for _, m := range mutes {
		if m.Until.After(now) {
			active[m.Rule] = true
		}
	}
	return active, nil
}

func (w *Worker) nextDelay() time.Duration {
	jitter := w.cfg.Jitter
	if jitter <= 0 {
		return w.cfg.Interval
	}
	if jitter > w.cfg.Interval {
		jitter = w.cfg.Interval
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return w.cfg.Interval
	}
	n := uint64(0)
	for _, v := range b {
		n = n<<8 | uint64(v)
	}
	// Jitter is bounded by the validated interval, so the addition is safe.
	return w.cfg.Interval + time.Duration(n%(uint64(jitter)+1))
}

func (w *Worker) lease() time.Duration {
	lease := 2*w.cfg.Interval + w.cfg.Jitter
	if lease < time.Minute {
		lease = time.Minute
	}
	if lease > maxRunLease {
		lease = maxRunLease
	}
	return lease
}

func (w *Worker) backoff(attempts int) time.Duration {
	d := w.cfg.RetryBase
	for i := 1; i < attempts; i++ {
		if d >= w.cfg.RetryMax/2 {
			return w.cfg.RetryMax
		}
		d *= 2
	}
	if d > w.cfg.RetryMax {
		return w.cfg.RetryMax
	}
	return d
}

func newOwner() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("alerts: generate run owner: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

func normalizeLogger(log *slog.Logger) *slog.Logger {
	if log == nil {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return log
}

func sortedKeys(m map[string]store.AlertState) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// fingerprint returns a stable hash of the deciding series labels. It never
// contains the labels themselves and is independent of message formatting.
func fingerprint(labels map[string]string) string {
	normalized := make(map[string]string, len(labels))
	for k, v := range labels {
		normalized[k] = v
	}
	b, err := json.Marshal(normalized)
	if err != nil {
		// A map of strings cannot fail to marshal; keep the identity stable.
		b = []byte("{}")
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// decide applies the documented transition policy. It returns the state to
// persist and, when a notification is due, its event kind.
func decide(cur *store.AlertState, a metrics.Alert, r metrics.Rule, cfg Config, now time.Time) (store.AlertState, store.AlertEvent) {
	observed := string(a.State)
	if cur == nil {
		st := store.AlertState{
			Rule:        a.Rule,
			State:       observed,
			Severity:    string(r.Severity),
			Comparison:  string(r.Comparison),
			Threshold:   a.Threshold,
			Labels:      map[string]string{},
			Fingerprint: fingerprint(nil),
			Since:       now,
			LastChange:  now,
		}
		if a.State != metrics.StateUnknown {
			st.Value = a.Value
			st.Labels = cloneLabels(a.Labels)
			st.Fingerprint = fingerprint(a.Labels)
		}
		if a.State == metrics.StateFiring {
			return st, store.EventFiring
		}
		return st, ""
	}

	next := *cur
	next.Labels = cloneLabels(cur.Labels)
	next.MissingSince = time.Time{}
	next.Threshold = a.Threshold
	next.Severity = string(r.Severity)
	next.Comparison = string(r.Comparison)
	if a.State != metrics.StateUnknown {
		next.Value = a.Value
		next.Labels = cloneLabels(a.Labels)
		next.Fingerprint = fingerprint(a.Labels)
	}

	// Track the unconfirmed candidate first; a different observation abandons
	// the previous candidate run.
	switch observed {
	case string(metrics.StateFiring):
		if next.PendingState != string(metrics.StateFiring) {
			next.PendingState = string(metrics.StateFiring)
			next.PendingSince = now
			next.PendingSamples = 1
		} else {
			next.PendingSamples++
		}
	case string(metrics.StateUnknown):
		if next.PendingState != string(metrics.StateUnknown) {
			next.PendingState = string(metrics.StateUnknown)
			next.PendingSince = now
			next.PendingSamples = 1
		} else {
			next.PendingSamples++
		}
	default:
		next.PendingState = ""
		next.PendingSince = time.Time{}
		next.PendingSamples = 0
	}

	switch observed {
	case string(metrics.StateOK):
		next.PendingState = ""
		next.PendingSince = time.Time{}
		next.PendingSamples = 0
		switch cur.State {
		case store.AlertFiring:
			next.State = store.AlertOK
			next.Since = now
			next.LastChange = now
			return next, store.EventRecovery
		case store.AlertUnknown:
			next.State = store.AlertOK
			next.Since = now
			next.LastChange = now
		}
		return next, ""
	case string(metrics.StateFiring):
		if cur.State == store.AlertFiring {
			next.PendingState = ""
			next.PendingSince = time.Time{}
			next.PendingSamples = 0
			return next, ""
		}
		if next.PendingSamples >= cfg.FlapSamples {
			next.State = store.AlertFiring
			next.Since = now
			next.LastChange = now
			next.PendingState = ""
			next.PendingSince = time.Time{}
			next.PendingSamples = 0
			return next, store.EventFiring
		}
		return next, ""
	default:
		if cur.State == store.AlertUnknown {
			next.PendingState = ""
			next.PendingSince = time.Time{}
			next.PendingSamples = 0
			return next, ""
		}
		if cfg.Grace <= 0 || now.Sub(next.PendingSince) >= cfg.Grace {
			next.State = store.AlertUnknown
			next.Since = now
			next.LastChange = now
			next.PendingState = ""
			next.PendingSince = time.Time{}
			next.PendingSamples = 0
			return next, store.EventUnknown
		}
		return next, ""
	}
}

func cloneLabels(labels map[string]string) map[string]string {
	out := make(map[string]string, len(labels))
	for k, v := range labels {
		out[k] = v
	}
	return out
}

// unknownReason maps a typed evaluation error to a bounded token. The error
// text never reaches a notification.
func unknownReason(err error) string {
	switch {
	case err == nil:
		return "unknown"
	case errors.Is(err, metrics.ErrNoData):
		return "no_data"
	case errors.Is(err, metrics.ErrNonFinite):
		return "non_finite"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	}
	var apiErr *metrics.APIError
	if errors.As(err, &apiErr) {
		return "query_error"
	}
	var httpErr *metrics.HTTPError
	if errors.As(err, &httpErr) {
		return "query_error"
	}
	var decodeErr *metrics.DecodeError
	if errors.As(err, &decodeErr) {
		return "invalid_response"
	}
	var typeErr *metrics.ResultTypeError
	if errors.As(err, &typeErr) {
		return "invalid_response"
	}
	var sizeErr *metrics.BodyTooLargeError
	if errors.As(err, &sizeErr) {
		return "invalid_response"
	}
	var reqErr *metrics.RequestError
	if errors.As(err, &reqErr) {
		return "request_failed"
	}
	return "query_failed"
}

// attemptDedupeKey keeps one sink dedupe identity per persistent attempt, so
// the outbox, not an in-memory sink window, owns retry policy.
func attemptDedupeKey(o store.AlertOutbox) string {
	suffix := fmt.Sprintf(".%d", o.Attempts)
	if len(o.DedupeKey)+len(suffix) > 128 {
		return o.DedupeKey
	}
	return o.DedupeKey + suffix
}
