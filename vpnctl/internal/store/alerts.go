package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"
)

// Alert states persisted for a metric rule.
const (
	AlertOK      = "ok"
	AlertFiring  = "firing"
	AlertUnknown = "unknown"
)

// AlertEvent is the kind of notification queued in the alert outbox.
type AlertEvent string

// Alert outbox events.
const (
	EventFiring   AlertEvent = "firing"
	EventRecovery AlertEvent = "recovery"
	EventUnknown  AlertEvent = "unknown"
	EventRemoved  AlertEvent = "removed"
)

var (
	alertRulePattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
	alertFingerprint     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	alertDedupeKey       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	alertRunOwnerPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)
)

// AlertState is the persisted evaluation state of one rule.
//
// PendingState and PendingSamples track an unconfirmed transition: firing
// observations accumulate until the configured flap count is reached, and an
// unknown observation waits for the grace period. Since/LastChange are only
// updated when State actually changes.
type AlertState struct {
	Rule           string
	State          string
	Severity       string
	Comparison     string
	Value          float64
	Threshold      float64
	Labels         map[string]string
	Fingerprint    string
	Since          time.Time
	LastChange     time.Time
	Revision       int64
	PendingState   string
	PendingSamples int
	PendingSince   time.Time
	MissingSince   time.Time
}

// AlertOutbox is one persisted notification. It is written before delivery so
// that a crash cannot lose a firing or recovery event.
type AlertOutbox struct {
	ID            int64
	Rule          string
	Event         AlertEvent
	Fingerprint   string
	DedupeKey     string
	Severity      string
	Message       string
	CreatedAt     time.Time
	Attempts      int
	NextAttemptAt time.Time
	ClaimedUntil  time.Time
	DeliveredAt   time.Time
	AbandonedAt   time.Time
	ExpiresAt     time.Time
}

// AlertMute suppresses notifications for a rule until Until.
type AlertMute struct {
	Rule  string
	Until time.Time
}

func validAlertState(st AlertState) error {
	switch {
	case !alertRulePattern.MatchString(st.Rule):
		return invalid("alert rule must match %s", alertRulePattern)
	case st.State != AlertOK && st.State != AlertFiring && st.State != AlertUnknown:
		return invalid("alert state must be ok, firing or unknown")
	case !validAlertSeverity(st.Severity):
		return invalid("alert severity must be info, warning or critical")
	case !validAlertComparison(st.Comparison):
		return invalid("alert comparison must be empty or one of >, >=, <, <=, ==, !=")
	case math.IsNaN(st.Value) || math.IsInf(st.Value, 0):
		return invalid("alert value must be finite")
	case math.IsNaN(st.Threshold) || math.IsInf(st.Threshold, 0):
		return invalid("alert threshold must be finite")
	case !alertFingerprint.MatchString(st.Fingerprint):
		return invalid("alert fingerprint must be 64 lowercase hex characters")
	case !validTime(st.Since) || !validTime(st.LastChange):
		return invalid("alert timestamps must be between the Unix epoch and year 2262")
	case st.PendingState != "" && st.PendingState != AlertFiring && st.PendingState != AlertUnknown:
		return invalid("alert pending state must be empty, firing or unknown")
	case st.PendingSamples < 0:
		return invalid("alert pending sample count must not be negative")
	case !st.PendingSince.IsZero() && !validTime(st.PendingSince):
		return invalid("alert pending time must be empty or a valid time")
	case !st.MissingSince.IsZero() && !validTime(st.MissingSince):
		return invalid("alert missing time must be empty or a valid time")
	}
	if err := validateAlertLabels(st.Labels); err != nil {
		return err
	}
	return nil
}

func validAlertSeverity(s string) bool {
	return s == "info" || s == "warning" || s == "critical"
}

func validAlertComparison(s string) bool {
	switch s {
	case "", ">", ">=", "<", "<=", "==", "!=":
		return true
	}
	return false
}

// validateAlertLabels bounds the stored label set. Labels are metric labels,
// not free-form diagnostics.
func validateAlertLabels(labels map[string]string) error {
	if len(labels) > 64 {
		return invalid("alert labels must contain at most 64 entries")
	}
	for k, v := range labels {
		if k == "" || len(k) > 128 || len(v) > 256 || strings.ContainsRune(k, 0) || strings.ContainsRune(v, 0) {
			return invalid("alert label keys must be 1..128 and values at most 256 bytes without NUL")
		}
	}
	return nil
}

func encodeAlertLabels(labels map[string]string) (string, error) {
	if len(labels) == 0 {
		return "{}", nil
	}
	b, err := json.Marshal(labels)
	if err != nil {
		return "", invalid("alert labels cannot be encoded")
	}
	if len(b) > 4096 {
		return "", invalid("alert labels exceed 4096 bytes")
	}
	return string(b), nil
}

func decodeAlertLabels(s string) (map[string]string, error) {
	var labels map[string]string
	if err := json.Unmarshal([]byte(s), &labels); err != nil {
		return nil, fmt.Errorf("%w: alert labels", ErrCorrupt)
	}
	if labels == nil {
		labels = map[string]string{}
	}
	return labels, nil
}

func validAlertEvent(e AlertEvent) bool {
	switch e {
	case EventFiring, EventRecovery, EventUnknown, EventRemoved:
		return true
	}
	return false
}

func validateAlertOutbox(o AlertOutbox) error {
	switch {
	case !alertRulePattern.MatchString(o.Rule):
		return invalid("alert outbox rule must match %s", alertRulePattern)
	case !validAlertEvent(o.Event):
		return invalid("alert outbox event must be firing, recovery, unknown or removed")
	case !alertFingerprint.MatchString(o.Fingerprint):
		return invalid("alert outbox fingerprint must be 64 lowercase hex characters")
	case !alertDedupeKey.MatchString(o.DedupeKey):
		return invalid("alert outbox dedupe key must match %s", alertDedupeKey)
	case !validAlertSeverity(o.Severity):
		return invalid("alert outbox severity must be info, warning or critical")
	case strings.TrimSpace(o.Message) == "" || strings.ContainsRune(o.Message, 0):
		return invalid("alert outbox message must be non-empty and contain no NUL")
	case len([]rune(o.Message)) > 4096:
		return invalid("alert outbox message exceeds 4096 characters")
	case !validTime(o.CreatedAt) || !validTime(o.ExpiresAt):
		return invalid("alert outbox timestamps must be between the Unix epoch and year 2262")
	case !o.ExpiresAt.After(o.CreatedAt):
		return invalid("alert outbox expiry must be after creation")
	}
	return nil
}

// CommitAlertTransition atomically stores next and inserts outbox when it is
// not nil. expectedRevision is the revision the caller read: 0 inserts a new
// row and fails with ErrConflict when the rule already has state, while a
// positive value updates only that revision. The written revision is always
// expectedRevision+1. It returns the stored state and whether the outbox row
// was inserted; a duplicate dedupe key is not an error and reports false.
func (s *Store) CommitAlertTransition(ctx context.Context, expectedRevision int64, next AlertState, outbox *AlertOutbox) (AlertState, bool, error) {
	if expectedRevision < 0 {
		return AlertState{}, false, invalid("expected alert revision must not be negative")
	}
	if err := validAlertState(next); err != nil {
		return AlertState{}, false, err
	}
	encoded, err := encodeAlertLabels(next.Labels)
	if err != nil {
		return AlertState{}, false, err
	}
	if outbox != nil {
		if outbox.Rule != next.Rule {
			return AlertState{}, false, invalid("alert outbox rule must match the state rule")
		}
		if err := validateAlertOutbox(*outbox); err != nil {
			return AlertState{}, false, err
		}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AlertState{}, false, dbError("begin alert transition", err)
	}
	defer tx.Rollback()

	cur, gerr := getAlertState(ctx, tx, next.Rule)
	switch {
	case gerr != nil && !errors.Is(gerr, ErrNotFound):
		return AlertState{}, false, gerr
	case expectedRevision == 0 && gerr == nil:
		return AlertState{}, false, ErrConflict
	case expectedRevision > 0 && errors.Is(gerr, ErrNotFound):
		return AlertState{}, false, ErrConflict
	case expectedRevision > 0 && cur.Revision != expectedRevision:
		return AlertState{}, false, ErrConflict
	}

	stored := next
	stored.Revision = expectedRevision + 1
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO alert_states (
			rule, state, severity, comparison, value, threshold, labels, fingerprint,
			since, last_change, revision, pending_state, pending_since,
			pending_samples, missing_since
		 ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT (rule) DO UPDATE SET
			state = excluded.state,
			severity = excluded.severity,
			comparison = excluded.comparison,
			value = excluded.value,
			threshold = excluded.threshold,
			labels = excluded.labels,
			fingerprint = excluded.fingerprint,
			since = excluded.since,
			last_change = excluded.last_change,
			revision = excluded.revision,
			pending_state = excluded.pending_state,
			pending_since = excluded.pending_since,
			pending_samples = excluded.pending_samples,
			missing_since = excluded.missing_since`,
		stored.Rule, stored.State, stored.Severity, stored.Comparison,
		stored.Value, stored.Threshold, encoded, stored.Fingerprint,
		timeToNS(stored.Since), timeToNS(stored.LastChange), stored.Revision,
		stored.PendingState, timeToNS(stored.PendingSince), stored.PendingSamples,
		timeToNS(stored.MissingSince)); err != nil {
		return AlertState{}, false, dbError("store alert state", err)
	}

	inserted := false
	if outbox != nil {
		res, err := tx.ExecContext(ctx,
			`INSERT INTO alert_outbox (
				rule, event, fingerprint, dedupe_key, severity, message,
				created_at, attempts, next_attempt_at, claimed_until,
				delivered_at, abandoned_at, expires_at
			 ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, 0, 0, 0, ?)
			 ON CONFLICT (dedupe_key) DO NOTHING`,
			outbox.Rule, string(outbox.Event), outbox.Fingerprint, outbox.DedupeKey,
			outbox.Severity, outbox.Message, timeToNS(outbox.CreatedAt),
			timeToNS(outbox.NextAttemptAt), timeToNS(outbox.ExpiresAt))
		if err != nil {
			return AlertState{}, false, dbError("queue alert notification", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return AlertState{}, false, dbError("queue alert notification", err)
		}
		inserted = n == 1
	}
	if err := tx.Commit(); err != nil {
		return AlertState{}, false, dbError("commit alert transition", err)
	}
	return stored, inserted, nil
}

type alertStateRower interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func getAlertState(ctx context.Context, q alertStateRower, rule string) (AlertState, error) {
	var st AlertState
	var labels string
	var since, lastChange int64
	var pendingSince, missingSince int64
	var pendingState string
	err := q.QueryRowContext(ctx,
		`SELECT rule, state, severity, comparison, value, threshold, labels, fingerprint,
		        since, last_change, revision, pending_state, pending_since,
		        pending_samples, missing_since
		 FROM alert_states WHERE rule = ?`, rule).
		Scan(&st.Rule, &st.State, &st.Severity, &st.Comparison, &st.Value, &st.Threshold,
			&labels, &st.Fingerprint, &since, &lastChange, &st.Revision,
			&pendingState, &pendingSince, &st.PendingSamples, &missingSince)
	if errors.Is(err, sql.ErrNoRows) {
		return AlertState{}, ErrNotFound
	}
	if err != nil {
		return AlertState{}, dbError("get alert state", err)
	}
	st.PendingState = pendingState
	st.Labels, err = decodeAlertLabels(labels)
	if err != nil {
		return AlertState{}, err
	}
	st.Since = nsToTime(since)
	st.LastChange = nsToTime(lastChange)
	st.PendingSince = nsToTime(pendingSince)
	st.MissingSince = nsToTime(missingSince)
	if err := validAlertState(st); err != nil || st.Revision < 1 {
		return AlertState{}, fmt.Errorf("%w: alert state row", ErrCorrupt)
	}
	return st, nil
}

// GetAlertState returns the persisted state of rule or ErrNotFound.
func (s *Store) GetAlertState(ctx context.Context, rule string) (AlertState, error) {
	if !alertRulePattern.MatchString(rule) {
		return AlertState{}, invalid("alert rule must match %s", alertRulePattern)
	}
	return getAlertState(ctx, s.db, rule)
}

// ListAlertStates returns every persisted rule state ordered by rule.
func (s *Store) ListAlertStates(ctx context.Context) ([]AlertState, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT rule, state, severity, comparison, value, threshold, labels, fingerprint,
		        since, last_change, revision, pending_state, pending_since,
		        pending_samples, missing_since
		 FROM alert_states ORDER BY rule`)
	if err != nil {
		return nil, dbError("list alert states", err)
	}
	defer rows.Close()

	var states []AlertState
	for rows.Next() {
		var (
			st                         AlertState
			labels                     string
			since, lastChange          int64
			pendingSince, missingSince int64
		)
		if err := rows.Scan(&st.Rule, &st.State, &st.Severity, &st.Comparison, &st.Value,
			&st.Threshold, &labels, &st.Fingerprint, &since, &lastChange, &st.Revision,
			&st.PendingState, &pendingSince, &st.PendingSamples, &missingSince); err != nil {
			return nil, dbError("list alert states", err)
		}
		st.Labels, err = decodeAlertLabels(labels)
		if err != nil {
			return nil, err
		}
		st.Since = nsToTime(since)
		st.LastChange = nsToTime(lastChange)
		st.PendingSince = nsToTime(pendingSince)
		st.MissingSince = nsToTime(missingSince)
		if err := validAlertState(st); err != nil || st.Revision < 1 {
			return nil, fmt.Errorf("%w: alert state row", ErrCorrupt)
		}
		states = append(states, st)
	}
	if err := rows.Err(); err != nil {
		return nil, dbError("list alert states", err)
	}
	return states, nil
}

// DeleteAlertStatesMissingBefore removes states for rules that have been
// absent since before cutoff. It returns the number of deleted rows.
func (s *Store) DeleteAlertStatesMissingBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	if !validTime(cutoff) {
		return 0, invalid("retention cutoff must be between the Unix epoch and year 2262")
	}
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM alert_states WHERE missing_since > 0 AND missing_since < ?`, timeToNS(cutoff))
	if err != nil {
		return 0, dbError("prune alert states", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, dbError("prune alert states", err)
	}
	return n, nil
}

// SetAlertMute persists a mute until until, replacing an earlier window.
func (s *Store) SetAlertMute(ctx context.Context, rule string, until time.Time) error {
	if !alertRulePattern.MatchString(rule) {
		return invalid("alert mute rule must match %s", alertRulePattern)
	}
	if !validTime(until) || until.IsZero() {
		return invalid("alert mute time must be between the Unix epoch and year 2262")
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO alert_mutes (rule, until) VALUES (?, ?)
		 ON CONFLICT (rule) DO UPDATE SET until = excluded.until`,
		rule, timeToNS(until)); err != nil {
		return dbError("set alert mute", err)
	}
	return nil
}

// ListAlertMutes returns every stored mute ordered by rule. Expired windows
// are returned as well; callers compare Until with the current time.
func (s *Store) ListAlertMutes(ctx context.Context) ([]AlertMute, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT rule, until FROM alert_mutes ORDER BY rule`)
	if err != nil {
		return nil, dbError("list alert mutes", err)
	}
	defer rows.Close()
	var mutes []AlertMute
	for rows.Next() {
		var m AlertMute
		var ns int64
		if err := rows.Scan(&m.Rule, &ns); err != nil {
			return nil, dbError("list alert mutes", err)
		}
		m.Until = nsToTime(ns)
		if !alertRulePattern.MatchString(m.Rule) || m.Until.IsZero() {
			return nil, fmt.Errorf("%w: alert mute row", ErrCorrupt)
		}
		mutes = append(mutes, m)
	}
	if err := rows.Err(); err != nil {
		return nil, dbError("list alert mutes", err)
	}
	return mutes, nil
}

// ClaimAlertOutbox reserves the oldest due notification for delivery. The
// attempt counter is incremented and claimed_until is set to now+lease so
// that a second worker skips the row. It returns false when nothing is due.
//
// A row is claimable only when no earlier undelivered row exists for the same
// rule, so notifications for one rule keep their insertion order across
// retries and restarts even while an earlier attempt waits for backoff.
func (s *Store) ClaimAlertOutbox(ctx context.Context, now time.Time, lease time.Duration, maxAttempts int) (AlertOutbox, bool, error) {
	switch {
	case !validTime(now) || now.IsZero():
		return AlertOutbox{}, false, invalid("alert claim time must be between the Unix epoch and year 2262")
	case lease <= 0:
		return AlertOutbox{}, false, invalid("alert claim lease must be positive")
	case maxAttempts < 1:
		return AlertOutbox{}, false, invalid("alert max attempts must be positive")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AlertOutbox{}, false, dbError("begin alert claim", err)
	}
	defer tx.Rollback()

	var (
		o                      AlertOutbox
		event, severity        string
		created, next, claimed int64
		delivered, abandoned   int64
		expires                int64
	)
	err = tx.QueryRowContext(ctx,
		`SELECT o.id, o.rule, o.event, o.fingerprint, o.dedupe_key, o.severity, o.message,
		        o.created_at, o.attempts, o.next_attempt_at, o.claimed_until,
		        o.delivered_at, o.abandoned_at, o.expires_at
		 FROM alert_outbox o
		 WHERE o.delivered_at = 0 AND o.abandoned_at = 0
		   AND o.next_attempt_at <= ? AND o.claimed_until <= ?
		   AND o.expires_at > ? AND o.attempts < ?
		   AND NOT EXISTS (
			SELECT 1 FROM alert_outbox e
			WHERE e.rule = o.rule AND e.id < o.id
			  AND e.delivered_at = 0 AND e.abandoned_at = 0
		   )
		 ORDER BY o.id LIMIT 1`,
		timeToNS(now), timeToNS(now), timeToNS(now), maxAttempts).
		Scan(&o.ID, &o.Rule, &event, &o.Fingerprint, &o.DedupeKey, &severity, &o.Message,
			&created, &o.Attempts, &next, &claimed, &delivered, &abandoned, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return AlertOutbox{}, false, nil
	}
	if err != nil {
		return AlertOutbox{}, false, dbError("claim alert notification", err)
	}
	if delivered != 0 || abandoned != 0 {
		return AlertOutbox{}, false, fmt.Errorf("%w: alert outbox row", ErrCorrupt)
	}
	o.Event = AlertEvent(event)
	o.Severity = severity
	o.CreatedAt = nsToTime(created)
	o.NextAttemptAt = nsToTime(next)
	o.ClaimedUntil = nsToTime(claimed)
	o.ExpiresAt = nsToTime(expires)

	o.Attempts++
	claimedUntil := now.Add(lease)
	res, err := tx.ExecContext(ctx,
		`UPDATE alert_outbox SET attempts = ?, claimed_until = ?
		 WHERE id = ? AND delivered_at = 0 AND claimed_until = ?`,
		o.Attempts, timeToNS(claimedUntil), o.ID, claimed)
	if err != nil {
		return AlertOutbox{}, false, dbError("claim alert notification", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return AlertOutbox{}, false, dbError("claim alert notification", err)
	} else if n != 1 {
		return AlertOutbox{}, false, ErrConflict
	}
	o.ClaimedUntil = claimedUntil
	if err := tx.Commit(); err != nil {
		return AlertOutbox{}, false, dbError("commit alert claim", err)
	}
	return o, true, nil
}

// MarkAlertDelivered records a successful delivery. Repeating it is a no-op.
func (s *Store) MarkAlertDelivered(ctx context.Context, id int64, now time.Time) error {
	if id < 1 {
		return invalid("alert outbox ID must be positive")
	}
	if !validTime(now) || now.IsZero() {
		return invalid("alert delivery time must be between the Unix epoch and year 2262")
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE alert_outbox SET delivered_at = ?, claimed_until = 0
		 WHERE id = ? AND delivered_at = 0`, timeToNS(now), id)
	if err != nil {
		return dbError("mark alert delivered", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return dbError("mark alert delivered", err)
	} else if n == 1 {
		return nil
	}
	var exists int
	err = s.db.QueryRowContext(ctx, `SELECT count(*) FROM alert_outbox WHERE id = ?`, id).Scan(&exists)
	if err != nil {
		return dbError("mark alert delivered", err)
	}
	if exists == 0 {
		return ErrNotFound
	}
	return nil
}

// RecordAlertFailure releases a claim and schedules the next attempt. When
// abandon is true the row is marked abandoned instead and is never retried;
// the entry stays visible to the CLI.
func (s *Store) RecordAlertFailure(ctx context.Context, id int64, now time.Time, next time.Time, abandon bool) error {
	switch {
	case id < 1:
		return invalid("alert outbox ID must be positive")
	case !validTime(now) || now.IsZero():
		return invalid("alert failure time must be between the Unix epoch and year 2262")
	case !abandon && (!validTime(next) || next.IsZero()):
		return invalid("alert retry time must be between the Unix epoch and year 2262")
	}
	var res sql.Result
	var err error
	if abandon {
		res, err = s.db.ExecContext(ctx,
			`UPDATE alert_outbox SET claimed_until = 0, abandoned_at = ?
			 WHERE id = ? AND delivered_at = 0 AND abandoned_at = 0`, timeToNS(now), id)
	} else {
		res, err = s.db.ExecContext(ctx,
			`UPDATE alert_outbox SET claimed_until = 0, next_attempt_at = ?
			 WHERE id = ? AND delivered_at = 0 AND abandoned_at = 0`, timeToNS(next), id)
	}
	if err != nil {
		return dbError("record alert failure", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return dbError("record alert failure", err)
	} else if n == 1 {
		return nil
	}
	var exists int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM alert_outbox WHERE id = ?`, id).Scan(&exists); err != nil {
		return dbError("record alert failure", err)
	}
	if exists == 0 {
		return ErrNotFound
	}
	return nil
}

// ExpireAlertOutbox marks undelivered notifications that passed their maximum
// age as abandoned. An abandoned row is never retried, remains visible as
// expired, and is removed later by PruneAlertOutbox after the retention
// period, so a long sink outage cannot grow the queue without bound.
func (s *Store) ExpireAlertOutbox(ctx context.Context, now time.Time) (int64, error) {
	if !validTime(now) || now.IsZero() {
		return 0, invalid("alert expiry time must be between the Unix epoch and year 2262")
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE alert_outbox SET abandoned_at = ?, claimed_until = 0
		 WHERE delivered_at = 0 AND abandoned_at = 0 AND expires_at <= ?`,
		timeToNS(now), timeToNS(now))
	if err != nil {
		return 0, dbError("expire alert notifications", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, dbError("expire alert notifications", err)
	}
	return n, nil
}

// AlertOutboxStatus counts undelivered and expired notifications. Pending
// entries are still retryable; expired entries include abandoned ones and
// rows whose maximum age passed.
func (s *Store) AlertOutboxStatus(ctx context.Context, now time.Time) (pending, expired int, err error) {
	if !validTime(now) || now.IsZero() {
		return 0, 0, invalid("alert status time must be between the Unix epoch and year 2262")
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT
			coalesce(sum(CASE WHEN delivered_at = 0 AND abandoned_at = 0 AND expires_at > ? THEN 1 ELSE 0 END), 0),
			coalesce(sum(CASE WHEN delivered_at = 0 AND (abandoned_at > 0 OR expires_at <= ?) THEN 1 ELSE 0 END), 0)
		 FROM alert_outbox`, timeToNS(now), timeToNS(now))
	if err != nil {
		return 0, 0, dbError("alert outbox status", err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return 0, 0, dbError("alert outbox status", err)
		}
		return 0, 0, nil
	}
	if err := rows.Scan(&pending, &expired); err != nil {
		return 0, 0, dbError("alert outbox status", err)
	}
	return pending, expired, rows.Err()
}

// ListOpenAlertOutbox returns undelivered notifications, including abandoned
// ones, ordered by insertion ID. limit must be from 1 through MaxLimit.
func (s *Store) ListOpenAlertOutbox(ctx context.Context, limit int) ([]AlertOutbox, error) {
	if limit < 1 || limit > MaxLimit {
		return nil, invalid("alert outbox limit must be from 1 through %d", MaxLimit)
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, rule, event, fingerprint, dedupe_key, severity, message,
		        created_at, attempts, next_attempt_at, claimed_until,
		        delivered_at, abandoned_at, expires_at
		 FROM alert_outbox WHERE delivered_at = 0
		 ORDER BY id LIMIT ?`, limit)
	if err != nil {
		return nil, dbError("list alert outbox", err)
	}
	defer rows.Close()
	var out []AlertOutbox
	for rows.Next() {
		var (
			o                      AlertOutbox
			event, severity        string
			created, next, claimed int64
			delivered, abandoned   int64
			expires                int64
		)
		if err := rows.Scan(&o.ID, &o.Rule, &event, &o.Fingerprint, &o.DedupeKey,
			&severity, &o.Message, &created, &o.Attempts, &next, &claimed,
			&delivered, &abandoned, &expires); err != nil {
			return nil, dbError("list alert outbox", err)
		}
		o.Event = AlertEvent(event)
		o.Severity = severity
		o.CreatedAt = nsToTime(created)
		o.NextAttemptAt = nsToTime(next)
		o.ClaimedUntil = nsToTime(claimed)
		o.ExpiresAt = nsToTime(expires)
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		return nil, dbError("list alert outbox", err)
	}
	return out, nil
}

// PruneAlertOutbox removes delivered and abandoned notifications older than
// the given cutoffs. Pending entries are never removed.
func (s *Store) PruneAlertOutbox(ctx context.Context, deliveredBefore, abandonedBefore time.Time) (int64, error) {
	if !validTime(deliveredBefore) || !validTime(abandonedBefore) {
		return 0, invalid("alert outbox cutoffs must be between the Unix epoch and year 2262")
	}
	var deleted int64
	for _, q := range []struct {
		query string
		arg   int64
	}{
		{`DELETE FROM alert_outbox WHERE delivered_at > 0 AND delivered_at < ?`, timeToNS(deliveredBefore)},
		{`DELETE FROM alert_outbox WHERE abandoned_at > 0 AND abandoned_at < ?`, timeToNS(abandonedBefore)},
	} {
		res, err := s.db.ExecContext(ctx, q.query, q.arg)
		if err != nil {
			return deleted, dbError("prune alert outbox", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return deleted, dbError("prune alert outbox", err)
		}
		deleted += n
	}
	return deleted, nil
}

// ClaimAlertRun acquires or renews the single-worker lease. It returns false
// while another owner holds an unexpired lease. The lease is renewed by
// calling again with the same owner.
func (s *Store) ClaimAlertRun(ctx context.Context, owner string, now time.Time, ttl time.Duration) (bool, error) {
	switch {
	case !alertRunOwnerPattern.MatchString(owner):
		return false, invalid("alert run owner must match %s", alertRunOwnerPattern)
	case !validTime(now) || now.IsZero():
		return false, invalid("alert run time must be between the Unix epoch and year 2262")
	case ttl <= 0:
		return false, invalid("alert run lease must be positive")
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO alert_runs (id, owner, expires_at) VALUES (1, ?, ?)
		 ON CONFLICT (id) DO UPDATE SET owner = excluded.owner, expires_at = excluded.expires_at
		 WHERE alert_runs.expires_at <= ? OR alert_runs.owner = excluded.owner`,
		owner, timeToNS(now.Add(ttl)), timeToNS(now))
	if err != nil {
		return false, dbError("claim alert run", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, dbError("claim alert run", err)
	}
	return n == 1, nil
}

// ReleaseAlertRun drops the lease when owner still holds it.
func (s *Store) ReleaseAlertRun(ctx context.Context, owner string) error {
	if !alertRunOwnerPattern.MatchString(owner) {
		return invalid("alert run owner must match %s", alertRunOwnerPattern)
	}
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM alert_runs WHERE id = 1 AND owner = ?`, owner); err != nil {
		return dbError("release alert run", err)
	}
	return nil
}

func timeToNS(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UTC().UnixNano()
}

func nsToTime(ns int64) time.Time {
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns).UTC()
}
