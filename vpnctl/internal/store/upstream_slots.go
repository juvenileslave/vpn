package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// UpstreamSlot is the persisted refresh state of one fixed egress slot.
type UpstreamSlot struct {
	Slot            int
	Mode            string // "upstream" | "blackhole"
	ActiveVersionID string
	FailureCount    int
	NextRunAt       time.Time // zero when unset
	LastErrorCode   string
	UpdatedAt       time.Time
}

func validOptionalUpstreamTime(t time.Time) bool {
	return t.IsZero() || (validTime(t) && t.UnixNano() > 0)
}

func validUpstreamSlotRow(sl UpstreamSlot, nextRunAt, updatedAt int64) bool {
	return sl.Slot >= minUpstreamSlot && sl.Slot <= maxUpstreamSlot &&
		validUpstreamOrigin(sl.Mode) &&
		(sl.ActiveVersionID == "" || upstreamIDPattern.MatchString(sl.ActiveVersionID)) &&
		sl.FailureCount >= 0 &&
		nextRunAt >= 0 &&
		(nextRunAt == 0 || validTime(sl.NextRunAt)) &&
		validUpstreamFailureCode(sl.LastErrorCode) &&
		updatedAt > 0 &&
		validTime(sl.UpdatedAt)
}

func scanUpstreamSlot(op string, row interface{ Scan(...any) error }) (UpstreamSlot, error) {
	var (
		sl                   UpstreamSlot
		nextRunAt, updatedAt int64
	)
	if err := row.Scan(
		&sl.Slot, &sl.Mode, &sl.ActiveVersionID, &sl.FailureCount,
		&nextRunAt, &sl.LastErrorCode, &updatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return UpstreamSlot{}, ErrNotFound
		}
		return UpstreamSlot{}, dbError(op, err)
	}
	if updatedAt > 0 {
		sl.UpdatedAt = time.Unix(0, updatedAt).UTC()
	}
	if nextRunAt > 0 {
		sl.NextRunAt = time.Unix(0, nextRunAt).UTC()
	}
	if !validUpstreamSlotRow(sl, nextRunAt, updatedAt) {
		return UpstreamSlot{}, fmt.Errorf("%w: upstream slot row", ErrCorrupt)
	}
	return sl, nil
}

// UpstreamSlot returns the persisted refresh state for slot, or ErrNotFound if never refreshed.
func (s *Store) UpstreamSlot(ctx context.Context, slot int) (UpstreamSlot, error) {
	if slot < minUpstreamSlot || slot > maxUpstreamSlot {
		return UpstreamSlot{}, invalid("upstream slot must be between %d and %d", minUpstreamSlot, maxUpstreamSlot)
	}
	row := s.db.QueryRowContext(ctx,
		`SELECT slot, mode, active_version_id, failure_count, next_run_at, last_error_code, updated_at
		 FROM upstream_slots
		 WHERE slot = ?`,
		slot)
	return scanUpstreamSlot("get upstream slot", row)
}

// ListUpstreamSlots returns all persisted upstream slot rows ordered by slot ascending.
func (s *Store) ListUpstreamSlots(ctx context.Context) ([]UpstreamSlot, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT slot, mode, active_version_id, failure_count, next_run_at, last_error_code, updated_at
		 FROM upstream_slots
		 ORDER BY slot ASC`)
	if err != nil {
		return nil, dbError("list upstream slots", err)
	}
	defer rows.Close()

	slots := []UpstreamSlot{}
	for rows.Next() {
		sl, err := scanUpstreamSlot("list upstream slots", rows)
		if err != nil {
			return nil, err
		}
		slots = append(slots, sl)
	}
	if err := rows.Err(); err != nil {
		return nil, dbError("list upstream slots", err)
	}
	return slots, nil
}

// RecordUpstreamFailure records a refresh failure for slot. Unknown slots are
// created in fail-closed blackhole mode; existing slots keep their mode and
// active_version_id while incrementing failure_count.
func (s *Store) RecordUpstreamFailure(ctx context.Context, slot int, code string, nextRun, now time.Time) (UpstreamSlot, error) {
	switch {
	case slot < minUpstreamSlot || slot > maxUpstreamSlot:
		return UpstreamSlot{}, invalid("upstream slot must be between %d and %d", minUpstreamSlot, maxUpstreamSlot)
	case !upstreamFailureCodePattern.MatchString(code):
		return UpstreamSlot{}, invalid("error code must match %s", upstreamFailureCodePattern)
	case !validOptionalUpstreamTime(nextRun):
		return UpstreamSlot{}, invalid("next run timestamp must be zero or valid")
	case !validTime(now) || now.UnixNano() <= 0:
		return UpstreamSlot{}, invalid("timestamp must be valid and after Unix epoch")
	}

	var nextRunNano int64
	if !nextRun.IsZero() {
		nextRunNano = nextRun.UTC().UnixNano()
	}
	nowNano := now.UTC().UnixNano()

	row := s.db.QueryRowContext(ctx,
		`INSERT INTO upstream_slots (slot, mode, failure_count, next_run_at, last_error_code, updated_at)
		 VALUES (?, 'blackhole', 1, ?, ?, ?)
		 ON CONFLICT(slot) DO UPDATE SET
		     failure_count = upstream_slots.failure_count + 1,
		     next_run_at = excluded.next_run_at,
		     last_error_code = excluded.last_error_code,
		     updated_at = excluded.updated_at
		 RETURNING slot, mode, active_version_id, failure_count, next_run_at, last_error_code, updated_at`,
		slot, nextRunNano, code, nowNano)
	return scanUpstreamSlot("record upstream failure", row)
}

// ScheduleUpstreamSlot updates next_run_at and updated_at for slot without
// modifying counters, error codes, mode, or active_version_id. Unknown slots
// are created in blackhole mode with failure_count 0.
func (s *Store) ScheduleUpstreamSlot(ctx context.Context, slot int, nextRun, now time.Time) error {
	switch {
	case slot < minUpstreamSlot || slot > maxUpstreamSlot:
		return invalid("upstream slot must be between %d and %d", minUpstreamSlot, maxUpstreamSlot)
	case !validOptionalUpstreamTime(nextRun):
		return invalid("next run timestamp must be zero or valid")
	case !validTime(now) || now.UnixNano() <= 0:
		return invalid("timestamp must be valid and after Unix epoch")
	}

	var nextRunNano int64
	if !nextRun.IsZero() {
		nextRunNano = nextRun.UTC().UnixNano()
	}
	nowNano := now.UTC().UnixNano()

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO upstream_slots (slot, mode, failure_count, next_run_at, updated_at)
		 VALUES (?, 'blackhole', 0, ?, ?)
		 ON CONFLICT(slot) DO UPDATE SET
		     next_run_at = excluded.next_run_at,
		     updated_at = excluded.updated_at`,
		slot, nextRunNano, nowNano)
	if err != nil {
		return dbError("schedule upstream slot", err)
	}
	return nil
}
