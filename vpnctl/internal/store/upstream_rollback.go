package store

import (
	"context"
	"fmt"
	"regexp"
	"time"
)

var upstreamFailCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// FailUpstreamVersion marks a candidate version failed. Only candidate -> failed is allowed.
func (s *Store) FailUpstreamVersion(ctx context.Context, id, code string, now time.Time) error {
	if !upstreamIDPattern.MatchString(id) {
		return invalid("upstream version ID must match %s", upstreamIDPattern)
	}
	if !upstreamFailCodePattern.MatchString(code) {
		return invalid("failure code must match %s", upstreamFailCodePattern)
	}
	if !validTime(now) || now.UnixNano() <= 0 {
		return invalid("timestamp must be valid and after Unix epoch")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return dbError("begin fail upstream version", err)
	}
	defer tx.Rollback()

	target, err := scanUpstreamVersion("get upstream version", tx.QueryRowContext(ctx,
		`SELECT id, slot, seq, origin, state, payload_ref, payload_sha256,
		        outbound_fingerprint, failure_code, created_at, activated_at, retired_at
		 FROM upstream_versions
		 WHERE id = ?`,
		id))
	if err != nil {
		return err
	}
	if target.State != "candidate" {
		return fmt.Errorf("%w: %s to failed", ErrInvalidTransition, target.State)
	}

	res, err := tx.ExecContext(ctx,
		`UPDATE upstream_versions
		 SET state = 'failed', failure_code = ?
		 WHERE id = ? AND state = 'candidate'`,
		code, target.ID)
	if err != nil {
		return dbError("fail upstream version", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return dbError("fail upstream version", err)
	} else if n != 1 {
		return ErrConflict
	}

	if err := tx.Commit(); err != nil {
		return dbError("commit fail upstream version", err)
	}
	return nil
}

// RollbackUpstreamSlot supersedes the current active version and reactivates the
// most recent superseded upstream version of the slot. A blackhole version is
// never restored. Returns (restored, previous active).
func (s *Store) RollbackUpstreamSlot(ctx context.Context, slot int, now time.Time) (UpstreamVersion, *UpstreamVersion, error) {
	if slot < minUpstreamSlot || slot > maxUpstreamSlot {
		return UpstreamVersion{}, nil, invalid("upstream slot must be between %d and %d", minUpstreamSlot, maxUpstreamSlot)
	}
	if !validTime(now) || now.UnixNano() <= 0 {
		return UpstreamVersion{}, nil, invalid("timestamp must be valid and after Unix epoch")
	}

	nowUTC := time.Unix(0, now.UnixNano()).UTC()
	nowNano := nowUTC.UnixNano()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return UpstreamVersion{}, nil, dbError("begin rollback upstream slot", err)
	}
	defer tx.Rollback()

	cur, err := scanUpstreamVersion("get active upstream version", tx.QueryRowContext(ctx,
		`SELECT id, slot, seq, origin, state, payload_ref, payload_sha256,
		        outbound_fingerprint, failure_code, created_at, activated_at, retired_at
		 FROM upstream_versions
		 WHERE slot = ? AND state = 'active'`,
		slot))
	if err != nil {
		return UpstreamVersion{}, nil, err
	}

	target, err := scanUpstreamVersion("get rollback target upstream version", tx.QueryRowContext(ctx,
		`SELECT id, slot, seq, origin, state, payload_ref, payload_sha256,
		        outbound_fingerprint, failure_code, created_at, activated_at, retired_at
		 FROM upstream_versions
		 WHERE slot = ? AND origin = 'upstream' AND state = 'superseded' AND seq < ?
		 ORDER BY seq DESC
		 LIMIT 1`,
		slot, cur.Seq))
	if err != nil {
		return UpstreamVersion{}, nil, err
	}

	res, err := tx.ExecContext(ctx,
		`UPDATE upstream_versions
		 SET state = 'superseded', retired_at = ?
		 WHERE id = ? AND state = 'active'`,
		nowNano, cur.ID)
	if err != nil {
		return UpstreamVersion{}, nil, dbError("supersede active upstream version", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return UpstreamVersion{}, nil, dbError("supersede active upstream version", err)
	} else if n != 1 {
		return UpstreamVersion{}, nil, ErrConflict
	}

	res, err = tx.ExecContext(ctx,
		`UPDATE upstream_versions
		 SET state = 'active', activated_at = ?, retired_at = 0
		 WHERE id = ? AND state = 'superseded'`,
		nowNano, target.ID)
	if err != nil {
		return UpstreamVersion{}, nil, dbError("restore upstream version", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return UpstreamVersion{}, nil, dbError("restore upstream version", err)
	} else if n != 1 {
		return UpstreamVersion{}, nil, ErrConflict
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO upstream_slots (slot, mode, active_version_id, failure_count, last_error_code, updated_at)
		 VALUES (?, 'upstream', ?, 0, '', ?)
		 ON CONFLICT(slot) DO UPDATE SET
		     mode = excluded.mode,
		     active_version_id = excluded.active_version_id,
		     failure_count = 0,
		     last_error_code = '',
		     updated_at = excluded.updated_at`,
		slot, target.ID, nowNano)
	if err != nil {
		return UpstreamVersion{}, nil, dbError("upsert upstream slot", err)
	}

	if err := tx.Commit(); err != nil {
		return UpstreamVersion{}, nil, dbError("commit rollback upstream slot", err)
	}

	cur.State = "superseded"
	cur.RetiredAt = nowUTC
	target.State = "active"
	target.ActivatedAt = nowUTC
	target.RetiredAt = time.Time{}
	return target, &cur, nil
}
