package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"time"
)

const (
	minUpstreamSlot = 1
	maxUpstreamSlot = 63
)

var (
	upstreamIDPattern          = regexp.MustCompile(`^[0-9a-f]{32}$`)
	upstreamHex64Pattern       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	upstreamPayloadRefPattern  = regexp.MustCompile(`^[\x21-\x7e]{1,128}$`)
	upstreamFailureCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

// UpstreamVersion is the persisted metadata of an immutable encrypted upstream
// configuration version for a slot.
type UpstreamVersion struct {
	ID                  string
	Slot                int
	Seq                 int64
	Origin              string
	State               string
	PayloadRef          string
	PayloadSHA256       string
	OutboundFingerprint string
	FailureCode         string
	CreatedAt           time.Time
	ActivatedAt         time.Time
	RetiredAt           time.Time
}

func validUpstreamOrigin(origin string) bool {
	return origin == "upstream" || origin == "blackhole"
}

func validUpstreamState(state string) bool {
	switch state {
	case "candidate", "active", "superseded", "failed":
		return true
	}
	return false
}

func validUpstreamFailureCode(code string) bool {
	return code == "" || upstreamFailureCodePattern.MatchString(code)
}

func validUpstreamVersionRow(v UpstreamVersion, createdAt, activatedAt, retiredAt int64) bool {
	return upstreamIDPattern.MatchString(v.ID) &&
		v.Slot >= minUpstreamSlot && v.Slot <= maxUpstreamSlot &&
		v.Seq >= 1 &&
		validUpstreamOrigin(v.Origin) &&
		validUpstreamState(v.State) &&
		upstreamPayloadRefPattern.MatchString(v.PayloadRef) &&
		upstreamHex64Pattern.MatchString(v.PayloadSHA256) &&
		upstreamHex64Pattern.MatchString(v.OutboundFingerprint) &&
		validUpstreamFailureCode(v.FailureCode) &&
		createdAt > 0 &&
		activatedAt >= 0 &&
		retiredAt >= 0
}

func scanUpstreamVersion(op string, row interface{ Scan(...any) error }) (UpstreamVersion, error) {
	var (
		v                                 UpstreamVersion
		createdAt, activatedAt, retiredAt int64
	)
	if err := row.Scan(
		&v.ID, &v.Slot, &v.Seq, &v.Origin, &v.State,
		&v.PayloadRef, &v.PayloadSHA256, &v.OutboundFingerprint,
		&v.FailureCode, &createdAt, &activatedAt, &retiredAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return UpstreamVersion{}, ErrNotFound
		}
		return UpstreamVersion{}, dbError(op, err)
	}
	if !validUpstreamVersionRow(v, createdAt, activatedAt, retiredAt) {
		return UpstreamVersion{}, fmt.Errorf("%w: upstream version row", ErrCorrupt)
	}
	v.CreatedAt = time.Unix(0, createdAt).UTC()
	if activatedAt > 0 {
		v.ActivatedAt = time.Unix(0, activatedAt).UTC()
	}
	if retiredAt > 0 {
		v.RetiredAt = time.Unix(0, retiredAt).UTC()
	}
	return v, nil
}

// ListUpstreamVersions returns up to limit versions of one slot, newest seq first.
// limit must be 1..MaxLimit (1000), otherwise ErrInvalidArgument.
// slot must be 1..63, otherwise ErrInvalidArgument.
func (s *Store) ListUpstreamVersions(ctx context.Context, slot, limit int) ([]UpstreamVersion, error) {
	if slot < minUpstreamSlot || slot > maxUpstreamSlot {
		return nil, invalid("upstream slot must be between %d and %d", minUpstreamSlot, maxUpstreamSlot)
	}
	if limit < 1 || limit > MaxLimit {
		return nil, invalid("limit must be between 1 and %d", MaxLimit)
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, slot, seq, origin, state, payload_ref, payload_sha256,
		        outbound_fingerprint, failure_code, created_at, activated_at, retired_at
		 FROM upstream_versions
		 WHERE slot = ?
		 ORDER BY seq DESC
		 LIMIT ?`,
		slot, limit)
	if err != nil {
		return nil, dbError("list upstream versions", err)
	}
	defer rows.Close()

	versions := []UpstreamVersion{}
	for rows.Next() {
		v, err := scanUpstreamVersion("list upstream versions", rows)
		if err != nil {
			return nil, err
		}
		versions = append(versions, v)
	}
	if err := rows.Err(); err != nil {
		return nil, dbError("list upstream versions", err)
	}
	return versions, nil
}

// GetUpstreamVersion returns the upstream version with the given ID or ErrNotFound.
func (s *Store) GetUpstreamVersion(ctx context.Context, id string) (UpstreamVersion, error) {
	if !upstreamIDPattern.MatchString(id) {
		return UpstreamVersion{}, invalid("upstream version ID must match %s", upstreamIDPattern)
	}
	row := s.db.QueryRowContext(ctx,
		`SELECT id, slot, seq, origin, state, payload_ref, payload_sha256,
		        outbound_fingerprint, failure_code, created_at, activated_at, retired_at
		 FROM upstream_versions
		 WHERE id = ?`,
		id)
	return scanUpstreamVersion("get upstream version", row)
}

// ActiveUpstreamVersion returns the active upstream version for slot or ErrNotFound.
func (s *Store) ActiveUpstreamVersion(ctx context.Context, slot int) (UpstreamVersion, error) {
	if slot < minUpstreamSlot || slot > maxUpstreamSlot {
		return UpstreamVersion{}, invalid("upstream slot must be between %d and %d", minUpstreamSlot, maxUpstreamSlot)
	}
	row := s.db.QueryRowContext(ctx,
		`SELECT id, slot, seq, origin, state, payload_ref, payload_sha256,
		        outbound_fingerprint, failure_code, created_at, activated_at, retired_at
		 FROM upstream_versions
		 WHERE slot = ? AND state = 'active'`,
		slot)
	return scanUpstreamVersion("get active upstream version", row)
}

// CreateUpstreamVersion validates and stores a new candidate version. When
// v.ID is empty a random 32-hex ID is assigned. Seq is max(seq)+1 for the slot.
func (s *Store) CreateUpstreamVersion(ctx context.Context, v UpstreamVersion, now time.Time) (UpstreamVersion, error) {
	switch {
	case v.ID != "" && !upstreamIDPattern.MatchString(v.ID):
		return UpstreamVersion{}, invalid("upstream version ID must be empty or match %s", upstreamIDPattern)
	case v.Slot < minUpstreamSlot || v.Slot > maxUpstreamSlot:
		return UpstreamVersion{}, invalid("upstream slot must be between %d and %d", minUpstreamSlot, maxUpstreamSlot)
	case !validUpstreamOrigin(v.Origin):
		return UpstreamVersion{}, invalid("upstream origin must be upstream or blackhole")
	case !upstreamPayloadRefPattern.MatchString(v.PayloadRef):
		return UpstreamVersion{}, invalid("payload ref must match %s", upstreamPayloadRefPattern)
	case !upstreamHex64Pattern.MatchString(v.PayloadSHA256):
		return UpstreamVersion{}, invalid("payload SHA-256 must match %s", upstreamHex64Pattern)
	case !upstreamHex64Pattern.MatchString(v.OutboundFingerprint):
		return UpstreamVersion{}, invalid("outbound fingerprint must match %s", upstreamHex64Pattern)
	case v.FailureCode != "":
		return UpstreamVersion{}, invalid("failure code must be empty for a new upstream version")
	case !validTime(now) || now.UnixNano() <= 0:
		return UpstreamVersion{}, invalid("timestamp must be valid and after Unix epoch")
	}

	id := v.ID
	if id == "" {
		var b [16]byte
		rand.Read(b[:])
		id = hex.EncodeToString(b[:])
	}
	createdAt := time.Unix(0, now.UnixNano()).UTC()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return UpstreamVersion{}, dbError("begin create upstream version", err)
	}
	defer tx.Rollback()

	var maxSeq int64
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(seq), 0) FROM upstream_versions WHERE slot = ?`,
		v.Slot,
	).Scan(&maxSeq); err != nil {
		return UpstreamVersion{}, dbError("next upstream version seq", err)
	}

	out := UpstreamVersion{
		ID:                  id,
		Slot:                v.Slot,
		Seq:                 maxSeq + 1,
		Origin:              v.Origin,
		State:               "candidate",
		PayloadRef:          v.PayloadRef,
		PayloadSHA256:       v.PayloadSHA256,
		OutboundFingerprint: v.OutboundFingerprint,
		CreatedAt:           createdAt,
	}
	_, err = tx.ExecContext(ctx,
		`INSERT INTO upstream_versions (
			id, slot, seq, origin, state, payload_ref, payload_sha256,
			outbound_fingerprint, failure_code, created_at, activated_at, retired_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0)`,
		out.ID, out.Slot, out.Seq, out.Origin, out.State,
		out.PayloadRef, out.PayloadSHA256, out.OutboundFingerprint,
		out.FailureCode, createdAt.UnixNano(),
	)
	if err != nil {
		return UpstreamVersion{}, dbError("create upstream version", err)
	}
	if err := tx.Commit(); err != nil {
		return UpstreamVersion{}, dbError("commit create upstream version", err)
	}
	return out, nil
}

// ActivateUpstreamVersion makes a candidate version the single active version
// of its slot, supersedes the previous active version, and upserts upstream_slots.
// It returns (new active, previous active or nil).
func (s *Store) ActivateUpstreamVersion(ctx context.Context, id string, now time.Time) (UpstreamVersion, *UpstreamVersion, error) {
	if !upstreamIDPattern.MatchString(id) {
		return UpstreamVersion{}, nil, invalid("upstream version ID must match %s", upstreamIDPattern)
	}
	if !validTime(now) || now.UnixNano() <= 0 {
		return UpstreamVersion{}, nil, invalid("timestamp must be valid and after Unix epoch")
	}

	nowUTC := time.Unix(0, now.UnixNano()).UTC()
	nowNano := nowUTC.UnixNano()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return UpstreamVersion{}, nil, dbError("begin activate upstream version", err)
	}
	defer tx.Rollback()

	target, err := scanUpstreamVersion("get upstream version", tx.QueryRowContext(ctx,
		`SELECT id, slot, seq, origin, state, payload_ref, payload_sha256,
		        outbound_fingerprint, failure_code, created_at, activated_at, retired_at
		 FROM upstream_versions
		 WHERE id = ?`,
		id))
	if err != nil {
		return UpstreamVersion{}, nil, err
	}
	if target.State != "candidate" {
		return UpstreamVersion{}, nil, fmt.Errorf("%w: %s to active", ErrInvalidTransition, target.State)
	}

	var prev *UpstreamVersion
	cur, err := scanUpstreamVersion("get active upstream version", tx.QueryRowContext(ctx,
		`SELECT id, slot, seq, origin, state, payload_ref, payload_sha256,
		        outbound_fingerprint, failure_code, created_at, activated_at, retired_at
		 FROM upstream_versions
		 WHERE slot = ? AND state = 'active'`,
		target.Slot))
	if err != nil && !errors.Is(err, ErrNotFound) {
		return UpstreamVersion{}, nil, err
	}
	if err == nil {
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
		cur.State = "superseded"
		cur.RetiredAt = nowUTC
		prev = &cur
	}

	res, err := tx.ExecContext(ctx,
		`UPDATE upstream_versions
		 SET state = 'active', activated_at = ?, retired_at = 0
		 WHERE id = ? AND state = 'candidate'`,
		nowNano, target.ID)
	if err != nil {
		return UpstreamVersion{}, nil, dbError("activate upstream version", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return UpstreamVersion{}, nil, dbError("activate upstream version", err)
	} else if n != 1 {
		return UpstreamVersion{}, nil, ErrConflict
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO upstream_slots (slot, mode, active_version_id, failure_count, last_error_code, updated_at)
		 VALUES (?, ?, ?, 0, '', ?)
		 ON CONFLICT(slot) DO UPDATE SET
		     mode = excluded.mode,
		     active_version_id = excluded.active_version_id,
		     failure_count = 0,
		     last_error_code = '',
		     updated_at = excluded.updated_at`,
		target.Slot, target.Origin, target.ID, nowNano)
	if err != nil {
		return UpstreamVersion{}, nil, dbError("upsert upstream slot", err)
	}

	if err := tx.Commit(); err != nil {
		return UpstreamVersion{}, nil, dbError("commit activate upstream version", err)
	}

	target.State = "active"
	target.ActivatedAt = nowUTC
	target.RetiredAt = time.Time{}
	return target, prev, nil
}
