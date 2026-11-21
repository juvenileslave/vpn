package store

import (
	"context"
	"database/sql"
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

	var versions []UpstreamVersion
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
