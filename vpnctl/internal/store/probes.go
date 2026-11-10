package store

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"time"
)

// MaxLimit is the largest result limit accepted by list queries.
const MaxLimit = 1000

// Family is the IP address family a probe used.
type Family string

// Probe address families.
const (
	FamilyIPv4 Family = "ipv4"
	FamilyIPv6 Family = "ipv6"
)

// Outcome is the observed result of a probe.
type Outcome string

// Probe outcomes.
const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
	OutcomeTimeout Outcome = "timeout"
)

// ProbeRecord is one probe observation. It intentionally has no field for
// response bodies or free-form error messages.
type ProbeRecord struct {
	// ID is assigned by AppendProbe; any value passed in is ignored.
	ID int64
	// Target is a label such as a node name, not an address or URL.
	Target string
	// Stage is the probe stage, for example "tcp", "tls" or "http".
	Stage      string
	Family     Family
	Outcome    Outcome
	ObservedAt time.Time
	Duration   time.Duration
	Bytes      int64
	// ErrorCode is a short code such as "connection_refused". It is required
	// for failure and timeout outcomes and must be empty for success.
	ErrorCode string
}

var (
	targetPattern    = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]{0,61}[A-Za-z0-9])?$`)
	tokenPattern     = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	errorCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	maxTime          = time.Unix(0, math.MaxInt64)
)

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalidArgument}, args...)...)
}

func validTime(t time.Time) bool {
	return !t.Before(time.Unix(0, 0)) && !t.After(maxTime)
}

func validateProbe(r ProbeRecord) error {
	switch {
	case !targetPattern.MatchString(r.Target):
		return invalid("probe target must match %s", targetPattern)
	case !tokenPattern.MatchString(r.Stage):
		return invalid("probe stage must match %s", tokenPattern)
	case r.Family != FamilyIPv4 && r.Family != FamilyIPv6:
		return invalid("probe family must be %s or %s", FamilyIPv4, FamilyIPv6)
	case !validTime(r.ObservedAt):
		return invalid("probe observation time must be between the Unix epoch and year 2262")
	case r.Duration < 0:
		return invalid("probe duration must not be negative")
	case r.Bytes < 0:
		return invalid("probe byte count must not be negative")
	}
	switch r.Outcome {
	case OutcomeSuccess:
		if r.ErrorCode != "" {
			return invalid("successful probe must not have an error code")
		}
	case OutcomeFailure, OutcomeTimeout:
		if !errorCodePattern.MatchString(r.ErrorCode) {
			return invalid("probe error code must match %s", errorCodePattern)
		}
	default:
		return invalid("probe outcome must be %s, %s or %s", OutcomeSuccess, OutcomeFailure, OutcomeTimeout)
	}
	return nil
}

// AppendProbe stores r and returns it with its assigned ID. ObservedAt is
// returned in UTC.
func (s *Store) AppendProbe(ctx context.Context, r ProbeRecord) (ProbeRecord, error) {
	if err := validateProbe(r); err != nil {
		return ProbeRecord{}, err
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO probes (target, stage, family, outcome, observed_at, duration_ns, bytes, error_code)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		r.Target, r.Stage, string(r.Family), string(r.Outcome),
		r.ObservedAt.UnixNano(), int64(r.Duration), r.Bytes, r.ErrorCode)
	if err != nil {
		return ProbeRecord{}, dbError("append probe", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return ProbeRecord{}, dbError("append probe", err)
	}
	r.ID = id
	r.ObservedAt = time.Unix(0, r.ObservedAt.UnixNano()).UTC()
	return r, nil
}

// LatestProbes returns up to limit observations for target, newest first.
// Ties on ObservedAt are ordered by descending ID. limit must be from 1
// through MaxLimit.
func (s *Store) LatestProbes(ctx context.Context, target string, limit int) ([]ProbeRecord, error) {
	if !targetPattern.MatchString(target) {
		return nil, invalid("probe target must match %s", targetPattern)
	}
	if limit < 1 || limit > MaxLimit {
		return nil, invalid("limit must be from 1 through %d", MaxLimit)
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, target, stage, family, outcome, observed_at, duration_ns, bytes, error_code
		 FROM probes WHERE target = ?
		 ORDER BY observed_at DESC, id DESC
		 LIMIT ?`, target, limit)
	if err != nil {
		return nil, dbError("query probes", err)
	}
	defer rows.Close()

	var out []ProbeRecord
	for rows.Next() {
		var (
			r                      ProbeRecord
			family, outcome        string
			observedAt, durationNS int64
		)
		if err := rows.Scan(&r.ID, &r.Target, &r.Stage, &family, &outcome,
			&observedAt, &durationNS, &r.Bytes, &r.ErrorCode); err != nil {
			return nil, fmt.Errorf("%w: probe row: %v", ErrCorrupt, err)
		}
		r.Family, r.Outcome = Family(family), Outcome(outcome)
		r.ObservedAt = time.Unix(0, observedAt).UTC()
		r.Duration = time.Duration(durationNS)
		if err := validateProbe(r); err != nil {
			return nil, fmt.Errorf("%w: probe %d", ErrCorrupt, r.ID)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, dbError("query probes", err)
	}
	return out, nil
}
