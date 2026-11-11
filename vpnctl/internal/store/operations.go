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

// State is the lifecycle state of an operation.
type State string

// Operation states: pending -> running -> succeeded | failed.
const (
	StatePending   State = "pending"
	StateRunning   State = "running"
	StateSucceeded State = "succeeded"
	StateFailed    State = "failed"
)

// Terminal reports whether no further transition is allowed from st.
func (st State) Terminal() bool {
	return st == StateSucceeded || st == StateFailed
}

func (st State) valid() bool {
	switch st {
	case StatePending, StateRunning, StateSucceeded, StateFailed:
		return true
	}
	return false
}

// Operation is the persisted metadata of a resumable operation. It holds no
// operation parameters or results.
type Operation struct {
	ID    string
	Kind  string
	State State
	// Step is the current step token; empty when no step has started.
	Step string
	// Revision starts at 1 and increases by one on every successful update.
	Revision  int64
	CreatedAt time.Time
	UpdatedAt time.Time
}

var operationIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

func validStep(step string) bool {
	return step == "" || tokenPattern.MatchString(step)
}

// CreateOperation stores a new pending operation with revision 1.
func (s *Store) CreateOperation(ctx context.Context, kind, step string) (Operation, error) {
	if !tokenPattern.MatchString(kind) {
		return Operation{}, invalid("operation kind must match %s", tokenPattern)
	}
	if !validStep(step) {
		return Operation{}, invalid("operation step must be empty or match %s", tokenPattern)
	}
	var b [16]byte
	rand.Read(b[:])
	now := time.Unix(0, time.Now().UnixNano()).UTC()
	op := Operation{
		ID:        hex.EncodeToString(b[:]),
		Kind:      kind,
		State:     StatePending,
		Step:      step,
		Revision:  1,
		CreatedAt: now,
		UpdatedAt: now,
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO operations (id, kind, state, step, revision, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		op.ID, op.Kind, string(op.State), op.Step, op.Revision, now.UnixNano(), now.UnixNano())
	if err != nil {
		return Operation{}, dbError("create operation", err)
	}
	return op, nil
}

// GetOperation returns the operation with the given ID or ErrNotFound.
func (s *Store) GetOperation(ctx context.Context, id string) (Operation, error) {
	if !operationIDPattern.MatchString(id) {
		return Operation{}, invalid("operation ID must match %s", operationIDPattern)
	}
	return getOperation(ctx, s.db, id)
}

type queryRower interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func getOperation(ctx context.Context, q queryRower, id string) (Operation, error) {
	var (
		op                   Operation
		state                string
		createdAt, updatedAt int64
	)
	err := q.QueryRowContext(ctx,
		`SELECT id, kind, state, step, revision, created_at, updated_at
		 FROM operations WHERE id = ?`, id).
		Scan(&op.ID, &op.Kind, &state, &op.Step, &op.Revision, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Operation{}, ErrNotFound
	}
	if err != nil {
		return Operation{}, dbError("get operation", err)
	}
	op.State = State(state)
	op.CreatedAt = time.Unix(0, createdAt).UTC()
	op.UpdatedAt = time.Unix(0, updatedAt).UTC()
	if !operationIDPattern.MatchString(op.ID) || !tokenPattern.MatchString(op.Kind) ||
		!op.State.valid() || !validStep(op.Step) || op.Revision < 1 {
		return Operation{}, fmt.Errorf("%w: operation row", ErrCorrupt)
	}
	return op, nil
}

func checkTransition(from, to State, fromStep, toStep string) error {
	if from.Terminal() {
		return ErrTerminal
	}
	switch {
	case from == StatePending && to == StateRunning:
	case from == StateRunning && to == StateRunning && toStep != fromStep:
	case from == StateRunning && to.Terminal():
	default:
		return fmt.Errorf("%w: %s to %s", ErrInvalidTransition, from, to)
	}
	return nil
}

// UpdateOperation moves operation id to state next with step, provided its
// current revision equals expectedRevision. Allowed changes are pending to
// running, running to running with a different step, and running to
// succeeded or failed. On success the revision is incremented and the updated
// operation is returned.
//
// Errors: ErrNotFound for an unknown ID, ErrConflict for a stale revision,
// ErrTerminal for a finished operation and ErrInvalidTransition otherwise.
// A failed update changes nothing.
func (s *Store) UpdateOperation(ctx context.Context, id string, expectedRevision int64, next State, step string) (Operation, error) {
	switch {
	case !operationIDPattern.MatchString(id):
		return Operation{}, invalid("operation ID must match %s", operationIDPattern)
	case expectedRevision < 1:
		return Operation{}, invalid("expected revision must be positive")
	case !next.valid():
		return Operation{}, invalid("unknown operation state")
	case !validStep(step):
		return Operation{}, invalid("operation step must be empty or match %s", tokenPattern)
	}

	// _txlock=immediate takes the write lock at BEGIN, so the read below and
	// the update are serialized against other connections.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Operation{}, dbError("begin update", err)
	}
	defer tx.Rollback()

	cur, err := getOperation(ctx, tx, id)
	if err != nil {
		return Operation{}, err
	}
	if cur.Revision != expectedRevision {
		return Operation{}, ErrConflict
	}
	if err := checkTransition(cur.State, next, cur.Step, step); err != nil {
		return Operation{}, err
	}

	now := time.Unix(0, time.Now().UnixNano()).UTC()
	res, err := tx.ExecContext(ctx,
		`UPDATE operations SET state = ?, step = ?, revision = revision + 1, updated_at = ?
		 WHERE id = ? AND revision = ?`,
		string(next), step, now.UnixNano(), id, expectedRevision)
	if err != nil {
		return Operation{}, dbError("update operation", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return Operation{}, dbError("update operation", err)
	} else if n != 1 {
		return Operation{}, ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return Operation{}, dbError("commit update", err)
	}

	cur.State, cur.Step, cur.Revision, cur.UpdatedAt = next, step, expectedRevision+1, now
	return cur, nil
}
