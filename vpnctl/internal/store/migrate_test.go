package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestFailedMigrationRollsBack(t *testing.T) {
	ctx := context.Background()
	path := tempPath(t)
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	op, err := s.CreateOperation(ctx, "rotate_ip", "")
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	errBoom := errors.New("boom")
	failing := append(migrations[:len(migrations):len(migrations)],
		func(ctx context.Context, tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, "CREATE TABLE partial (x INTEGER)"); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, "DELETE FROM operations"); err != nil {
				return err
			}
			return errBoom
		})
	if s, err := open(ctx, path, failing); !errors.Is(err, errBoom) {
		if err == nil {
			s.Close()
		}
		t.Fatalf("open with failing migration err = %v, want %v", err, errBoom)
	}

	s, err = Open(ctx, path)
	if err != nil {
		t.Fatalf("Open after failed migration: %v", err)
	}
	defer s.Close()
	if got := pragmaInt(t, s.db, "user_version"); got != int64(len(migrations)) {
		t.Errorf("user_version = %d, want %d", got, len(migrations))
	}
	if tableExists(t, s.db, "partial") {
		t.Error("table from failed migration exists")
	}
	if _, err := s.GetOperation(ctx, op.ID); err != nil {
		t.Errorf("row deleted by failed migration is missing: %v", err)
	}
}

func TestFailedInitialMigrationRemovesNewFile(t *testing.T) {
	path := tempPath(t)
	errBoom := errors.New("boom")
	failing := []migration{func(ctx context.Context, tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "CREATE TABLE partial (x INTEGER)"); err != nil {
			return err
		}
		return errBoom
	}}
	if s, err := open(context.Background(), path, failing); !errors.Is(err, errBoom) {
		if err == nil {
			s.Close()
		}
		t.Fatalf("err = %v, want %v", err, errBoom)
	}
	for _, p := range []string{path, path + "-journal", path + "-wal", path + "-shm"} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s left behind after failed initialization", p)
		}
	}
}

func TestMigrationAppliesPendingVersionsOnly(t *testing.T) {
	ctx := context.Background()
	path := tempPath(t)
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	calls := 0
	next := append(migrations[:len(migrations):len(migrations)],
		func(ctx context.Context, tx *sql.Tx) error {
			calls++
			_, err := tx.ExecContext(ctx, "CREATE TABLE added (x INTEGER)")
			return err
		})
	for i := 0; i < 2; i++ {
		s, err := open(ctx, path, next)
		if err != nil {
			t.Fatal(err)
		}
		if got := pragmaInt(t, s.db, "user_version"); got != int64(len(next)) {
			t.Errorf("user_version = %d, want %d", got, len(next))
		}
		if !tableExists(t, s.db, "added") {
			t.Error("migrated table missing")
		}
		s.Close()
	}
	if calls != 1 {
		t.Errorf("new migration ran %d times, want 1", calls)
	}

	// The original build now sees a newer schema and must refuse it.
	if s, err := Open(ctx, path); !errors.Is(err, ErrUnsupportedSchema) {
		if err == nil {
			s.Close()
		}
		t.Errorf("older build Open err = %v, want ErrUnsupportedSchema", err)
	}
}

func TestMigrationFivePreservesExistingState(t *testing.T) {
	ctx := context.Background()
	path := tempPath(t)

	s, err := open(ctx, path, migrations[:4])
	if err != nil {
		t.Fatal(err)
	}
	probe, err := s.AppendProbe(ctx, ProbeRecord{
		Target:     "node-1",
		Stage:      "connect",
		Family:     Family("ipv4"),
		Outcome:    Outcome("success"),
		ObservedAt: time.Unix(1700000000, 0).UTC(),
		Duration:   10 * time.Millisecond,
		Bytes:      1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	op, err := s.CreateOperation(ctx, "rotate_ip", "")
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := s.ClaimBotUpdate(ctx, 42)
	if err != nil || !claimed {
		t.Fatalf("ClaimBotUpdate(42) = (%v, %v), want (true, nil)", claimed, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = Open(ctx, path)
	if err != nil {
		t.Fatalf("Open to migrate to v5: %v", err)
	}
	defer s.Close()

	if got := pragmaInt(t, s.db, "user_version"); got != 5 {
		t.Errorf("user_version = %d, want 5", got)
	}
	probes, err := s.LatestProbes(ctx, "node-1", 10)
	if err != nil {
		t.Fatalf("LatestProbes after migration: %v", err)
	}
	if len(probes) != 1 || probes[0].ID != probe.ID {
		t.Errorf("LatestProbes = %+v, want single probe ID %d", probes, probe.ID)
	}
	if _, err := s.GetOperation(ctx, op.ID); err != nil {
		t.Errorf("GetOperation after migration: %v", err)
	}
	claimed, err = s.ClaimBotUpdate(ctx, 42)
	if err != nil || claimed {
		t.Errorf("ClaimBotUpdate(42) after migration = (%v, %v), want (false, nil)", claimed, err)
	}
	for _, table := range []string{"upstream_versions", "upstream_slots"} {
		if !tableExists(t, s.db, table) {
			t.Errorf("table %s missing after migration", table)
		}
	}

	const insertVersion = `INSERT INTO upstream_versions (
		id, slot, seq, origin, state, payload_ref, payload_sha256, outbound_fingerprint, created_at
	) VALUES (?, ?, ?, 'upstream', ?, 'enc/payload', ?, ?, 1700000000)`
	id1 := strings.Repeat("1", 32)
	id2 := strings.Repeat("2", 32)
	id3 := strings.Repeat("3", 32)
	id4 := strings.Repeat("4", 32)
	sha := strings.Repeat("a", 64)
	fp := strings.Repeat("b", 64)

	if _, err := s.db.ExecContext(ctx, insertVersion, id1, 1, 1, "active", sha, fp); err != nil {
		t.Fatalf("insert active version for slot 1: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, insertVersion, id2, 1, 2, "candidate", sha, fp); err != nil {
		t.Fatalf("insert candidate version for slot 1: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, insertVersion, id3, 1, 3, "active", sha, fp); err == nil {
		t.Error("second active version for slot 1 succeeded, want error")
	}
	if _, err := s.db.ExecContext(ctx, insertVersion, id4, 2, 1, "active", sha, fp); err != nil {
		t.Errorf("insert active version for slot 2: %v", err)
	}

	const insertSlot = `INSERT INTO upstream_slots (slot, mode, active_version_id, updated_at)
		VALUES (?, 'upstream', ?, 1700000000)`
	if _, err := s.db.ExecContext(ctx, insertSlot, 1, id1); err != nil {
		t.Errorf("insert upstream_slots slot 1: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, insertSlot, 0, ""); err == nil {
		t.Error("insert upstream_slots slot 0 succeeded, want CHECK error")
	}
}
