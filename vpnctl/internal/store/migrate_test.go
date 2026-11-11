package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
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
