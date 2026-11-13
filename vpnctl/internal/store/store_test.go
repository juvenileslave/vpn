package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func tempPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "state.db")
}

func openTemp(t *testing.T) (*Store, string) {
	t.Helper()
	path := tempPath(t)
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

// rawDB opens path without the store, for setting up foreign or damaged files.
func rawDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func mustExec(t *testing.T, db *sql.DB, query string) {
	t.Helper()
	if _, err := db.Exec(query); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
}

func pragmaInt(t *testing.T, db *sql.DB, name string) int64 {
	t.Helper()
	var v int64
	if err := db.QueryRow("PRAGMA " + name).Scan(&v); err != nil {
		t.Fatalf("PRAGMA %s: %v", name, err)
	}
	return v
}

func tableExists(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, name).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestOpenCreatesPrivateDatabaseWithSettings(t *testing.T) {
	s, path := openTemp(t)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("database mode = %v, want no group/other access", perm)
	}

	var mode string
	if err := s.db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != "wal" {
		t.Errorf("journal_mode = %q, want wal", mode)
	}
	checks := map[string]int64{
		"busy_timeout":   BusyTimeout.Milliseconds(),
		"foreign_keys":   1,
		"synchronous":    2, // FULL
		"user_version":   int64(len(migrations)),
		"application_id": applicationID,
	}
	for name, want := range checks {
		if got := pragmaInt(t, s.db, name); got != want {
			t.Errorf("PRAGMA %s = %d, want %d", name, got, want)
		}
	}
	if got := s.db.Stats().MaxOpenConnections; got != 1 {
		t.Errorf("MaxOpenConnections = %d, want 1", got)
	}
}

func TestOpenPathCannotInjectDSNParameters(t *testing.T) {
	dir := t.TempDir()
	name := "x.db?_pragma=journal_mode(OFF)&mode=memory#frag"
	path := filepath.Join(dir, name)

	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	var mode string
	if err := s.db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != "wal" {
		t.Errorf("journal_mode = %q, want wal", mode)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("database not stored under the literal file name: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "x.db")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("truncated file name x.db was created")
	}
}

func TestOpenRejectsInvalidPaths(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"empty":       "",
		"nul":         "a\x00b",
		"directory":   dir,
		"missing dir": filepath.Join(dir, "missing", "state.db"),
	}
	for name, path := range cases {
		t.Run(name, func(t *testing.T) {
			if s, err := Open(context.Background(), path); err == nil {
				s.Close()
				t.Fatal("Open succeeded")
			}
		})
	}
	if _, err := os.Stat(filepath.Join(dir, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Error("missing parent directory was created")
	}
}

func TestReopenPersistsData(t *testing.T) {
	ctx := context.Background()
	path := tempPath(t)

	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	probe, err := s.AppendProbe(ctx, probeAt("exit-01", 1))
	if err != nil {
		t.Fatal(err)
	}
	op, err := s.CreateOperation(ctx, "rotate_ip", "")
	if err != nil {
		t.Fatal(err)
	}
	op, err = s.UpdateOperation(ctx, op.ID, 1, StateRunning, "create_ip")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetOperation(ctx, op.ID); err == nil {
		t.Error("GetOperation after Close succeeded")
	}

	s, err = Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s.Close()
	probes, err := s.LatestProbes(ctx, "exit-01", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(probes) != 1 || probes[0] != probe {
		t.Errorf("probes after reopen = %+v, want [%+v]", probes, probe)
	}
	got, err := s.GetOperation(ctx, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got != op {
		t.Errorf("operation after reopen = %+v, want %+v", got, op)
	}
	t.Logf("after reopen: operation state=%s step=%s revision=%d; %d probe(s)", got.State, got.Step, got.Revision, len(probes))

	// The persisted revision still guards the next update.
	if _, err := s.UpdateOperation(ctx, op.ID, 1, StateRunning, "poweroff"); !errors.Is(err, ErrConflict) {
		t.Errorf("stale update after reopen: err = %v, want ErrConflict", err)
	}
	if _, err := s.UpdateOperation(ctx, op.ID, 2, StateRunning, "poweroff"); err != nil {
		t.Errorf("current update after reopen: %v", err)
	}
}

func TestDatabasesAreIsolated(t *testing.T) {
	ctx := context.Background()
	a, _ := openTemp(t)
	b, _ := openTemp(t)

	if _, err := a.AppendProbe(ctx, probeAt("exit-01", 1)); err != nil {
		t.Fatal(err)
	}
	op, err := a.CreateOperation(ctx, "rotate_ip", "")
	if err != nil {
		t.Fatal(err)
	}
	probes, err := b.LatestProbes(ctx, "exit-01", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(probes) != 0 {
		t.Errorf("second database has %d probes", len(probes))
	}
	if _, err := b.GetOperation(ctx, op.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("second database GetOperation err = %v, want ErrNotFound", err)
	}
}

func TestOpenRejectsMalformedFilesWithoutChangingThem(t *testing.T) {
	cases := map[string]struct {
		setup func(t *testing.T, path string)
		want  error
	}{
		"text file": {
			setup: func(t *testing.T, path string) {
				if err := os.WriteFile(path, bytes.Repeat([]byte("not a database\n"), 400), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			want: ErrNotDatabase,
		},
		"truncated sqlite header": {
			setup: func(t *testing.T, path string) {
				data := append([]byte("SQLite format 3\x00"), bytes.Repeat([]byte{0xff}, 4096)...)
				if err := os.WriteFile(path, data, 0o644); err != nil {
					t.Fatal(err)
				}
			},
			want: ErrNotDatabase,
		},
		"foreign sqlite database": {
			setup: func(t *testing.T, path string) {
				db := rawDB(t, path)
				mustExec(t, db, "CREATE TABLE other (x INTEGER)")
				mustExec(t, db, "INSERT INTO other VALUES (1)")
				db.Close()
			},
			want: ErrForeignDatabase,
		},
		"newer schema": {
			setup: func(t *testing.T, path string) {
				s, err := Open(context.Background(), path)
				if err != nil {
					t.Fatal(err)
				}
				s.Close()
				db := rawDB(t, path)
				mustExec(t, db, "PRAGMA user_version = 99")
				db.Close()
			},
			want: ErrUnsupportedSchema,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			path := tempPath(t)
			tc.setup(t, path)
			before := readFile(t, path)
			infoBefore, _ := os.Stat(path)

			s, err := Open(context.Background(), path)
			if err == nil {
				s.Close()
				t.Fatal("Open succeeded")
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("Open err = %v, want %v", err, tc.want)
			}
			if !bytes.Equal(readFile(t, path), before) {
				t.Error("file content changed")
			}
			infoAfter, err := os.Stat(path)
			if err != nil {
				t.Fatalf("file removed: %v", err)
			}
			if infoAfter.Mode() != infoBefore.Mode() {
				t.Errorf("mode changed from %v to %v", infoBefore.Mode(), infoAfter.Mode())
			}
		})
	}
}

func TestCorruptRowIsReportedNotReturned(t *testing.T) {
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

	db := rawDB(t, path)
	mustExec(t, db, "PRAGMA ignore_check_constraints = ON")
	if _, err := db.Exec("UPDATE operations SET state = 'bogus' WHERE id = ?", op.ID); err != nil {
		t.Fatal(err)
	}
	db.Close()

	s, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.GetOperation(ctx, op.ID); !errors.Is(err, ErrCorrupt) {
		t.Errorf("GetOperation err = %v, want ErrCorrupt", err)
	}
	if _, err := s.UpdateOperation(ctx, op.ID, 1, StateRunning, "a"); !errors.Is(err, ErrCorrupt) {
		t.Errorf("UpdateOperation err = %v, want ErrCorrupt", err)
	}
}

func TestCanceledContext(t *testing.T) {
	s, _ := openTemp(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := s.AppendProbe(ctx, probeAt("exit-01", 1)); !errors.Is(err, context.Canceled) {
		t.Errorf("AppendProbe err = %v, want context.Canceled", err)
	}
	if _, err := s.CreateOperation(ctx, "rotate_ip", ""); !errors.Is(err, context.Canceled) {
		t.Errorf("CreateOperation err = %v, want context.Canceled", err)
	}
	probes, err := s.LatestProbes(context.Background(), "exit-01", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(probes) != 0 {
		t.Errorf("canceled append stored %d probes", len(probes))
	}
}

// A sidecar without its database is someone else's data: Open must neither
// delete nor modify it, whether initialization fails early or not.
func TestOpenPreservesPreexistingSidecarWithoutDatabase(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	contexts := map[string]context.Context{"live": context.Background(), "canceled": canceled}
	for _, suffix := range sidecarSuffixes {
		for ctxName, ctx := range contexts {
			t.Run(suffix+"/"+ctxName, func(t *testing.T) {
				path := tempPath(t)
				content := []byte("synthetic pre-existing sidecar data\n")
				if err := os.WriteFile(path+suffix, content, 0o600); err != nil {
					t.Fatal(err)
				}

				s, err := Open(ctx, path)
				if err == nil {
					s.Close()
					t.Fatal("Open succeeded")
				}
				if ctxName == "live" && !errors.Is(err, ErrOrphanedSidecar) {
					t.Errorf("err = %v, want ErrOrphanedSidecar", err)
				}
				got, err := os.ReadFile(path + suffix)
				if err != nil {
					t.Fatalf("pre-existing %s removed: %v", suffix, err)
				}
				if !bytes.Equal(got, content) {
					t.Errorf("pre-existing %s contents changed", suffix)
				}
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Error("database file left behind")
				}
				t.Logf("open_failed=true preexisting_sibling_survives=true contents_preserved=%t", bytes.Equal(got, content))
			})
		}
	}
}

// For an existing database, sidecars belong to that database and SQLite owns
// their recovery; a failed Open must not lose data still held in the WAL.
func TestFailedOpenOfExistingDatabaseKeepsWALData(t *testing.T) {
	ctx := context.Background()
	path := tempPath(t)
	// Start from the newest schema below this build's latest, so the test
	// keeps exercising a real forward migration after the WAL recovery.
	s, err := open(ctx, path, migrations[:len(migrations)-1])
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	writer := rawDB(t, path)
	writer.SetMaxOpenConns(1)
	mustExec(t, writer, "PRAGMA wal_autocheckpoint = 0")
	mustExec(t, writer, "PRAGMA user_version = 99")
	if _, err := writer.Exec(`INSERT INTO operations (id, kind, state, step, revision, created_at, updated_at)
		VALUES ('0123456789abcdef0123456789abcdef', 'rotate_ip', 'running', 'poweroff', 3, 1, 2)`); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + "-wal"); err != nil {
		t.Fatalf("WAL not in use: %v", err)
	}

	if s, err := Open(ctx, path); !errors.Is(err, ErrUnsupportedSchema) {
		if err == nil {
			s.Close()
		}
		t.Fatalf("Open err = %v, want ErrUnsupportedSchema", err)
	}
	for _, name := range []string{path, path + "-wal"} {
		if _, err := os.Stat(name); err != nil {
			t.Fatalf("%s removed: %v", filepath.Base(name), err)
		}
	}
	mustExec(t, writer, fmt.Sprintf("PRAGMA user_version = %d", len(migrations)-1))
	writer.Close()

	s, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	op, err := s.GetOperation(ctx, "0123456789abcdef0123456789abcdef")
	if err != nil || op.Revision != 3 || op.Step != "poweroff" {
		t.Errorf("WAL-held operation = %+v, %v", op, err)
	}
}

func TestCanceledOpenOfNewPathLeavesNoFiles(t *testing.T) {
	path := tempPath(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if s, err := Open(ctx, path); !errors.Is(err, context.Canceled) {
		if err == nil {
			s.Close()
		}
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("files left behind: %v", entries)
	}
}

// Cleanup must not remove a file that replaced the one this call created.
func TestCleanupSkipsReplacedDatabaseFile(t *testing.T) {
	path := tempPath(t)
	own, err := createFile(path)
	if err != nil {
		t.Fatal(err)
	}
	replacement := path + ".new"
	if err := os.WriteFile(replacement, []byte("someone else's file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+"-wal", []byte("their wal"), 0o600); err != nil {
		t.Fatal(err)
	}
	own.cleanup()
	for _, name := range []string{path, path + "-wal"} {
		if _, err := os.Stat(name); err != nil {
			t.Errorf("%s removed: %v", filepath.Base(name), err)
		}
	}
}
