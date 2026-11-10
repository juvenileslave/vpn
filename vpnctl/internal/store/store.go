// Package store persists vpnctl probe observations and resumable operation
// state in a local SQLite database.
//
// The store keeps only bounded, validated metadata: it never stores
// credentials, configuration contents, raw HTTP bodies or free-form error
// text. See docs/STATE_STORE.md for the schema and operational notes.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// BusyTimeout bounds how long a statement waits for a lock held by another
// connection before failing with SQLITE_BUSY.
const BusyTimeout = 5 * time.Second

// applicationID marks databases created by this package ("vpnc").
const applicationID = 0x76706e63

var (
	// ErrNotFound is returned when no record has the requested ID.
	ErrNotFound = errors.New("store: not found")
	// ErrConflict is returned when the expected revision is stale.
	ErrConflict = errors.New("store: revision conflict")
	// ErrTerminal is returned when updating a succeeded or failed operation.
	ErrTerminal = errors.New("store: operation is in a terminal state")
	// ErrInvalidTransition is returned for a state change the state machine forbids.
	ErrInvalidTransition = errors.New("store: invalid state transition")
	// ErrInvalidArgument is returned for invalid caller input.
	ErrInvalidArgument = errors.New("store: invalid argument")
	// ErrNotDatabase is returned when the file is not a readable SQLite database.
	ErrNotDatabase = errors.New("store: file is not a valid SQLite database")
	// ErrForeignDatabase is returned for a SQLite database not created by this package.
	ErrForeignDatabase = errors.New("store: database was not created by vpnctl")
	// ErrUnsupportedSchema is returned when the schema is newer than this build supports.
	ErrUnsupportedSchema = errors.New("store: database schema version is not supported")
	// ErrCorrupt is returned when a stored row violates the record contract.
	ErrCorrupt = errors.New("store: stored record is invalid")
)

// Store is an open state database. Its methods are safe for concurrent use;
// all statements share a single connection.
type Store struct {
	db *sql.DB
}

// Open opens the database at path, creating it with mode 0600 if it does not
// exist, and applies pending schema migrations. The parent directory must
// exist. If initialization fails, a file created by this call is removed and
// an existing file is left untouched.
func Open(ctx context.Context, path string) (*Store, error) {
	return open(ctx, path, migrations)
}

func open(ctx context.Context, path string, migs []migration) (*Store, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil context", ErrInvalidArgument)
	}
	abs, err := cleanPath(path)
	if err != nil {
		return nil, err
	}
	created, err := createFile(abs)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dsn(abs))
	if err == nil {
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
		db.SetConnMaxLifetime(0)
		db.SetConnMaxIdleTime(0)
		s := &Store{db: db}
		if err = s.init(ctx, migs); err == nil {
			return s, nil
		}
		db.Close()
	}
	if created {
		removeCreated(abs)
	}
	return nil, err
}

// Close closes the database. Methods called after Close return an error.
func (s *Store) Close() error {
	return s.db.Close()
}

func cleanPath(path string) (string, error) {
	if path == "" || strings.ContainsRune(path, 0) {
		return "", fmt.Errorf("%w: database path must be non-empty and contain no NUL bytes", ErrInvalidArgument)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("store: resolve database path: %w", err)
	}
	return abs, nil
}

// createFile creates abs exclusively so that SQLite never creates the file
// with default permissions. It reports whether this call created the file.
func createFile(abs string) (bool, error) {
	f, err := os.OpenFile(abs, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		if err := f.Close(); err != nil {
			os.Remove(abs)
			return false, fmt.Errorf("store: create database file: %w", err)
		}
		return true, nil
	}
	if !errors.Is(err, fs.ErrExist) {
		return false, fmt.Errorf("store: create database file: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return false, fmt.Errorf("store: stat database file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("%w: database path is not a regular file", ErrInvalidArgument)
	}
	return false, nil
}

func removeCreated(abs string) {
	for _, suffix := range []string{"", "-journal", "-wal", "-shm"} {
		os.Remove(abs + suffix)
	}
}

// dsn builds a SQLite URI. The path is percent-escaped, so characters such as
// '?' and '#' stay part of the file name and cannot add DSN parameters.
// mode=rw stops SQLite from creating a file that createFile did not create.
func dsn(abs string) string {
	q := url.Values{}
	q.Set("mode", "rw")
	q.Set("_busy_timeout", strconv.FormatInt(BusyTimeout.Milliseconds(), 10))
	q.Set("_foreign_keys", "1")
	q.Set("_synchronous", "FULL")
	q.Set("_txlock", "immediate")
	return "file:" + (&url.URL{Path: filepath.ToSlash(abs)}).EscapedPath() + "?" + q.Encode()
}

func (s *Store) init(ctx context.Context, migs []migration) error {
	var version, appID, objects int64
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return dbError("read schema version", err)
	}
	if err := s.db.QueryRowContext(ctx, "PRAGMA application_id").Scan(&appID); err != nil {
		return dbError("read application id", err)
	}
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master").Scan(&objects); err != nil {
		return dbError("read schema", err)
	}
	if err := checkIdentity(version, appID, objects, len(migs)); err != nil {
		return err
	}
	if version < int64(len(migs)) {
		if err := migrate(ctx, s.db, migs); err != nil {
			return err
		}
	}
	// journal_mode is persistent, so it is changed only after the file is
	// known to belong to this package.
	var mode string
	if err := s.db.QueryRowContext(ctx, "PRAGMA journal_mode = WAL").Scan(&mode); err != nil {
		return dbError("set journal mode", err)
	}
	if !strings.EqualFold(mode, "wal") {
		return fmt.Errorf("store: journal mode is %q, want wal", mode)
	}
	return nil
}

func checkIdentity(version, appID, objects int64, latest int) error {
	switch {
	case appID == applicationID:
	case appID == 0 && version == 0 && objects == 0:
		// Empty database: initialized by the first migration.
	default:
		return ErrForeignDatabase
	}
	if version < 0 || version > int64(latest) {
		return fmt.Errorf("%w: version %d, latest supported %d", ErrUnsupportedSchema, version, latest)
	}
	return nil
}

// dbError wraps a driver error, mapping unreadable files to ErrNotDatabase.
func dbError(op string, err error) error {
	var se *sqlite.Error
	if errors.As(err, &se) {
		switch se.Code() & 0xff {
		case sqlite3.SQLITE_NOTADB, sqlite3.SQLITE_CORRUPT:
			return fmt.Errorf("%w: %s: %v", ErrNotDatabase, op, err)
		}
	}
	return fmt.Errorf("store: %s: %w", op, err)
}
