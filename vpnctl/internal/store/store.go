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
	// ErrOrphanedSidecar is returned when a new database would be created
	// next to an existing -wal, -shm or -journal file.
	ErrOrphanedSidecar = errors.New("store: database sidecar file exists without the database")
)

// Store is an open state database. Its methods are safe for concurrent use;
// all statements share a single connection.
type Store struct {
	db *sql.DB
}

// Open opens the database at path, creating it with mode 0600 if it does not
// exist, and applies pending schema migrations. The parent directory must
// exist.
//
// Open never removes or rewrites files it did not create. A new database is
// refused with ErrOrphanedSidecar if a -wal, -shm or -journal file already
// exists for the path. If initialization fails, only the database file
// created by this call and sidecar files that did not exist before it are
// removed.
func Open(ctx context.Context, path string) (*Store, error) {
	return open(ctx, path, migrations)
}

func open(ctx context.Context, path string, migs []migration) (*Store, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil context", ErrInvalidArgument)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	abs, err := cleanPath(path)
	if err != nil {
		return nil, err
	}
	own, err := createFile(abs)
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
	own.cleanup()
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

var sidecarSuffixes = []string{"-journal", "-wal", "-shm"}

// ownership records the files a single Open call created and may remove if
// initialization fails. The zero value owns nothing.
type ownership struct {
	abs  string
	file fs.FileInfo // identity of the database file created by this call
}

// cleanup removes the database file only while it is still the inode this
// call created, and then the sidecars, which did not exist when the file was
// created (createFile checks) and so were created by SQLite for this file.
func (o ownership) cleanup() {
	if o.file == nil {
		return
	}
	cur, err := os.Lstat(o.abs)
	if err != nil || !os.SameFile(cur, o.file) {
		return
	}
	if os.Remove(o.abs) != nil {
		return
	}
	for _, suffix := range sidecarSuffixes {
		os.Remove(o.abs + suffix)
	}
}

// existingSidecar returns the first sidecar of abs that exists, or "".
func existingSidecar(abs string) (string, error) {
	for _, suffix := range sidecarSuffixes {
		_, err := os.Lstat(abs + suffix)
		if err == nil {
			return suffix, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("store: stat database sidecar: %w", err)
		}
	}
	return "", nil
}

// createFile creates abs exclusively so that SQLite never creates the file
// with default permissions. For an existing regular file it returns zero
// ownership: such a file and its sidecars are never removed.
func createFile(abs string) (ownership, error) {
	// A sidecar without its database belongs to someone else; SQLite could
	// replay or delete it when opening a fresh file at this path.
	if suffix, err := existingSidecar(abs); err != nil {
		return ownership{}, err
	} else if suffix != "" {
		if _, err := os.Lstat(abs); errors.Is(err, fs.ErrNotExist) {
			return ownership{}, fmt.Errorf("%w: %s exists without the database file", ErrOrphanedSidecar, suffix)
		}
	}

	f, err := os.OpenFile(abs, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		info, statErr := f.Stat()
		closeErr := f.Close()
		if statErr != nil || closeErr != nil {
			if statErr == nil {
				ownership{abs: abs, file: info}.cleanup()
			}
			return ownership{}, fmt.Errorf("store: create database file: %w", errors.Join(statErr, closeErr))
		}
		// Recheck: a sidecar may have appeared between the first check and
		// the exclusive create. The database file is ours and still empty.
		own := ownership{abs: abs, file: info}
		if suffix, err := existingSidecar(abs); err != nil || suffix != "" {
			if cur, lerr := os.Lstat(abs); lerr == nil && os.SameFile(cur, info) {
				os.Remove(abs)
			}
			if err != nil {
				return ownership{}, err
			}
			return ownership{}, fmt.Errorf("%w: %s exists without the database file", ErrOrphanedSidecar, suffix)
		}
		return own, nil
	}
	if !errors.Is(err, fs.ErrExist) {
		return ownership{}, fmt.Errorf("store: create database file: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return ownership{}, fmt.Errorf("store: stat database file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return ownership{}, fmt.Errorf("%w: database path is not a regular file", ErrInvalidArgument)
	}
	return ownership{}, nil
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
