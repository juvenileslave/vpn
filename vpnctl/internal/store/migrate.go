package store

import (
	"context"
	"database/sql"
	"fmt"
)

// migration upgrades the schema by one version inside a transaction.
type migration func(ctx context.Context, tx *sql.Tx) error

// migrations[i] upgrades schema version i to i+1. Append only; never edit a
// released migration.
var migrations = []migration{
	execAll(
		`CREATE TABLE probes (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			target      TEXT    NOT NULL CHECK (length(target) BETWEEN 1 AND 63),
			stage       TEXT    NOT NULL CHECK (length(stage) BETWEEN 1 AND 32),
			family      TEXT    NOT NULL CHECK (family IN ('ipv4', 'ipv6')),
			outcome     TEXT    NOT NULL CHECK (outcome IN ('success', 'failure', 'timeout')),
			observed_at INTEGER NOT NULL CHECK (observed_at >= 0),
			duration_ns INTEGER NOT NULL CHECK (duration_ns >= 0),
			bytes       INTEGER NOT NULL CHECK (bytes >= 0),
			error_code  TEXT    NOT NULL CHECK (length(error_code) <= 64)
		) STRICT`,
		`CREATE INDEX probes_target_latest ON probes (target, observed_at DESC, id DESC)`,
		`CREATE TABLE operations (
			id         TEXT    PRIMARY KEY CHECK (length(id) = 32),
			kind       TEXT    NOT NULL CHECK (length(kind) BETWEEN 1 AND 32),
			state      TEXT    NOT NULL CHECK (state IN ('pending', 'running', 'succeeded', 'failed')),
			step       TEXT    NOT NULL CHECK (length(step) <= 32),
			revision   INTEGER NOT NULL CHECK (revision >= 1),
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		) STRICT`,
	),
}

func execAll(statements ...string) migration {
	return func(ctx context.Context, tx *sql.Tx) error {
		for _, stmt := range statements {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				return err
			}
		}
		return nil
	}
}

// migrate applies pending migrations, one transaction per version. The
// version is re-read under the write lock, so concurrent openers neither
// apply a migration twice nor initialize a database that changed meanwhile.
func migrate(ctx context.Context, db *sql.DB, migs []migration) error {
	for {
		done, err := migrateOne(ctx, db, migs)
		if err != nil || done {
			return err
		}
	}
}

func migrateOne(ctx context.Context, db *sql.DB, migs []migration) (done bool, err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, dbError("begin migration", err)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	var version, appID, objects int64
	if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return false, dbError("read schema version", err)
	}
	if err := tx.QueryRowContext(ctx, "PRAGMA application_id").Scan(&appID); err != nil {
		return false, dbError("read application id", err)
	}
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master").Scan(&objects); err != nil {
		return false, dbError("read schema", err)
	}
	if err := checkIdentity(version, appID, objects, len(migs)); err != nil {
		return false, err
	}
	if version == int64(len(migs)) {
		return true, tx.Commit()
	}

	if err := migs[version](ctx, tx); err != nil {
		return false, fmt.Errorf("store: migrate schema to version %d: %w", version+1, err)
	}
	// PRAGMA values cannot be bound; both are integers formatted here.
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA application_id = %d", applicationID)); err != nil {
		return false, dbError("set application id", err)
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", version+1)); err != nil {
		return false, dbError("set schema version", err)
	}
	if err := tx.Commit(); err != nil {
		return false, dbError("commit migration", err)
	}
	return false, nil
}
