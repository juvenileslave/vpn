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
	// Version 2: Telegram bot offset and processed update IDs.
	execAll(
		`CREATE TABLE telegram_offsets (
			id            INTEGER PRIMARY KEY CHECK (id = 1),
			update_offset INTEGER NOT NULL CHECK (update_offset >= 0)
		) STRICT`,
		`CREATE TABLE telegram_updates (
			update_id INTEGER PRIMARY KEY CHECK (update_id > 0)
		) STRICT`,
	),
	// Version 3: explicit ladder/vantage identities and measured body time.
	// Defaults preserve every legacy probe and operation without reinterpretation.
	execAll(
		`ALTER TABLE probes ADD COLUMN run_id TEXT NOT NULL DEFAULT '' CHECK (length(run_id) IN (0, 32))`,
		`ALTER TABLE probes ADD COLUMN vantage TEXT NOT NULL DEFAULT '' CHECK (length(vantage) <= 63)`,
		`ALTER TABLE probes ADD COLUMN network TEXT NOT NULL DEFAULT '' CHECK (length(network) <= 63)`,
		`ALTER TABLE probes ADD COLUMN vantage_kind TEXT NOT NULL DEFAULT '' CHECK (vantage_kind IN ('', 'in_country', 'outside', 'local_dc', 'external_http'))`,
		`ALTER TABLE probes ADD COLUMN scope TEXT NOT NULL DEFAULT '' CHECK (scope IN ('', 'node_path', 'same_address_control', 'external_http'))`,
		`ALTER TABLE probes ADD COLUMN endpoint_identity TEXT NOT NULL DEFAULT '' CHECK (length(endpoint_identity) IN (0, 64))`,
		`ALTER TABLE probes ADD COLUMN config_identity TEXT NOT NULL DEFAULT '' CHECK (length(config_identity) IN (0, 64))`,
		`ALTER TABLE probes ADD COLUMN sni_identity TEXT NOT NULL DEFAULT '' CHECK (length(sni_identity) IN (0, 64))`,
		`ALTER TABLE probes ADD COLUMN expected_bytes INTEGER NOT NULL DEFAULT 0 CHECK (expected_bytes BETWEEN 0 AND 20971520)`,
		`ALTER TABLE probes ADD COLUMN body_duration_ns INTEGER NOT NULL DEFAULT 0 CHECK (body_duration_ns >= 0)`,
		`ALTER TABLE probes ADD COLUMN throughput_floor INTEGER NOT NULL DEFAULT 0 CHECK (throughput_floor BETWEEN 0 AND 1000000000000)`,
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
