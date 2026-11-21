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
	// Version 4: stateful metric alerts. Only new tables are created, so every
	// probe, operation and Telegram row from versions 1-3 is preserved.
	execAll(
		`CREATE TABLE alert_states (
			rule            TEXT    PRIMARY KEY CHECK (length(rule) BETWEEN 1 AND 64),
			state           TEXT    NOT NULL CHECK (state IN ('ok', 'firing', 'unknown')),
			severity        TEXT    NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
			comparison      TEXT    NOT NULL CHECK (comparison IN ('', '>', '>=', '<', '<=', '==', '!=')),
			value           REAL    NOT NULL,
			threshold       REAL    NOT NULL,
			labels          TEXT    NOT NULL CHECK (length(labels) <= 4096),
			fingerprint     TEXT    NOT NULL CHECK (length(fingerprint) = 64),
			since           INTEGER NOT NULL CHECK (since > 0),
			last_change     INTEGER NOT NULL CHECK (last_change > 0),
			revision        INTEGER NOT NULL CHECK (revision >= 1),
			pending_state   TEXT    NOT NULL CHECK (pending_state IN ('', 'firing', 'unknown')),
			pending_since   INTEGER NOT NULL DEFAULT 0 CHECK (pending_since >= 0),
			pending_samples INTEGER NOT NULL DEFAULT 0 CHECK (pending_samples >= 0),
			missing_since   INTEGER NOT NULL DEFAULT 0 CHECK (missing_since >= 0)
		) STRICT`,
		`CREATE TABLE alert_outbox (
			id             INTEGER PRIMARY KEY AUTOINCREMENT,
			rule           TEXT    NOT NULL CHECK (length(rule) BETWEEN 1 AND 64),
			event          TEXT    NOT NULL CHECK (event IN ('firing', 'recovery', 'unknown', 'removed')),
			fingerprint    TEXT    NOT NULL CHECK (length(fingerprint) = 64),
			dedupe_key     TEXT    NOT NULL UNIQUE CHECK (length(dedupe_key) BETWEEN 1 AND 128),
			severity       TEXT    NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
			message        TEXT    NOT NULL CHECK (length(message) BETWEEN 1 AND 4096),
			created_at     INTEGER NOT NULL CHECK (created_at > 0),
			attempts       INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
			next_attempt_at INTEGER NOT NULL DEFAULT 0 CHECK (next_attempt_at >= 0),
			claimed_until  INTEGER NOT NULL DEFAULT 0 CHECK (claimed_until >= 0),
			delivered_at   INTEGER NOT NULL DEFAULT 0 CHECK (delivered_at >= 0),
			abandoned_at   INTEGER NOT NULL DEFAULT 0 CHECK (abandoned_at >= 0),
			expires_at     INTEGER NOT NULL CHECK (expires_at > 0)
		) STRICT`,
		`CREATE INDEX alert_outbox_due ON alert_outbox (delivered_at, abandoned_at, next_attempt_at, id)`,
		`CREATE TABLE alert_mutes (
			rule  TEXT    PRIMARY KEY CHECK (length(rule) BETWEEN 1 AND 64),
			until INTEGER NOT NULL CHECK (until > 0)
		) STRICT`,
		`CREATE TABLE alert_runs (
			id         INTEGER PRIMARY KEY CHECK (id = 1),
			owner      TEXT    NOT NULL CHECK (length(owner) BETWEEN 1 AND 64),
			expires_at INTEGER NOT NULL CHECK (expires_at > 0)
		) STRICT`,
	),
	// Version 5: upstream candidate pipeline versions and slot refresh state.
	// Only new tables are created, so every row from versions 1-4 is preserved.
	execAll(
		`CREATE TABLE upstream_versions (
			id                   TEXT    PRIMARY KEY CHECK (length(id) = 32),
			slot                 INTEGER NOT NULL CHECK (slot BETWEEN 1 AND 63),
			seq                  INTEGER NOT NULL CHECK (seq >= 1),
			origin               TEXT    NOT NULL CHECK (origin IN ('upstream', 'blackhole')),
			state                TEXT    NOT NULL CHECK (state IN ('candidate', 'active', 'superseded', 'failed')),
			payload_ref          TEXT    NOT NULL CHECK (length(payload_ref) BETWEEN 1 AND 128),
			payload_sha256       TEXT    NOT NULL CHECK (length(payload_sha256) = 64),
			outbound_fingerprint TEXT    NOT NULL CHECK (length(outbound_fingerprint) = 64),
			failure_code         TEXT    NOT NULL DEFAULT '' CHECK (length(failure_code) <= 64),
			created_at           INTEGER NOT NULL CHECK (created_at > 0),
			activated_at         INTEGER NOT NULL DEFAULT 0 CHECK (activated_at >= 0),
			retired_at           INTEGER NOT NULL DEFAULT 0 CHECK (retired_at >= 0),
			UNIQUE (slot, seq)
		) STRICT`,
		`CREATE UNIQUE INDEX upstream_versions_active ON upstream_versions (slot) WHERE state = 'active'`,
		`CREATE INDEX upstream_versions_latest ON upstream_versions (slot, seq DESC)`,
		`CREATE TABLE upstream_slots (
			slot              INTEGER PRIMARY KEY CHECK (slot BETWEEN 1 AND 63),
			mode              TEXT    NOT NULL CHECK (mode IN ('upstream', 'blackhole')),
			active_version_id TEXT    NOT NULL DEFAULT '' CHECK (length(active_version_id) IN (0, 32)),
			failure_count     INTEGER NOT NULL DEFAULT 0 CHECK (failure_count >= 0),
			next_run_at       INTEGER NOT NULL DEFAULT 0 CHECK (next_run_at >= 0),
			last_error_code   TEXT    NOT NULL DEFAULT '' CHECK (length(last_error_code) <= 64),
			updated_at        INTEGER NOT NULL CHECK (updated_at > 0)
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
