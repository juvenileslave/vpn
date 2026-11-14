package store

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func scopedRecord() ProbeRecord {
	record := probeAt("exit-test", 1)
	record.RunID = strings.Repeat("a", 32)
	record.Vantage, record.Network, record.VantageKind, record.Scope = "inside", "synthetic-a", "in_country", "node_path"
	record.EndpointIdentity, record.ConfigIdentity, record.SNIIdentity = strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	record.ThroughputFloor = 1 << 20
	return record
}

// A pre-upgrade fixture must use the released columns, not the new API.
func appendLegacyProbe(t *testing.T, database *Store, record ProbeRecord) ProbeRecord {
	t.Helper()
	result, err := database.db.ExecContext(context.Background(),
		`INSERT INTO probes (target, stage, family, outcome, observed_at, duration_ns, bytes, error_code)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		record.Target, record.Stage, string(record.Family), string(record.Outcome),
		record.ObservedAt.UnixNano(), int64(record.Duration), record.Bytes, record.ErrorCode)
	if err != nil {
		t.Fatal(err)
	}
	record.ID, err = result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	record.ObservedAt = record.ObservedAt.UTC()
	return record
}

func TestLadderMigrationPreservesLegacyProbeAndOperation(t *testing.T) {
	ctx, path := context.Background(), tempPath(t)
	previous, err := open(ctx, path, migrations[:2])
	if err != nil {
		t.Fatal(err)
	}
	legacy := appendLegacyProbe(t, previous, probeAt("legacy-exit", 1))
	operation, err := previous.CreateOperation(ctx, "probe", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := previous.Close(); err != nil {
		t.Fatal(err)
	}
	current, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	probes, err := current.LatestProbes(ctx, "legacy-exit", 10)
	if err != nil || len(probes) != 1 || probes[0] != legacy {
		t.Fatalf("legacy row changed: %+v, %v", probes, err)
	}
	if got, err := current.GetOperation(ctx, operation.ID); err != nil || got != operation {
		t.Fatalf("operation changed: %+v, %v", got, err)
	}
	record, err := current.AppendProbe(ctx, scopedRecord())
	if err != nil {
		t.Fatal(err)
	}
	got, err := current.LatestProbes(ctx, "exit-test", 10)
	if err != nil || len(got) != 1 || got[0] != record {
		t.Fatalf("scoped fields changed: %+v, %v", got, err)
	}
}

func TestStoreRejectsInvalidOrUnsafeLadderContext(t *testing.T) {
	for _, kind := range []string{"missing-run", "raw-address", "bad-hash", "http-auth", "unbounded-body", "untrusted-error"} {
		t.Run(kind, func(t *testing.T) {
			record := scopedRecord()
			switch kind {
			case "missing-run":
				record.RunID = ""
			case "raw-address":
				record.Network = "https://private-value-canary/"
			case "bad-hash":
				record.EndpointIdentity = strings.Repeat("z", 64)
			case "http-auth":
				record.VantageKind = "external_http"
			case "unbounded-body":
				record.ExpectedBytes = 21 << 20
			case "untrusted-error":
				record.Outcome, record.ErrorCode = OutcomeFailure, "https://private-value-canary/"
			}
			database, _ := openTemp(t)
			if _, err := database.AppendProbe(context.Background(), record); !errors.Is(err, ErrInvalidArgument) || strings.Contains(err.Error(), "private-value-canary") {
				t.Fatalf("unsafe context accepted or disclosed: %v", err)
			}
		})
	}
}

func TestCorruptContextIsNotReturnedToClassifier(t *testing.T) {
	database, _ := openTemp(t)
	if _, err := database.AppendProbe(context.Background(), scopedRecord()); err != nil {
		t.Fatal(err)
	}
	mustExec(t, database.db, "UPDATE probes SET config_identity = 'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz'")
	if _, err := database.LatestProbes(context.Background(), "exit-test", 10); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("corrupt identity escaped validation: %v", err)
	}
}
