package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func testAlertState(rule, state string, revision int64, now time.Time) AlertState {
	return AlertState{
		Rule:        rule,
		State:       state,
		Severity:    "warning",
		Comparison:  ">=",
		Value:       95.5,
		Threshold:   90,
		Labels:      map[string]string{"instance": "exit-01", "env": "prod"},
		Fingerprint: strings.Repeat("a", 64),
		Since:       now,
		LastChange:  now,
		Revision:    revision,
	}
}

func testOutbox(rule, key string, event AlertEvent, now time.Time) *AlertOutbox {
	return &AlertOutbox{
		Rule:          rule,
		Event:         event,
		Fingerprint:   strings.Repeat("a", 64),
		DedupeKey:     key,
		Severity:      "warning",
		Message:       "firing rule=" + rule,
		CreatedAt:     now,
		NextAttemptAt: now,
		ExpiresAt:     now.Add(time.Hour),
	}
}

func TestAlertStateTransitionAndRestart(t *testing.T) {
	ctx := context.Background()
	s, path := openTemp(t)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	st := testAlertState("node-cpu-busy", AlertOK, 0, now)
	got, inserted, err := s.CommitAlertTransition(ctx, 0, st, testOutbox(st.Rule, "alerts.node-cpu-busy.firing.aabbccdd.0", EventFiring, now))
	if err != nil {
		t.Fatalf("insert state: %v", err)
	}
	if !inserted || got.Revision != 1 {
		t.Fatalf("insert = %+v, inserted %v", got, inserted)
	}
	if _, _, err := s.CommitAlertTransition(ctx, 0, st, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("second insert err = %v, want ErrConflict", err)
	}
	if _, _, err := s.CommitAlertTransition(ctx, 7, st, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale revision err = %v, want ErrConflict", err)
	}

	next := got
	next.State = AlertOK
	next.LastChange = now.Add(time.Minute)
	got, inserted, err = s.CommitAlertTransition(ctx, got.Revision,
		next, testOutbox(next.Rule, "alerts.node-cpu-busy.recovery.aabbccdd.1", EventRecovery, now.Add(time.Minute)))
	if err != nil {
		t.Fatalf("update state: %v", err)
	}
	if !inserted || got.Revision != 2 || got.State != AlertOK {
		t.Fatalf("update = %+v, inserted %v", got, inserted)
	}

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s.Close()
	reloaded, err := s.GetAlertState(ctx, "node-cpu-busy")
	if err != nil {
		t.Fatalf("reload state: %v", err)
	}
	if reloaded.Revision != 2 || reloaded.State != AlertOK || reloaded.Labels["instance"] != "exit-01" {
		t.Fatalf("reloaded = %+v", reloaded)
	}
	states, err := s.ListAlertStates(ctx)
	if err != nil || len(states) != 1 {
		t.Fatalf("states = %+v, %v", states, err)
	}
}

func TestAlertTransitionDedupeKeyIsUnique(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	defer s.Close()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	st := testAlertState("disk-full", AlertOK, 0, now)
	out := testOutbox(st.Rule, "alerts.disk-full.firing.01234567.0", EventFiring, now)
	if _, inserted, err := s.CommitAlertTransition(ctx, 0, st, out); err != nil || !inserted {
		t.Fatalf("first insert = %v, %v", inserted, err)
	}
	next := st
	next.State = AlertOK
	next.Revision = 1
	if _, inserted, err := s.CommitAlertTransition(ctx, 1, next, out); err != nil || inserted {
		t.Fatalf("duplicate outbox = %v, %v", inserted, err)
	}
	pending, expired, err := s.AlertOutboxStatus(ctx, now)
	if err != nil || pending != 1 || expired != 0 {
		t.Fatalf("status = %d/%d, %v", pending, expired, err)
	}
}

func TestAlertStatePruningOnlyForMissingRules(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	defer s.Close()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	present := testAlertState("present", AlertOK, 0, now)
	missing := testAlertState("missing", AlertFiring, 0, now)
	missing.MissingSince = now.Add(-2 * time.Hour)
	for _, st := range []AlertState{present, missing} {
		if _, _, err := s.CommitAlertTransition(ctx, 0, st, nil); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.DeleteAlertStatesMissingBefore(ctx, now.Add(-time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("prune = %d, %v", n, err)
	}
	if _, err := s.GetAlertState(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing state err = %v", err)
	}
	if _, err := s.GetAlertState(ctx, "present"); err != nil {
		t.Fatalf("present state: %v", err)
	}
}

func TestAlertStatePruningKeepsRulesWithOutboxRows(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	defer s.Close()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	st := testAlertState("missing", AlertFiring, 0, now)
	st.MissingSince = now.Add(-2 * time.Hour)
	out := testOutbox(st.Rule, "alerts.missing.firing.aaaaaaaa.0", EventFiring, now)
	if _, _, err := s.CommitAlertTransition(ctx, 0, st, out); err != nil {
		t.Fatal(err)
	}
	open, err := s.ListOpenAlertOutbox(ctx, 10)
	if err != nil || len(open) != 1 {
		t.Fatalf("open outbox = %+v, %v", open, err)
	}
	if n, err := s.DeleteAlertStatesMissingBefore(ctx, now.Add(-time.Hour)); err != nil || n != 0 {
		t.Fatalf("prune with live outbox = %d, %v; want 0", n, err)
	}
	if retained, err := s.GetAlertState(ctx, st.Rule); err != nil || retained.Revision != 1 {
		t.Fatalf("retained state = %+v, %v; want revision 1", retained, err)
	}
	if err := s.RecordAlertFailure(ctx, open[0].ID, now, now, true); err != nil {
		t.Fatal(err)
	}
	if n, err := s.PruneAlertOutbox(ctx, now.Add(time.Hour), now.Add(time.Hour)); err != nil || n != 1 {
		t.Fatalf("prune outbox = %d, %v; want 1", n, err)
	}
	if n, err := s.DeleteAlertStatesMissingBefore(ctx, now.Add(-time.Hour)); err != nil || n != 1 {
		t.Fatalf("prune after outbox removal = %d, %v; want 1", n, err)
	}
}

func TestAlertOutboxExpireRespectsClaimsAndExhaustedAttempts(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	defer s.Close()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	claimedState := testAlertState("claimed", AlertFiring, 0, now)
	claimedOut := testOutbox("claimed", "alerts.claimed.firing.aaaaaaaa.0", EventFiring, now)
	claimedOut.ExpiresAt = now.Add(time.Minute)
	if _, _, err := s.CommitAlertTransition(ctx, 0, claimedState, claimedOut); err != nil {
		t.Fatal(err)
	}
	claimed, ok, err := s.ClaimAlertOutbox(ctx, now, 10*time.Minute, 3)
	if err != nil || !ok {
		t.Fatalf("claim = %+v, %v, %v", claimed, ok, err)
	}
	if n, err := s.ExpireAlertOutbox(ctx, now.Add(2*time.Minute), 3); err != nil || n != 0 {
		t.Fatalf("expire active claim = %d, %v; want 0", n, err)
	}
	if err := s.MarkAlertDelivered(ctx, claimed.ID, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if pending, expired, err := s.AlertOutboxStatus(ctx, now.Add(2*time.Minute)); err != nil || pending != 0 || expired != 0 {
		t.Fatalf("status after late delivery = %d/%d, %v", pending, expired, err)
	}

	exhaustedState := testAlertState("exhausted", AlertFiring, 0, now)
	exhaustedOut := testOutbox("exhausted", "alerts.exhausted.firing.bbbbbbbb.0", EventFiring, now)
	exhaustedOut.ExpiresAt = now.Add(time.Hour)
	if _, _, err := s.CommitAlertTransition(ctx, 0, exhaustedState, exhaustedOut); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.ClaimAlertOutbox(ctx, now, time.Minute, 1); err != nil || !ok {
		t.Fatalf("exhausted claim = %v, %v", ok, err)
	}
	if n, err := s.ExpireAlertOutbox(ctx, now.Add(2*time.Minute), 1); err != nil || n != 1 {
		t.Fatalf("expire exhausted row = %d, %v; want 1", n, err)
	}
	if pending, expired, err := s.AlertOutboxStatus(ctx, now.Add(2*time.Minute)); err != nil || pending != 0 || expired != 1 {
		t.Fatalf("status after exhaustion = %d/%d, %v", pending, expired, err)
	}
}

func TestAlertMutes(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	defer s.Close()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	if err := s.SetAlertMute(ctx, "node-cpu-busy", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAlertMute(ctx, "node-cpu-busy", now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAlertMute(ctx, "bad name", now); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("invalid rule err = %v", err)
	}
	mutes, err := s.ListAlertMutes(ctx)
	if err != nil || len(mutes) != 1 {
		t.Fatalf("mutes = %+v, %v", mutes, err)
	}
	if !mutes[0].Until.Equal(now.Add(2 * time.Hour)) {
		t.Fatalf("until = %v", mutes[0].Until)
	}
}

func TestAlertOutboxClaimDeliverAndRetry(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	defer s.Close()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	for _, key := range []string{
		"alerts.a.firing.aaaaaaaa.0",
		"alerts.b.firing.bbbbbbbb.0",
	} {
		rule := strings.Split(key, ".")[1]
		st := testAlertState(rule, AlertOK, 0, now)
		st.Fingerprint = strings.Repeat(key[:1], 64)
		if _, _, err := s.CommitAlertTransition(ctx, 0, st, testOutbox(rule, key, EventFiring, now)); err != nil {
			t.Fatal(err)
		}
	}

	first, ok, err := s.ClaimAlertOutbox(ctx, now, time.Minute, 3)
	if err != nil || !ok {
		t.Fatalf("claim = %v, %v", ok, err)
	}
	if first.Attempts != 1 || first.Rule != "a" {
		t.Fatalf("first = %+v", first)
	}
	again, ok, err := s.ClaimAlertOutbox(ctx, now, time.Minute, 3)
	if err != nil || !ok || again.Rule != "b" {
		t.Fatalf("second claim = %+v, %v, %v", again, ok, err)
	}
	if _, ok, _ := s.ClaimAlertOutbox(ctx, now, time.Minute, 3); ok {
		t.Fatal("claimed rows must not be claimed twice")
	}

	if err := s.MarkAlertDelivered(ctx, first.ID, now); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkAlertDelivered(ctx, first.ID, now); err != nil {
		t.Fatalf("repeat delivery: %v", err)
	}

	// A failed attempt is not retried before its backoff time.
	next := now.Add(time.Minute)
	if err := s.RecordAlertFailure(ctx, again.ID, now, next, false); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.ClaimAlertOutbox(ctx, now, time.Minute, 3); ok {
		t.Fatal("failed row retried before backoff")
	}
	retry, ok, err := s.ClaimAlertOutbox(ctx, next, time.Minute, 3)
	if err != nil || !ok || retry.ID != again.ID || retry.Attempts != 2 {
		t.Fatalf("retry = %+v, %v, %v", retry, ok, err)
	}
	if err := s.RecordAlertFailure(ctx, retry.ID, next, next.Add(time.Minute), true); err != nil {
		t.Fatal(err)
	}
	pending, expired, err := s.AlertOutboxStatus(ctx, next)
	if err != nil || pending != 0 || expired != 1 {
		t.Fatalf("status = %d/%d, %v", pending, expired, err)
	}
	if _, ok, _ := s.ClaimAlertOutbox(ctx, next.Add(time.Hour), time.Minute, 3); ok {
		t.Fatal("abandoned row retried")
	}
	rows, err := s.ListOpenAlertOutbox(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].ID != retry.ID {
		t.Fatalf("pending rows = %+v", rows)
	}
	if _, err := s.PruneAlertOutbox(ctx, next.Add(time.Hour), next.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
}

func TestAlertOutboxExpiry(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	defer s.Close()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	st := testAlertState("expiring", AlertOK, 0, now)
	out := testOutbox(st.Rule, "alerts.expiring.firing.aaaaaaaa.0", EventFiring, now)
	out.ExpiresAt = now.Add(time.Minute)
	if _, _, err := s.CommitAlertTransition(ctx, 0, st, out); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.ClaimAlertOutbox(ctx, now.Add(2*time.Minute), time.Minute, 3); err != nil || ok {
		t.Fatalf("expired claim = %v, %v", ok, err)
	}
	_, expired, err := s.AlertOutboxStatus(ctx, now.Add(2*time.Minute))
	if err != nil || expired != 1 {
		t.Fatalf("expired = %d, %v", expired, err)
	}
}

func TestAlertRunLock(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	defer s.Close()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	ok, err := s.ClaimAlertRun(ctx, "owner-a", now, time.Minute)
	if err != nil || !ok {
		t.Fatalf("claim a = %v, %v", ok, err)
	}
	ok, err = s.ClaimAlertRun(ctx, "owner-b", now, time.Minute)
	if err != nil || ok {
		t.Fatalf("claim b = %v, %v", ok, err)
	}
	ok, err = s.ClaimAlertRun(ctx, "owner-a", now.Add(30*time.Second), time.Minute)
	if err != nil || !ok {
		t.Fatalf("renew a = %v, %v", ok, err)
	}
	ok, err = s.ClaimAlertRun(ctx, "owner-b", now.Add(2*time.Minute), time.Minute)
	if err != nil || !ok {
		t.Fatalf("expired claim b = %v, %v", ok, err)
	}
	if err := s.ReleaseAlertRun(ctx, "owner-a"); err != nil {
		t.Fatal(err)
	}
	if err := s.ReleaseAlertRun(ctx, "owner-b"); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.ClaimAlertRun(ctx, "owner-c", now.Add(2*time.Minute), time.Minute); err != nil || !ok {
		t.Fatalf("claim after release = %v, %v", ok, err)
	}
}

func TestMigration4PreservesVersion3Rows(t *testing.T) {
	ctx := context.Background()
	path := tempPath(t)
	old, err := open(ctx, path, migrations[:3])
	if err != nil {
		t.Fatalf("open v3: %v", err)
	}
	probe, err := old.AppendProbe(ctx, ProbeRecord{
		Target: "exit-01", Stage: "tcp", Family: FamilyIPv4,
		Outcome: OutcomeSuccess, ObservedAt: time.Unix(1700000000, 0).UTC(),
	})
	if err != nil {
		t.Fatalf("append probe: %v", err)
	}
	op, err := old.CreateOperation(ctx, "rotate_ip", "")
	if err != nil {
		t.Fatalf("create operation: %v", err)
	}
	if claimed, err := old.ClaimBotUpdate(ctx, 42); err != nil || !claimed {
		t.Fatalf("claim update = %v, %v", claimed, err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}

	upgraded, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	defer upgraded.Close()
	if got := pragmaInt(t, upgraded.db, "user_version"); got != int64(len(migrations)) {
		t.Fatalf("user_version = %d", got)
	}
	for _, table := range []string{"alert_states", "alert_outbox", "alert_mutes", "alert_runs"} {
		if !tableExists(t, upgraded.db, table) {
			t.Errorf("table %q missing", table)
		}
	}
	probes, err := upgraded.LatestProbes(ctx, "exit-01", 1)
	if err != nil || len(probes) != 1 || probes[0].ID != probe.ID {
		t.Fatalf("probes = %+v, %v", probes, err)
	}
	if _, err := upgraded.GetOperation(ctx, op.ID); err != nil {
		t.Fatalf("operation: %v", err)
	}
	if offset, err := upgraded.BotOffset(ctx); err != nil || offset != 43 {
		t.Fatalf("offset = %d, %v", offset, err)
	}
}
