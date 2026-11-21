package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func seedRollbackSlotRow(t *testing.T, ctx context.Context, s *Store, slot int, mode, activeID string, failureCount int, nextRunAt int64, lastErrorCode string, updatedAt int64) {
	t.Helper()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO upstream_slots (slot, mode, active_version_id, failure_count, next_run_at, last_error_code, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		slot, mode, activeID, failureCount, nextRunAt, lastErrorCode, updatedAt,
	)
	if err != nil {
		t.Fatalf("seed upstream_slots(%d): %v", slot, err)
	}
}

func readRollbackSlotRow(t *testing.T, ctx context.Context, s *Store, slot int) (mode, activeID string, failureCount int, nextRunAt int64, lastErrorCode string, updatedAt int64) {
	t.Helper()
	err := s.db.QueryRowContext(ctx,
		`SELECT mode, active_version_id, failure_count, next_run_at, last_error_code, updated_at
		 FROM upstream_slots
		 WHERE slot = ?`,
		slot,
	).Scan(&mode, &activeID, &failureCount, &nextRunAt, &lastErrorCode, &updatedAt)
	if err != nil {
		t.Fatalf("read upstream_slots(%d): %v", slot, err)
	}
	return mode, activeID, failureCount, nextRunAt, lastErrorCode, updatedAt
}

func TestFailUpstreamVersion(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, tempPath(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	t1 := time.Date(2026, 5, 6, 10, 0, 0, 100, time.UTC)
	t2 := t1.Add(time.Minute)
	t3 := t2.Add(time.Minute)
	t4 := t3.Add(time.Minute)

	sha := strings.Repeat("a", 64)
	fp := strings.Repeat("b", 64)

	v1 := UpstreamVersion{
		ID:                  strings.Repeat("1", 32),
		Slot:                1,
		Seq:                 1,
		Origin:              "upstream",
		State:               "superseded",
		PayloadRef:          "slot1/v1.enc",
		PayloadSHA256:       sha,
		OutboundFingerprint: fp,
		CreatedAt:           t1,
		ActivatedAt:         t1.Add(time.Second),
		RetiredAt:           t2,
	}
	v2 := UpstreamVersion{
		ID:                  strings.Repeat("2", 32),
		Slot:                1,
		Seq:                 2,
		Origin:              "upstream",
		State:               "active",
		PayloadRef:          "slot1/v2.enc",
		PayloadSHA256:       sha,
		OutboundFingerprint: fp,
		CreatedAt:           t2,
		ActivatedAt:         t2.Add(time.Second),
	}
	v3 := UpstreamVersion{
		ID:                  strings.Repeat("3", 32),
		Slot:                1,
		Seq:                 3,
		Origin:              "upstream",
		State:               "candidate",
		PayloadRef:          "slot1/v3.enc",
		PayloadSHA256:       sha,
		OutboundFingerprint: fp,
		CreatedAt:           t3,
	}
	v4 := UpstreamVersion{
		ID:                  strings.Repeat("4", 32),
		Slot:                1,
		Seq:                 4,
		Origin:              "upstream",
		State:               "failed",
		PayloadRef:          "slot1/v4.enc",
		PayloadSHA256:       sha,
		OutboundFingerprint: fp,
		FailureCode:         "old_error",
		CreatedAt:           t3,
	}
	for _, row := range []UpstreamVersion{v1, v2, v3, v4} {
		insertUpstreamVersionRow(t, ctx, s, row)
	}
	nextRun := t4.Add(5 * time.Minute).UnixNano()
	seedRollbackSlotRow(t, ctx, s, 1, "upstream", v2.ID, 2, nextRun, "prior_err", t2.UnixNano())

	// Candidate -> failed succeeds and leaves active version and slot row untouched.
	if err := s.FailUpstreamVersion(ctx, v3.ID, "verify_failed", t4); err != nil {
		t.Fatalf("FailUpstreamVersion(candidate): %v", err)
	}
	gotV3, err := s.GetUpstreamVersion(ctx, v3.ID)
	if err != nil {
		t.Fatalf("GetUpstreamVersion(v3): %v", err)
	}
	wantV3 := v3
	wantV3.State = "failed"
	wantV3.FailureCode = "verify_failed"
	if gotV3 != wantV3 {
		t.Fatalf("v3 = %+v, want %+v", gotV3, wantV3)
	}
	gotActive, err := s.ActiveUpstreamVersion(ctx, 1)
	if err != nil || gotActive != v2 {
		t.Fatalf("active version changed: got (%+v, %v), want %+v", gotActive, err, v2)
	}
	mode, activeID, failCount, gotNextRun, lastErr, updatedAt := readRollbackSlotRow(t, ctx, s, 1)
	if mode != "upstream" || activeID != v2.ID || failCount != 2 || gotNextRun != nextRun || lastErr != "prior_err" || updatedAt != t2.UnixNano() {
		t.Fatalf("slot 1 row changed: (%q, %q, %d, %d, %q, %d)", mode, activeID, failCount, gotNextRun, lastErr, updatedAt)
	}

	// Active, superseded, and already-failed versions return ErrInvalidTransition.
	for _, id := range []string{v2.ID, v1.ID, v4.ID} {
		if err := s.FailUpstreamVersion(ctx, id, "new_error", t4); !errors.Is(err, ErrInvalidTransition) {
			t.Fatalf("FailUpstreamVersion(%s) err = %v, want ErrInvalidTransition", id, err)
		}
	}
	for _, want := range []UpstreamVersion{v1, v2, v4} {
		got, err := s.GetUpstreamVersion(ctx, want.ID)
		if err != nil || got != want {
			t.Fatalf("version %s changed after rejected fail: got (%+v, %v), want %+v", want.ID, got, err, want)
		}
	}

	// Unknown valid ID returns ErrNotFound.
	if err := s.FailUpstreamVersion(ctx, strings.Repeat("f", 32), "verify_failed", t4); !errors.Is(err, ErrNotFound) {
		t.Fatalf("FailUpstreamVersion(missing) err = %v, want ErrNotFound", err)
	}

	// Invalid arguments return ErrInvalidArgument without echoing rejected values.
	badCases := []struct {
		name   string
		id     string
		code   string
		now    time.Time
		secret string
	}{
		{name: "short id", id: "zz", code: "bad_cfg", now: t4, secret: "zz"},
		{name: "uppercase id", id: strings.Repeat("A", 32), code: "bad_cfg", now: t4, secret: strings.Repeat("A", 32)},
		{name: "empty code", id: v3.ID, code: "", now: t4},
		{name: "uppercase code", id: v3.ID, code: "BadCode", now: t4, secret: "BadCode"},
		{name: "leading digit code", id: v3.ID, code: "1bad_code", now: t4, secret: "1bad_code"},
		{name: "oversize code", id: v3.ID, code: "a" + strings.Repeat("b", 64), now: t4, secret: "a" + strings.Repeat("b", 64)},
		{name: "zero now", id: v3.ID, code: "bad_cfg", now: time.Time{}},
		{name: "epoch now", id: v3.ID, code: "bad_cfg", now: time.Unix(0, 0).UTC()},
	}
	for _, tc := range badCases {
		t.Run(tc.name, func(t *testing.T) {
			err := s.FailUpstreamVersion(ctx, tc.id, tc.code, tc.now)
			if !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("FailUpstreamVersion(%s) err = %v, want ErrInvalidArgument", tc.name, err)
			}
			if tc.secret != "" && strings.Contains(err.Error(), tc.secret) {
				t.Fatalf("FailUpstreamVersion(%s) error leaked rejected value: %v", tc.name, err)
			}
		})
	}
}

func TestRollbackUpstreamSlot(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, tempPath(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	loc := time.FixedZone("EST", -5*3600)
	t1 := time.Date(2026, 5, 7, 10, 0, 0, 111, time.UTC)
	t2 := t1.Add(time.Minute)
	t3 := t2.Add(time.Minute)
	t4 := t3.Add(time.Minute)
	t5 := t4.Add(time.Minute).In(loc)
	t6 := t5.Add(time.Minute)

	sha := strings.Repeat("a", 64)
	fp := strings.Repeat("b", 64)

	// Slot 1: superseded upstream v1, superseded upstream v2, superseded blackhole v3, active upstream v4.
	s1v1 := UpstreamVersion{
		ID:                  strings.Repeat("1", 32),
		Slot:                1,
		Seq:                 1,
		Origin:              "upstream",
		State:               "superseded",
		PayloadRef:          "slot1/v1.enc",
		PayloadSHA256:       sha,
		OutboundFingerprint: fp,
		CreatedAt:           t1,
		ActivatedAt:         t1.Add(time.Second),
		RetiredAt:           t2,
	}
	s1v2 := UpstreamVersion{
		ID:                  strings.Repeat("2", 32),
		Slot:                1,
		Seq:                 2,
		Origin:              "upstream",
		State:               "superseded",
		PayloadRef:          "slot1/v2.enc",
		PayloadSHA256:       sha,
		OutboundFingerprint: fp,
		CreatedAt:           t2,
		ActivatedAt:         t2.Add(time.Second),
		RetiredAt:           t3,
	}
	s1v3 := UpstreamVersion{
		ID:                  strings.Repeat("3", 32),
		Slot:                1,
		Seq:                 3,
		Origin:              "blackhole",
		State:               "superseded",
		PayloadRef:          "slot1/v3-bh.enc",
		PayloadSHA256:       sha,
		OutboundFingerprint: fp,
		CreatedAt:           t3,
		ActivatedAt:         t3.Add(time.Second),
		RetiredAt:           t4,
	}
	s1v4 := UpstreamVersion{
		ID:                  strings.Repeat("4", 32),
		Slot:                1,
		Seq:                 4,
		Origin:              "upstream",
		State:               "active",
		PayloadRef:          "slot1/v4.enc",
		PayloadSHA256:       sha,
		OutboundFingerprint: fp,
		CreatedAt:           t4,
		ActivatedAt:         t4.Add(time.Second),
	}
	for _, row := range []UpstreamVersion{s1v1, s1v2, s1v3, s1v4} {
		insertUpstreamVersionRow(t, ctx, s, row)
	}
	nextRun := t6.Add(10 * time.Minute).UTC().UnixNano()
	seedRollbackSlotRow(t, ctx, s, 1, "upstream", s1v4.ID, 4, nextRun, "probe_failed", t4.UnixNano())

	restored1, prev1, err := s.RollbackUpstreamSlot(ctx, 1, t5)
	if err != nil {
		t.Fatalf("RollbackUpstreamSlot(slot 1 #1): %v", err)
	}
	wantRestored1 := s1v2
	wantRestored1.State = "active"
	wantRestored1.ActivatedAt = t5.UTC()
	wantRestored1.RetiredAt = time.Time{}
	if restored1 != wantRestored1 || restored1.ActivatedAt.Location() != time.UTC {
		t.Fatalf("restored1 = %+v, want %+v (UTC)", restored1, wantRestored1)
	}
	wantPrev1 := s1v4
	wantPrev1.State = "superseded"
	wantPrev1.RetiredAt = t5.UTC()
	if prev1 == nil || *prev1 != wantPrev1 || prev1.RetiredAt.Location() != time.UTC {
		t.Fatalf("prev1 = %+v, want %+v (UTC)", prev1, wantPrev1)
	}
	gotActive1, err := s.ActiveUpstreamVersion(ctx, 1)
	if err != nil || gotActive1 != wantRestored1 {
		t.Fatalf("ActiveUpstreamVersion(1) = (%+v, %v), want %+v", gotActive1, err, wantRestored1)
	}
	gotPrev1, err := s.GetUpstreamVersion(ctx, s1v4.ID)
	if err != nil || gotPrev1 != wantPrev1 {
		t.Fatalf("GetUpstreamVersion(s1v4) = (%+v, %v), want %+v", gotPrev1, err, wantPrev1)
	}
	listed1, err := s.ListUpstreamVersions(ctx, 1, 10)
	if err != nil {
		t.Fatalf("ListUpstreamVersions(1): %v", err)
	}
	activeCount := 0
	for _, v := range listed1 {
		if v.State == "active" {
			activeCount++
		}
	}
	if activeCount != 1 {
		t.Fatalf("slot 1 active count = %d, want 1", activeCount)
	}
	mode, activeID, failCount, gotNextRun, lastErr, updatedAt := readRollbackSlotRow(t, ctx, s, 1)
	if mode != "upstream" || activeID != s1v2.ID || failCount != 0 || gotNextRun != nextRun || lastErr != "" || updatedAt != t5.UTC().UnixNano() {
		t.Fatalf("slot 1 row = (%q, %q, %d, %d, %q, %d), want (upstream, %s, 0, %d, '', %d)",
			mode, activeID, failCount, gotNextRun, lastErr, updatedAt, s1v2.ID, nextRun, t5.UTC().UnixNano())
	}

	// Second rollback on slot 1 restores s1v1 (seq < active.seq) rather than newer s1v4.
	restored2, prev2, err := s.RollbackUpstreamSlot(ctx, 1, t6)
	if err != nil {
		t.Fatalf("RollbackUpstreamSlot(slot 1 #2): %v", err)
	}
	if restored2.ID != s1v1.ID || prev2 == nil || prev2.ID != s1v2.ID {
		t.Fatalf("second rollback = (%+v, %+v), want restored s1v1 and prev s1v2", restored2, prev2)
	}

	// Slot 2: blackhole active version with an older superseded upstream row restores upstream.
	s2v1 := UpstreamVersion{
		ID:                  strings.Repeat("5", 32),
		Slot:                2,
		Seq:                 1,
		Origin:              "upstream",
		State:               "superseded",
		PayloadRef:          "slot2/v1.enc",
		PayloadSHA256:       sha,
		OutboundFingerprint: fp,
		CreatedAt:           t1,
		ActivatedAt:         t1.Add(time.Second),
		RetiredAt:           t2,
	}
	s2v2 := UpstreamVersion{
		ID:                  strings.Repeat("6", 32),
		Slot:                2,
		Seq:                 2,
		Origin:              "blackhole",
		State:               "active",
		PayloadRef:          "slot2/v2-bh.enc",
		PayloadSHA256:       sha,
		OutboundFingerprint: fp,
		CreatedAt:           t2,
		ActivatedAt:         t2.Add(time.Second),
	}
	insertUpstreamVersionRow(t, ctx, s, s2v1)
	insertUpstreamVersionRow(t, ctx, s, s2v2)
	seedRollbackSlotRow(t, ctx, s, 2, "blackhole", s2v2.ID, 3, 0, "upstream_down", t2.UnixNano())

	restoredBH, prevBH, err := s.RollbackUpstreamSlot(ctx, 2, t3)
	if err != nil {
		t.Fatalf("RollbackUpstreamSlot(slot 2): %v", err)
	}
	if restoredBH.ID != s2v1.ID || restoredBH.State != "active" || restoredBH.ActivatedAt != t3.UTC() || !restoredBH.RetiredAt.IsZero() {
		t.Fatalf("slot 2 restored = %+v, want s2v1 active at %v", restoredBH, t3.UTC())
	}
	if prevBH == nil || prevBH.ID != s2v2.ID || prevBH.State != "superseded" || prevBH.RetiredAt != t3.UTC() {
		t.Fatalf("slot 2 prev = %+v, want s2v2 superseded at %v", prevBH, t3.UTC())
	}
	mode, activeID, failCount, _, lastErr, updatedAt = readRollbackSlotRow(t, ctx, s, 2)
	if mode != "upstream" || activeID != s2v1.ID || failCount != 0 || lastErr != "" || updatedAt != t3.UTC().UnixNano() {
		t.Fatalf("slot 2 row = (%q, %q, %d, %q, %d), want (upstream, %s, 0, '', %d)",
			mode, activeID, failCount, lastErr, updatedAt, s2v1.ID, t3.UTC().UnixNano())
	}

	// Slot 3: only-active version -> ErrNotFound, nothing changes.
	s3v1 := UpstreamVersion{
		ID:                  strings.Repeat("7", 32),
		Slot:                3,
		Seq:                 1,
		Origin:              "upstream",
		State:               "active",
		PayloadRef:          "slot3/v1.enc",
		PayloadSHA256:       sha,
		OutboundFingerprint: fp,
		CreatedAt:           t1,
		ActivatedAt:         t1.Add(time.Second),
	}
	insertUpstreamVersionRow(t, ctx, s, s3v1)
	seedRollbackSlotRow(t, ctx, s, 3, "upstream", s3v1.ID, 1, 0, "err_once", t1.UnixNano())

	if _, _, err := s.RollbackUpstreamSlot(ctx, 3, t3); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RollbackUpstreamSlot(only active) err = %v, want ErrNotFound", err)
	}
	gotS3, err := s.ActiveUpstreamVersion(ctx, 3)
	if err != nil || gotS3 != s3v1 {
		t.Fatalf("slot 3 active changed: got (%+v, %v), want %+v", gotS3, err, s3v1)
	}
	mode, activeID, failCount, _, lastErr, updatedAt = readRollbackSlotRow(t, ctx, s, 3)
	if mode != "upstream" || activeID != s3v1.ID || failCount != 1 || lastErr != "err_once" || updatedAt != t1.UnixNano() {
		t.Fatalf("slot 3 row changed after refused rollback: (%q, %q, %d, %q, %d)", mode, activeID, failCount, lastErr, updatedAt)
	}

	// Slot 4: superseded blackhole only -> ErrNotFound, nothing changes.
	s4v1 := UpstreamVersion{
		ID:                  strings.Repeat("8", 32),
		Slot:                4,
		Seq:                 1,
		Origin:              "blackhole",
		State:               "superseded",
		PayloadRef:          "slot4/v1-bh.enc",
		PayloadSHA256:       sha,
		OutboundFingerprint: fp,
		CreatedAt:           t1,
		ActivatedAt:         t1.Add(time.Second),
		RetiredAt:           t2,
	}
	s4v2 := UpstreamVersion{
		ID:                  strings.Repeat("9", 32),
		Slot:                4,
		Seq:                 2,
		Origin:              "upstream",
		State:               "active",
		PayloadRef:          "slot4/v2.enc",
		PayloadSHA256:       sha,
		OutboundFingerprint: fp,
		CreatedAt:           t2,
		ActivatedAt:         t2.Add(time.Second),
	}
	insertUpstreamVersionRow(t, ctx, s, s4v1)
	insertUpstreamVersionRow(t, ctx, s, s4v2)
	seedRollbackSlotRow(t, ctx, s, 4, "upstream", s4v2.ID, 0, 0, "", t2.UnixNano())

	if _, _, err := s.RollbackUpstreamSlot(ctx, 4, t3); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RollbackUpstreamSlot(blackhole only) err = %v, want ErrNotFound", err)
	}
	gotS4v1, err := s.GetUpstreamVersion(ctx, s4v1.ID)
	if err != nil || gotS4v1 != s4v1 {
		t.Fatalf("s4v1 changed: got (%+v, %v), want %+v", gotS4v1, err, s4v1)
	}
	gotS4v2, err := s.ActiveUpstreamVersion(ctx, 4)
	if err != nil || gotS4v2 != s4v2 {
		t.Fatalf("s4v2 changed: got (%+v, %v), want %+v", gotS4v2, err, s4v2)
	}

	// Slot 5: no active version -> ErrNotFound.
	if _, _, err := s.RollbackUpstreamSlot(ctx, 5, t3); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RollbackUpstreamSlot(no active) err = %v, want ErrNotFound", err)
	}

	// Invalid slot and invalid time return ErrInvalidArgument.
	for _, badSlot := range []int{0, 64} {
		if _, _, err := s.RollbackUpstreamSlot(ctx, badSlot, t3); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("RollbackUpstreamSlot(slot=%d) err = %v, want ErrInvalidArgument", badSlot, err)
		}
	}
	for _, badNow := range []time.Time{{}, time.Unix(0, 0).UTC()} {
		if _, _, err := s.RollbackUpstreamSlot(ctx, 1, badNow); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("RollbackUpstreamSlot(now=%v) err = %v, want ErrInvalidArgument", badNow, err)
		}
	}
}

func TestRollbackUpstreamSlotAfterBlackholePrefersLatestRetired(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, tempPath(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	t1 := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)
	t2 := t1.Add(time.Minute)
	t3 := t2.Add(time.Minute)
	sha := strings.Repeat("a", 64)
	fp := strings.Repeat("b", 64)

	// v1 was restored by a rollback at t2 (so v2 retired at t1), then a
	// blackhole v3 became active at t3. Rollback must restore v1, not the
	// rejected v2.
	v1 := UpstreamVersion{
		ID: strings.Repeat("a", 32), Slot: 6, Seq: 1, Origin: "upstream", State: "superseded",
		PayloadRef: "slot6/v1.enc", PayloadSHA256: sha, OutboundFingerprint: fp,
		CreatedAt: t1, ActivatedAt: t1, RetiredAt: t2,
	}
	v2 := UpstreamVersion{
		ID: strings.Repeat("b", 32), Slot: 6, Seq: 2, Origin: "upstream", State: "superseded",
		PayloadRef: "slot6/v2.enc", PayloadSHA256: sha, OutboundFingerprint: fp,
		CreatedAt: t1, ActivatedAt: t1, RetiredAt: t1.Add(time.Second),
	}
	v3 := UpstreamVersion{
		ID: strings.Repeat("c", 32), Slot: 6, Seq: 3, Origin: "blackhole", State: "active",
		PayloadRef: "slot6/v3-bh.enc", PayloadSHA256: sha, OutboundFingerprint: fp,
		CreatedAt: t3, ActivatedAt: t3,
	}
	for _, row := range []UpstreamVersion{v1, v2, v3} {
		insertUpstreamVersionRow(t, ctx, s, row)
	}
	seedRollbackSlotRow(t, ctx, s, 6, "blackhole", v3.ID, 2, 0, "probe_failed", t3.UnixNano())

	restored, prev, err := s.RollbackUpstreamSlot(ctx, 6, t3.Add(time.Minute))
	if err != nil {
		t.Fatalf("RollbackUpstreamSlot: %v", err)
	}
	if restored.ID != v1.ID {
		t.Fatalf("restored = %s, want v1 %s", restored.ID, v1.ID)
	}
	if prev == nil || prev.ID != v3.ID {
		t.Fatalf("prev = %+v, want blackhole %s", prev, v3.ID)
	}
}
