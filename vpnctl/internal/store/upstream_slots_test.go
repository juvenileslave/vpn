package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestUpstreamSlotAndRecordFailure(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, tempPath(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	if _, err := s.UpstreamSlot(ctx, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpstreamSlot(unrefreshed) err = %v, want ErrNotFound", err)
	}

	loc := time.FixedZone("CET", 3600)
	now1 := time.Date(2026, 5, 8, 10, 0, 0, 123, loc)
	next1 := now1.Add(5 * time.Minute)

	got1, err := s.RecordUpstreamFailure(ctx, 1, "dns_timeout", next1, now1)
	if err != nil {
		t.Fatalf("RecordUpstreamFailure(#1): %v", err)
	}
	want1 := UpstreamSlot{
		Slot:          1,
		Mode:          "blackhole",
		FailureCount:  1,
		NextRunAt:     next1.UTC(),
		LastErrorCode: "dns_timeout",
		UpdatedAt:     now1.UTC(),
	}
	if got1 != want1 || got1.NextRunAt.Location() != time.UTC || got1.UpdatedAt.Location() != time.UTC {
		t.Fatalf("RecordUpstreamFailure(#1) = %+v, want %+v (UTC)", got1, want1)
	}
	persisted1, err := s.UpstreamSlot(ctx, 1)
	if err != nil || persisted1 != want1 {
		t.Fatalf("UpstreamSlot(1) = (%+v, %v), want %+v", persisted1, err, want1)
	}

	// Set mode and active_version_id directly via SQL to verify preservation on failure.
	activeID := strings.Repeat("a", 32)
	if _, err := s.db.ExecContext(ctx,
		`UPDATE upstream_slots SET mode = 'upstream', active_version_id = ? WHERE slot = 1`,
		activeID,
	); err != nil {
		t.Fatalf("seed slot 1 mode/active_version_id: %v", err)
	}

	now2 := now1.Add(time.Minute)
	next2 := now2.Add(10 * time.Minute)
	got2, err := s.RecordUpstreamFailure(ctx, 1, "tls_handshake_failed", next2, now2)
	if err != nil {
		t.Fatalf("RecordUpstreamFailure(#2): %v", err)
	}
	want2 := UpstreamSlot{
		Slot:            1,
		Mode:            "upstream",
		ActiveVersionID: activeID,
		FailureCount:    2,
		NextRunAt:       next2.UTC(),
		LastErrorCode:   "tls_handshake_failed",
		UpdatedAt:       now2.UTC(),
	}
	if got2 != want2 {
		t.Fatalf("RecordUpstreamFailure(#2) = %+v, want %+v", got2, want2)
	}
	persisted2, err := s.UpstreamSlot(ctx, 1)
	if err != nil || persisted2 != want2 {
		t.Fatalf("UpstreamSlot(1 after #2) = (%+v, %v), want %+v", persisted2, err, want2)
	}

	// Zero nextRun clears NextRunAt while incrementing FailureCount and preserving mode/active_version_id.
	now3 := now2.Add(time.Minute)
	got3, err := s.RecordUpstreamFailure(ctx, 1, "bad_signature", time.Time{}, now3)
	if err != nil {
		t.Fatalf("RecordUpstreamFailure(#3): %v", err)
	}
	want3 := UpstreamSlot{
		Slot:            1,
		Mode:            "upstream",
		ActiveVersionID: activeID,
		FailureCount:    3,
		LastErrorCode:   "bad_signature",
		UpdatedAt:       now3.UTC(),
	}
	if got3 != want3 || !got3.NextRunAt.IsZero() {
		t.Fatalf("RecordUpstreamFailure(#3) = %+v, want %+v with zero NextRunAt", got3, want3)
	}
}

func TestScheduleUpstreamSlot(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, tempPath(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	loc := time.FixedZone("EST", -5*3600)
	now1 := time.Date(2026, 5, 9, 8, 0, 0, 456, loc)
	next1 := now1.Add(15 * time.Minute)

	// Missing slot is created in blackhole mode with count 0.
	if err := s.ScheduleUpstreamSlot(ctx, 3, next1, now1); err != nil {
		t.Fatalf("ScheduleUpstreamSlot(missing): %v", err)
	}
	got3, err := s.UpstreamSlot(ctx, 3)
	if err != nil {
		t.Fatalf("UpstreamSlot(3): %v", err)
	}
	want3 := UpstreamSlot{
		Slot:         3,
		Mode:         "blackhole",
		FailureCount: 0,
		NextRunAt:    next1.UTC(),
		UpdatedAt:    now1.UTC(),
	}
	if got3 != want3 || got3.NextRunAt.Location() != time.UTC || got3.UpdatedAt.Location() != time.UTC {
		t.Fatalf("UpstreamSlot(3) = %+v, want %+v (UTC)", got3, want3)
	}

	// Existing slot updates only next_run_at and updated_at.
	activeID := strings.Repeat("b", 32)
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO upstream_slots (slot, mode, active_version_id, failure_count, next_run_at, last_error_code, updated_at)
		 VALUES (4, 'upstream', ?, 5, ?, 'fetch_timeout', ?)`,
		activeID, next1.UTC().UnixNano(), now1.UTC().UnixNano(),
	); err != nil {
		t.Fatalf("seed slot 4: %v", err)
	}

	now2 := now1.Add(time.Minute)
	next2 := now2.Add(30 * time.Minute)
	if err := s.ScheduleUpstreamSlot(ctx, 4, next2, now2); err != nil {
		t.Fatalf("ScheduleUpstreamSlot(existing): %v", err)
	}
	got4, err := s.UpstreamSlot(ctx, 4)
	if err != nil {
		t.Fatalf("UpstreamSlot(4): %v", err)
	}
	want4 := UpstreamSlot{
		Slot:            4,
		Mode:            "upstream",
		ActiveVersionID: activeID,
		FailureCount:    5,
		NextRunAt:       next2.UTC(),
		LastErrorCode:   "fetch_timeout",
		UpdatedAt:       now2.UTC(),
	}
	if got4 != want4 {
		t.Fatalf("UpstreamSlot(4) = %+v, want %+v", got4, want4)
	}

	// Zero nextRun clears NextRunAt while leaving other fields intact.
	now3 := now2.Add(time.Minute)
	if err := s.ScheduleUpstreamSlot(ctx, 4, time.Time{}, now3); err != nil {
		t.Fatalf("ScheduleUpstreamSlot(zero nextRun): %v", err)
	}
	got4Cleared, err := s.UpstreamSlot(ctx, 4)
	if err != nil {
		t.Fatalf("UpstreamSlot(4 cleared): %v", err)
	}
	want4.NextRunAt = time.Time{}
	want4.UpdatedAt = now3.UTC()
	if got4Cleared != want4 || !got4Cleared.NextRunAt.IsZero() {
		t.Fatalf("UpstreamSlot(4 cleared) = %+v, want %+v", got4Cleared, want4)
	}
}

func TestListUpstreamSlots(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, tempPath(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	empty, err := s.ListUpstreamSlots(ctx)
	if err != nil {
		t.Fatalf("ListUpstreamSlots(empty): %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("ListUpstreamSlots(empty) len = %d, want 0", len(empty))
	}

	now := time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC)
	next := now.Add(time.Hour)
	if _, err := s.RecordUpstreamFailure(ctx, 10, "err_ten", next, now); err != nil {
		t.Fatalf("RecordUpstreamFailure(10): %v", err)
	}
	if err := s.ScheduleUpstreamSlot(ctx, 2, next, now); err != nil {
		t.Fatalf("ScheduleUpstreamSlot(2): %v", err)
	}
	if _, err := s.RecordUpstreamFailure(ctx, 5, "err_five", time.Time{}, now); err != nil {
		t.Fatalf("RecordUpstreamFailure(5): %v", err)
	}

	got, err := s.ListUpstreamSlots(ctx)
	if err != nil {
		t.Fatalf("ListUpstreamSlots: %v", err)
	}
	wantSlots := []int{2, 5, 10}
	if len(got) != len(wantSlots) {
		t.Fatalf("ListUpstreamSlots len = %d, want %d", len(got), len(wantSlots))
	}
	for i, slot := range wantSlots {
		if got[i].Slot != slot {
			t.Fatalf("ListUpstreamSlots[%d].Slot = %d, want %d", i, got[i].Slot, slot)
		}
		want, err := s.UpstreamSlot(ctx, slot)
		if err != nil {
			t.Fatalf("UpstreamSlot(%d): %v", slot, err)
		}
		if got[i] != want {
			t.Fatalf("ListUpstreamSlots[%d] = %+v, want %+v", i, got[i], want)
		}
	}
}

func TestUpstreamSlotsValidation(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, tempPath(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	validNow := time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC)
	validNext := validNow.Add(time.Minute)
	negTime := time.Unix(-1, 0).UTC()

	for _, badSlot := range []int{0, 64} {
		if _, err := s.UpstreamSlot(ctx, badSlot); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("UpstreamSlot(%d) err = %v, want ErrInvalidArgument", badSlot, err)
		}
	}

	failCases := []struct {
		name    string
		slot    int
		code    string
		nextRun time.Time
		now     time.Time
		secret  string
	}{
		{name: "slot zero", slot: 0, code: "bad_cfg", nextRun: validNext, now: validNow},
		{name: "slot too high", slot: 64, code: "bad_cfg", nextRun: validNext, now: validNow},
		{name: "empty code", slot: 1, code: "", nextRun: validNext, now: validNow},
		{name: "uppercase code", slot: 1, code: "UPPER_SECRET_CODE", nextRun: validNext, now: validNow, secret: "UPPER_SECRET_CODE"},
		{name: "leading digit code", slot: 1, code: "1secret_code", nextRun: validNext, now: validNow, secret: "1secret_code"},
		{name: "oversize code", slot: 1, code: "a" + strings.Repeat("b", 64), nextRun: validNext, now: validNow, secret: "a" + strings.Repeat("b", 64)},
		{name: "zero now", slot: 1, code: "bad_cfg", nextRun: validNext, now: time.Time{}},
		{name: "epoch now", slot: 1, code: "bad_cfg", nextRun: validNext, now: time.Unix(0, 0).UTC()},
		{name: "negative nextRun", slot: 1, code: "bad_cfg", nextRun: negTime, now: validNow},
	}
	for _, tc := range failCases {
		t.Run("record_"+tc.name, func(t *testing.T) {
			_, err := s.RecordUpstreamFailure(ctx, tc.slot, tc.code, tc.nextRun, tc.now)
			if !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("RecordUpstreamFailure(%s) err = %v, want ErrInvalidArgument", tc.name, err)
			}
			if tc.secret != "" && strings.Contains(err.Error(), tc.secret) {
				t.Fatalf("RecordUpstreamFailure(%s) error leaked rejected value: %v", tc.name, err)
			}
		})
	}

	schedCases := []struct {
		name    string
		slot    int
		nextRun time.Time
		now     time.Time
	}{
		{name: "slot zero", slot: 0, nextRun: validNext, now: validNow},
		{name: "slot too high", slot: 64, nextRun: validNext, now: validNow},
		{name: "zero now", slot: 1, nextRun: validNext, now: time.Time{}},
		{name: "epoch now", slot: 1, nextRun: validNext, now: time.Unix(0, 0).UTC()},
		{name: "negative nextRun", slot: 1, nextRun: negTime, now: validNow},
	}
	for _, tc := range schedCases {
		t.Run("schedule_"+tc.name, func(t *testing.T) {
			err := s.ScheduleUpstreamSlot(ctx, tc.slot, tc.nextRun, tc.now)
			if !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("ScheduleUpstreamSlot(%s) err = %v, want ErrInvalidArgument", tc.name, err)
			}
		})
	}

	got, err := s.ListUpstreamSlots(ctx)
	if err != nil {
		t.Fatalf("ListUpstreamSlots: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("invalid calls persisted %d rows, want 0", len(got))
	}
}

func TestUpstreamSlotsCorruptRow(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, tempPath(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	now := time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC).UnixNano()
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO upstream_slots (slot, mode, active_version_id, failure_count, next_run_at, last_error_code, updated_at)
		 VALUES (8, 'upstream', ?, 0, 0, '', ?)`,
		strings.Repeat("Z", 32), now,
	); err != nil {
		t.Fatalf("insert corrupt slot row: %v", err)
	}

	if _, err := s.UpstreamSlot(ctx, 8); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("UpstreamSlot(corrupt) err = %v, want ErrCorrupt", err)
	}
	if _, err := s.ListUpstreamSlots(ctx); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("ListUpstreamSlots(corrupt) err = %v, want ErrCorrupt", err)
	}
}
