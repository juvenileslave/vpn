package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func insertUpstreamVersionRow(t *testing.T, ctx context.Context, s *Store, v UpstreamVersion) {
	t.Helper()
	var activatedAt, retiredAt int64
	if !v.ActivatedAt.IsZero() {
		activatedAt = v.ActivatedAt.UTC().UnixNano()
	}
	if !v.RetiredAt.IsZero() {
		retiredAt = v.RetiredAt.UTC().UnixNano()
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO upstream_versions (
			id, slot, seq, origin, state, payload_ref, payload_sha256,
			outbound_fingerprint, failure_code, created_at, activated_at, retired_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		v.ID, v.Slot, v.Seq, v.Origin, v.State, v.PayloadRef, v.PayloadSHA256,
		v.OutboundFingerprint, v.FailureCode, v.CreatedAt.UTC().UnixNano(), activatedAt, retiredAt,
	)
	if err != nil {
		t.Fatalf("insert upstream version %s: %v", v.ID, err)
	}
}

func TestListUpstreamVersions(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, tempPath(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	t1 := time.Date(2026, 5, 1, 10, 0, 0, 123, time.UTC)
	t2 := t1.Add(time.Minute)
	t3 := t2.Add(time.Minute)
	t4 := t3.Add(time.Minute)

	shaA := strings.Repeat("a", 64)
	shaB := strings.Repeat("b", 64)
	shaC := strings.Repeat("c", 64)
	fpA := strings.Repeat("1", 64)
	fpB := strings.Repeat("2", 64)
	fpC := strings.Repeat("3", 64)

	s1v1 := UpstreamVersion{
		ID:                  strings.Repeat("a", 32),
		Slot:                1,
		Seq:                 1,
		Origin:              "upstream",
		State:               "superseded",
		PayloadRef:          "slot1/v1.enc",
		PayloadSHA256:       shaA,
		OutboundFingerprint: fpA,
		CreatedAt:           t1,
		ActivatedAt:         t1.Add(time.Second),
		RetiredAt:           t2,
	}
	s1v2 := UpstreamVersion{
		ID:                  strings.Repeat("b", 32),
		Slot:                1,
		Seq:                 2,
		Origin:              "upstream",
		State:               "active",
		PayloadRef:          "slot1/v2.enc",
		PayloadSHA256:       shaB,
		OutboundFingerprint: fpB,
		CreatedAt:           t2,
		ActivatedAt:         t2.Add(time.Second),
	}
	s1v3 := UpstreamVersion{
		ID:                  strings.Repeat("c", 32),
		Slot:                1,
		Seq:                 3,
		Origin:              "blackhole",
		State:               "failed",
		PayloadRef:          "slot1/v3.enc",
		PayloadSHA256:       shaC,
		OutboundFingerprint: fpC,
		FailureCode:         "bad_checksum",
		CreatedAt:           t3,
	}
	s2v1 := UpstreamVersion{
		ID:                  strings.Repeat("d", 32),
		Slot:                2,
		Seq:                 1,
		Origin:              "upstream",
		State:               "candidate",
		PayloadRef:          "slot2/v1.enc",
		PayloadSHA256:       shaA,
		OutboundFingerprint: fpA,
		CreatedAt:           t4,
	}

	// Insert out of seq order to ensure ORDER BY seq DESC is enforced.
	for _, row := range []UpstreamVersion{s1v1, s1v3, s2v1, s1v2} {
		insertUpstreamVersionRow(t, ctx, s, row)
	}

	gotSlot1, err := s.ListUpstreamVersions(ctx, 1, 10)
	if err != nil {
		t.Fatalf("ListUpstreamVersions(slot 1): %v", err)
	}
	wantSlot1 := []UpstreamVersion{s1v3, s1v2, s1v1}
	if len(gotSlot1) != len(wantSlot1) {
		t.Fatalf("slot 1 len = %d, want %d", len(gotSlot1), len(wantSlot1))
	}
	for i := range wantSlot1 {
		if gotSlot1[i] != wantSlot1[i] {
			t.Errorf("slot 1[%d] = %+v, want %+v", i, gotSlot1[i], wantSlot1[i])
		}
		if gotSlot1[i].CreatedAt.Location() != time.UTC {
			t.Errorf("slot 1[%d].CreatedAt location = %v, want UTC", i, gotSlot1[i].CreatedAt.Location())
		}
	}
	if !gotSlot1[0].ActivatedAt.IsZero() || !gotSlot1[0].RetiredAt.IsZero() {
		t.Errorf("unset timestamps should be zero: activated=%v retired=%v", gotSlot1[0].ActivatedAt, gotSlot1[0].RetiredAt)
	}

	gotLimited, err := s.ListUpstreamVersions(ctx, 1, 2)
	if err != nil {
		t.Fatalf("ListUpstreamVersions(slot 1, limit 2): %v", err)
	}
	if len(gotLimited) != 2 || gotLimited[0].Seq != 3 || gotLimited[1].Seq != 2 {
		t.Fatalf("limited slot 1 = %+v, want seqs [3, 2]", gotLimited)
	}

	gotSlot2, err := s.ListUpstreamVersions(ctx, 2, 10)
	if err != nil {
		t.Fatalf("ListUpstreamVersions(slot 2): %v", err)
	}
	if len(gotSlot2) != 1 || gotSlot2[0] != s2v1 {
		t.Fatalf("slot 2 = %+v, want [%+v]", gotSlot2, s2v1)
	}

	gotEmpty, err := s.ListUpstreamVersions(ctx, 3, 10)
	if err != nil {
		t.Fatalf("ListUpstreamVersions(unused slot 3): %v", err)
	}
	if len(gotEmpty) != 0 {
		t.Fatalf("unused slot 3 len = %d, want 0", len(gotEmpty))
	}
}

func TestListUpstreamVersionsValidation(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, tempPath(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	cases := []struct {
		name  string
		slot  int
		limit int
	}{
		{name: "slot zero", slot: 0, limit: 10},
		{name: "slot too high", slot: 64, limit: 10},
		{name: "limit zero", slot: 1, limit: 0},
		{name: "limit above max", slot: 1, limit: 1001},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.ListUpstreamVersions(ctx, tc.slot, tc.limit)
			if !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("ListUpstreamVersions(%d, %d) err = %v, want ErrInvalidArgument", tc.slot, tc.limit, err)
			}
		})
	}
}

func TestListUpstreamVersionsCorruptRow(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, tempPath(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	insertUpstreamVersionRow(t, ctx, s, UpstreamVersion{
		ID:                  strings.Repeat("Z", 32),
		Slot:                9,
		Seq:                 1,
		Origin:              "upstream",
		State:               "candidate",
		PayloadRef:          "slot9/v1.enc",
		PayloadSHA256:       strings.Repeat("a", 64),
		OutboundFingerprint: strings.Repeat("b", 64),
		CreatedAt:           time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC),
	})

	_, err = s.ListUpstreamVersions(ctx, 9, 10)
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("ListUpstreamVersions(corrupt row) err = %v, want ErrCorrupt", err)
	}
}

func TestGetUpstreamVersion(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, tempPath(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	created := time.Date(2026, 5, 2, 12, 30, 0, 456, time.UTC)
	activated := created.Add(5 * time.Second)
	want := UpstreamVersion{
		ID:                  strings.Repeat("1", 32),
		Slot:                4,
		Seq:                 2,
		Origin:              "upstream",
		State:               "active",
		PayloadRef:          "slot4/v2.enc",
		PayloadSHA256:       strings.Repeat("a", 64),
		OutboundFingerprint: strings.Repeat("b", 64),
		CreatedAt:           created,
		ActivatedAt:         activated,
	}
	insertUpstreamVersionRow(t, ctx, s, want)

	got, err := s.GetUpstreamVersion(ctx, want.ID)
	if err != nil {
		t.Fatalf("GetUpstreamVersion: %v", err)
	}
	if got != want {
		t.Fatalf("GetUpstreamVersion = %+v, want %+v", got, want)
	}
	if got.CreatedAt.Location() != time.UTC || got.ActivatedAt.Location() != time.UTC {
		t.Fatalf("timestamps not UTC: created=%v activated=%v", got.CreatedAt.Location(), got.ActivatedAt.Location())
	}
	if !got.RetiredAt.IsZero() {
		t.Fatalf("RetiredAt = %v, want zero", got.RetiredAt)
	}

	_, err = s.GetUpstreamVersion(ctx, strings.Repeat("f", 32))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetUpstreamVersion(missing) err = %v, want ErrNotFound", err)
	}

	for _, badID := range []string{"zz", strings.Repeat("A", 32)} {
		_, err = s.GetUpstreamVersion(ctx, badID)
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("GetUpstreamVersion(%q) err = %v, want ErrInvalidArgument", badID, err)
		}
		if strings.Contains(err.Error(), badID) {
			t.Fatalf("GetUpstreamVersion(%q) error leaked rejected value: %v", badID, err)
		}
	}

	corruptID := strings.Repeat("2", 32)
	insertUpstreamVersionRow(t, ctx, s, UpstreamVersion{
		ID:                  corruptID,
		Slot:                4,
		Seq:                 3,
		Origin:              "upstream",
		State:               "candidate",
		PayloadRef:          "slot4/v3.enc",
		PayloadSHA256:       strings.Repeat("A", 64),
		OutboundFingerprint: strings.Repeat("b", 64),
		CreatedAt:           created,
	})
	_, err = s.GetUpstreamVersion(ctx, corruptID)
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("GetUpstreamVersion(corrupt) err = %v, want ErrCorrupt", err)
	}
}

func TestActiveUpstreamVersion(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, tempPath(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	t1 := time.Date(2026, 5, 3, 8, 0, 0, 789, time.UTC)
	t2 := t1.Add(time.Minute)
	t3 := t2.Add(time.Minute)
	t4 := t3.Add(time.Minute)

	sha := strings.Repeat("a", 64)
	fp := strings.Repeat("b", 64)

	wantSlot1 := UpstreamVersion{
		ID:                  strings.Repeat("b", 32),
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
	rows := []UpstreamVersion{
		{
			ID:                  strings.Repeat("a", 32),
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
		},
		wantSlot1,
		{
			ID:                  strings.Repeat("c", 32),
			Slot:                1,
			Seq:                 3,
			Origin:              "upstream",
			State:               "candidate",
			PayloadRef:          "slot1/v3.enc",
			PayloadSHA256:       sha,
			OutboundFingerprint: fp,
			CreatedAt:           t3,
		},
		{
			ID:                  strings.Repeat("d", 32),
			Slot:                1,
			Seq:                 4,
			Origin:              "blackhole",
			State:               "failed",
			PayloadRef:          "slot1/v4.enc",
			PayloadSHA256:       sha,
			OutboundFingerprint: fp,
			FailureCode:         "invalid_payload",
			CreatedAt:           t4,
		},
		{
			ID:                  strings.Repeat("e", 32),
			Slot:                2,
			Seq:                 1,
			Origin:              "upstream",
			State:               "candidate",
			PayloadRef:          "slot2/v1.enc",
			PayloadSHA256:       sha,
			OutboundFingerprint: fp,
			CreatedAt:           t1,
		},
		{
			ID:                  strings.Repeat("f", 32),
			Slot:                2,
			Seq:                 2,
			Origin:              "upstream",
			State:               "superseded",
			PayloadRef:          "slot2/v2.enc",
			PayloadSHA256:       sha,
			OutboundFingerprint: fp,
			CreatedAt:           t2,
			ActivatedAt:         t2.Add(time.Second),
			RetiredAt:           t3,
		},
		{
			ID:                  strings.Repeat("0", 32),
			Slot:                2,
			Seq:                 3,
			Origin:              "blackhole",
			State:               "failed",
			PayloadRef:          "slot2/v3.enc",
			PayloadSHA256:       sha,
			OutboundFingerprint: fp,
			FailureCode:         "decode_error",
			CreatedAt:           t3,
		},
	}
	for _, r := range rows {
		insertUpstreamVersionRow(t, ctx, s, r)
	}

	got, err := s.ActiveUpstreamVersion(ctx, 1)
	if err != nil {
		t.Fatalf("ActiveUpstreamVersion(1): %v", err)
	}
	if got != wantSlot1 {
		t.Fatalf("ActiveUpstreamVersion(1) = %+v, want %+v", got, wantSlot1)
	}
	if got.CreatedAt.Location() != time.UTC || got.ActivatedAt.Location() != time.UTC {
		t.Fatalf("timestamps not UTC: created=%v activated=%v", got.CreatedAt.Location(), got.ActivatedAt.Location())
	}

	for _, slot := range []int{2, 3} {
		_, err = s.ActiveUpstreamVersion(ctx, slot)
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("ActiveUpstreamVersion(%d) err = %v, want ErrNotFound", slot, err)
		}
	}

	for _, badSlot := range []int{0, 64} {
		_, err = s.ActiveUpstreamVersion(ctx, badSlot)
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("ActiveUpstreamVersion(%d) err = %v, want ErrInvalidArgument", badSlot, err)
		}
	}

	insertUpstreamVersionRow(t, ctx, s, UpstreamVersion{
		ID:                  strings.Repeat("9", 32),
		Slot:                5,
		Seq:                 1,
		Origin:              "upstream",
		State:               "active",
		PayloadRef:          "slot5/v1.enc",
		PayloadSHA256:       strings.Repeat("F", 64),
		OutboundFingerprint: fp,
		CreatedAt:           t1,
		ActivatedAt:         t1,
	})
	_, err = s.ActiveUpstreamVersion(ctx, 5)
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("ActiveUpstreamVersion(corrupt) err = %v, want ErrCorrupt", err)
	}
}

func TestCreateUpstreamVersion(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, tempPath(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	loc := time.FixedZone("EST", -5*3600)
	now1 := time.Date(2026, 5, 4, 9, 0, 0, 123, loc)
	now2 := now1.Add(time.Minute)
	now3 := now2.Add(time.Minute)

	sha := strings.Repeat("a", 64)
	fp := strings.Repeat("b", 64)

	// Empty ID generates a 32-hex ID; caller-supplied Seq/State/ActivatedAt/RetiredAt are ignored.
	v1, err := s.CreateUpstreamVersion(ctx, UpstreamVersion{
		Slot:                1,
		Seq:                 99,
		Origin:              "upstream",
		State:               "active",
		PayloadRef:          "slot1/v1.enc",
		PayloadSHA256:       sha,
		OutboundFingerprint: fp,
		ActivatedAt:         now1,
		RetiredAt:           now1,
	}, now1)
	if err != nil {
		t.Fatalf("CreateUpstreamVersion(slot 1 #1): %v", err)
	}
	if !upstreamIDPattern.MatchString(v1.ID) {
		t.Fatalf("generated ID %q does not match 32-hex pattern", v1.ID)
	}
	if v1.Seq != 1 {
		t.Fatalf("v1.Seq = %d, want 1", v1.Seq)
	}
	if v1.State != "candidate" {
		t.Fatalf("v1.State = %q, want candidate", v1.State)
	}
	if v1.CreatedAt != now1.UTC() || v1.CreatedAt.Location() != time.UTC {
		t.Fatalf("v1.CreatedAt = %v (%v), want %v (UTC)", v1.CreatedAt, v1.CreatedAt.Location(), now1.UTC())
	}
	if !v1.ActivatedAt.IsZero() || !v1.RetiredAt.IsZero() {
		t.Fatalf("v1 activated/retired should be zero: %v / %v", v1.ActivatedAt, v1.RetiredAt)
	}

	got1, err := s.GetUpstreamVersion(ctx, v1.ID)
	if err != nil {
		t.Fatalf("GetUpstreamVersion(v1): %v", err)
	}
	if got1 != v1 {
		t.Fatalf("round-trip v1 = %+v, want %+v", got1, v1)
	}

	// Second version in slot 1 gets seq 2; caller-supplied ID is preserved.
	suppliedID := strings.Repeat("c", 32)
	v2, err := s.CreateUpstreamVersion(ctx, UpstreamVersion{
		ID:                  suppliedID,
		Slot:                1,
		Origin:              "blackhole",
		PayloadRef:          "slot1/v2.enc",
		PayloadSHA256:       strings.Repeat("d", 64),
		OutboundFingerprint: strings.Repeat("e", 64),
	}, now2)
	if err != nil {
		t.Fatalf("CreateUpstreamVersion(slot 1 #2): %v", err)
	}
	if v2.ID != suppliedID {
		t.Fatalf("v2.ID = %q, want %q", v2.ID, suppliedID)
	}
	if v2.Seq != 2 {
		t.Fatalf("v2.Seq = %d, want 2", v2.Seq)
	}
	if v2.Origin != "blackhole" || v2.State != "candidate" {
		t.Fatalf("v2 origin/state = %q/%q, want blackhole/candidate", v2.Origin, v2.State)
	}

	got2, err := s.GetUpstreamVersion(ctx, v2.ID)
	if err != nil {
		t.Fatalf("GetUpstreamVersion(v2): %v", err)
	}
	if got2 != v2 {
		t.Fatalf("round-trip v2 = %+v, want %+v", got2, v2)
	}

	// Slot 2 has an independent sequence starting at 1.
	s2v1, err := s.CreateUpstreamVersion(ctx, UpstreamVersion{
		Slot:                2,
		Origin:              "upstream",
		PayloadRef:          "slot2/v1.enc",
		PayloadSHA256:       sha,
		OutboundFingerprint: fp,
	}, now3)
	if err != nil {
		t.Fatalf("CreateUpstreamVersion(slot 2 #1): %v", err)
	}
	if s2v1.Seq != 1 {
		t.Fatalf("slot 2 seq = %d, want 1", s2v1.Seq)
	}
	if s2v1.ID == v1.ID || !upstreamIDPattern.MatchString(s2v1.ID) {
		t.Fatalf("slot 2 ID = %q, want fresh 32-hex ID", s2v1.ID)
	}
}

func TestCreateUpstreamVersionValidation(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, tempPath(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	validNow := time.Date(2026, 5, 4, 10, 0, 0, 0, time.UTC)
	base := func() UpstreamVersion {
		return UpstreamVersion{
			Slot:                7,
			Origin:              "upstream",
			PayloadRef:          "slot7/v1.enc",
			PayloadSHA256:       strings.Repeat("a", 64),
			OutboundFingerprint: strings.Repeat("b", 64),
		}
	}

	cases := []struct {
		name   string
		mutate func(*UpstreamVersion)
		now    time.Time
		secret string
	}{
		{
			name:   "slot zero",
			mutate: func(v *UpstreamVersion) { v.Slot = 0 },
			now:    validNow,
		},
		{
			name:   "slot too high",
			mutate: func(v *UpstreamVersion) { v.Slot = 64 },
			now:    validNow,
		},
		{
			name:   "empty origin",
			mutate: func(v *UpstreamVersion) { v.Origin = "" },
			now:    validNow,
		},
		{
			name:   "unknown origin",
			mutate: func(v *UpstreamVersion) { v.Origin = "secret_origin_val" },
			now:    validNow,
			secret: "secret_origin_val",
		},
		{
			name:   "empty payload ref",
			mutate: func(v *UpstreamVersion) { v.PayloadRef = "" },
			now:    validNow,
		},
		{
			name:   "payload ref with space",
			mutate: func(v *UpstreamVersion) { v.PayloadRef = "slot7/bad ref.enc" },
			now:    validNow,
			secret: "bad ref",
		},
		{
			name:   "payload ref with control char",
			mutate: func(v *UpstreamVersion) { v.PayloadRef = "slot7/ctrl\x01ref.enc" },
			now:    validNow,
			secret: "ctrl\x01ref",
		},
		{
			name:   "payload ref too long",
			mutate: func(v *UpstreamVersion) { v.PayloadRef = strings.Repeat("x", 129) },
			now:    validNow,
			secret: strings.Repeat("x", 129),
		},
		{
			name:   "uppercase sha256",
			mutate: func(v *UpstreamVersion) { v.PayloadSHA256 = strings.Repeat("A", 64) },
			now:    validNow,
			secret: strings.Repeat("A", 64),
		},
		{
			name:   "short sha256",
			mutate: func(v *UpstreamVersion) { v.PayloadSHA256 = "deadbeef" },
			now:    validNow,
			secret: "deadbeef",
		},
		{
			name:   "uppercase fingerprint",
			mutate: func(v *UpstreamVersion) { v.OutboundFingerprint = strings.Repeat("F", 64) },
			now:    validNow,
			secret: strings.Repeat("F", 64),
		},
		{
			name:   "short fingerprint",
			mutate: func(v *UpstreamVersion) { v.OutboundFingerprint = "cafebabe" },
			now:    validNow,
			secret: "cafebabe",
		},
		{
			name:   "non-empty failure code",
			mutate: func(v *UpstreamVersion) { v.FailureCode = "bad_checksum" },
			now:    validNow,
			secret: "bad_checksum",
		},
		{
			name:   "invalid caller id",
			mutate: func(v *UpstreamVersion) { v.ID = "not-a-valid-hex-id" },
			now:    validNow,
			secret: "not-a-valid-hex-id",
		},
		{
			name:   "uppercase caller id",
			mutate: func(v *UpstreamVersion) { v.ID = strings.Repeat("B", 32) },
			now:    validNow,
			secret: strings.Repeat("B", 32),
		},
		{
			name:   "zero now",
			mutate: func(v *UpstreamVersion) {},
			now:    time.Time{},
		},
		{
			name:   "epoch now",
			mutate: func(v *UpstreamVersion) {},
			now:    time.Unix(0, 0).UTC(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := base()
			tc.mutate(&v)
			_, err := s.CreateUpstreamVersion(ctx, v, tc.now)
			if !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("CreateUpstreamVersion(%s) err = %v, want ErrInvalidArgument", tc.name, err)
			}
			if tc.secret != "" && strings.Contains(err.Error(), tc.secret) {
				t.Fatalf("CreateUpstreamVersion(%s) error leaked rejected value: %v", tc.name, err)
			}
		})
	}

	got, err := s.ListUpstreamVersions(ctx, 7, 10)
	if err != nil {
		t.Fatalf("ListUpstreamVersions(7): %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("invalid creates persisted %d rows, want 0", len(got))
	}
}

func readUpstreamSlotRow(t *testing.T, ctx context.Context, s *Store, slot int) (mode, activeID string, failureCount int, nextRunAt int64, lastErrorCode string, updatedAt int64) {
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

func TestActivateUpstreamVersion(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, tempPath(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	loc := time.FixedZone("CET", 3600)
	t1 := time.Date(2026, 5, 5, 10, 0, 0, 111, loc)
	t2 := t1.Add(time.Minute)
	t3 := t2.Add(time.Minute)
	t4 := t3.Add(time.Minute)
	t5 := t4.Add(time.Minute)

	sha := strings.Repeat("a", 64)
	fp := strings.Repeat("b", 64)

	c1 := UpstreamVersion{
		ID:                  strings.Repeat("1", 32),
		Slot:                1,
		Seq:                 1,
		Origin:              "upstream",
		State:               "candidate",
		PayloadRef:          "slot1/v1.enc",
		PayloadSHA256:       sha,
		OutboundFingerprint: fp,
		CreatedAt:           t1.UTC(),
	}
	insertUpstreamVersionRow(t, ctx, s, c1)

	// Activate first candidate (no previous active).
	active1, prev1, err := s.ActivateUpstreamVersion(ctx, c1.ID, t2)
	if err != nil {
		t.Fatalf("ActivateUpstreamVersion(c1): %v", err)
	}
	if prev1 != nil {
		t.Fatalf("prev1 = %+v, want nil", prev1)
	}
	if active1.State != "active" || active1.ActivatedAt != t2.UTC() || active1.ActivatedAt.Location() != time.UTC || !active1.RetiredAt.IsZero() {
		t.Fatalf("active1 = %+v, want active with ActivatedAt=%v UTC and zero RetiredAt", active1, t2.UTC())
	}
	got1, err := s.GetUpstreamVersion(ctx, c1.ID)
	if err != nil {
		t.Fatalf("GetUpstreamVersion(c1): %v", err)
	}
	if got1 != active1 {
		t.Fatalf("GetUpstreamVersion(c1) = %+v, want %+v", got1, active1)
	}
	mode, activeID, failCount, nextRun, lastErr, updatedAt := readUpstreamSlotRow(t, ctx, s, 1)
	if mode != "upstream" || activeID != c1.ID || failCount != 0 || nextRun != 0 || lastErr != "" || updatedAt != t2.UTC().UnixNano() {
		t.Fatalf("slot 1 row = (%q, %q, %d, %d, %q, %d), want (upstream, %s, 0, 0, '', %d)",
			mode, activeID, failCount, nextRun, lastErr, updatedAt, c1.ID, t2.UTC().UnixNano())
	}

	// Simulate prior failures on slot 1 before activating a second candidate.
	nextRunTarget := t3.Add(5 * time.Minute).UTC().UnixNano()
	if _, err := s.db.ExecContext(ctx,
		`UPDATE upstream_slots
		 SET failure_count = 3, last_error_code = 'upstream_timeout', next_run_at = ?
		 WHERE slot = 1`,
		nextRunTarget); err != nil {
		t.Fatalf("seed slot 1 failure counters: %v", err)
	}

	// Activate second candidate with a previous active version.
	c2 := UpstreamVersion{
		ID:                  strings.Repeat("2", 32),
		Slot:                1,
		Seq:                 2,
		Origin:              "upstream",
		State:               "candidate",
		PayloadRef:          "slot1/v2.enc",
		PayloadSHA256:       strings.Repeat("c", 64),
		OutboundFingerprint: strings.Repeat("d", 64),
		CreatedAt:           t2.UTC(),
	}
	insertUpstreamVersionRow(t, ctx, s, c2)

	active2, prev2, err := s.ActivateUpstreamVersion(ctx, c2.ID, t3)
	if err != nil {
		t.Fatalf("ActivateUpstreamVersion(c2): %v", err)
	}
	if prev2 == nil {
		t.Fatal("prev2 = nil, want previous active version")
	}
	wantPrev2 := active1
	wantPrev2.State = "superseded"
	wantPrev2.RetiredAt = t3.UTC()
	if *prev2 != wantPrev2 {
		t.Fatalf("prev2 = %+v, want %+v", *prev2, wantPrev2)
	}
	if active2.ID != c2.ID || active2.State != "active" || active2.ActivatedAt != t3.UTC() || !active2.RetiredAt.IsZero() {
		t.Fatalf("active2 = %+v, want c2 active at %v", active2, t3.UTC())
	}

	gotPrev, err := s.GetUpstreamVersion(ctx, c1.ID)
	if err != nil {
		t.Fatalf("GetUpstreamVersion(c1 after supersede): %v", err)
	}
	if gotPrev != wantPrev2 {
		t.Fatalf("persisted c1 = %+v, want %+v", gotPrev, wantPrev2)
	}
	gotActive, err := s.ActiveUpstreamVersion(ctx, 1)
	if err != nil {
		t.Fatalf("ActiveUpstreamVersion(1): %v", err)
	}
	if gotActive != active2 {
		t.Fatalf("ActiveUpstreamVersion(1) = %+v, want %+v", gotActive, active2)
	}

	// Exactly one active row remains in slot 1.
	listed, err := s.ListUpstreamVersions(ctx, 1, 10)
	if err != nil {
		t.Fatalf("ListUpstreamVersions(1): %v", err)
	}
	activeCount := 0
	for _, v := range listed {
		if v.State == "active" {
			activeCount++
		}
	}
	if activeCount != 1 {
		t.Fatalf("active row count in slot 1 = %d, want 1", activeCount)
	}

	// Failure counters reset on activation while next_run_at is preserved.
	mode, activeID, failCount, nextRun, lastErr, updatedAt = readUpstreamSlotRow(t, ctx, s, 1)
	if mode != "upstream" || activeID != c2.ID || failCount != 0 || nextRun != nextRunTarget || lastErr != "" || updatedAt != t3.UTC().UnixNano() {
		t.Fatalf("slot 1 row after c2 = (%q, %q, %d, %d, %q, %d), want (upstream, %s, 0, %d, '', %d)",
			mode, activeID, failCount, nextRun, lastErr, updatedAt, c2.ID, nextRunTarget, t3.UTC().UnixNano())
	}

	// Activating a blackhole candidate sets upstream_slots.mode = 'blackhole'.
	bh := UpstreamVersion{
		ID:                  strings.Repeat("3", 32),
		Slot:                1,
		Seq:                 3,
		Origin:              "blackhole",
		State:               "candidate",
		PayloadRef:          "slot1/v3-bh.enc",
		PayloadSHA256:       strings.Repeat("e", 64),
		OutboundFingerprint: strings.Repeat("f", 64),
		CreatedAt:           t3.UTC(),
	}
	insertUpstreamVersionRow(t, ctx, s, bh)

	active3, prev3, err := s.ActivateUpstreamVersion(ctx, bh.ID, t4)
	if err != nil {
		t.Fatalf("ActivateUpstreamVersion(bh): %v", err)
	}
	if active3.Origin != "blackhole" || active3.State != "active" || prev3 == nil || prev3.ID != c2.ID {
		t.Fatalf("ActivateUpstreamVersion(bh) = (%+v, %+v), want blackhole active and prev c2", active3, prev3)
	}
	mode, activeID, failCount, _, lastErr, updatedAt = readUpstreamSlotRow(t, ctx, s, 1)
	if mode != "blackhole" || activeID != bh.ID || failCount != 0 || lastErr != "" || updatedAt != t4.UTC().UnixNano() {
		t.Fatalf("slot 1 row after bh = (%q, %q, %d, %q, %d), want (blackhole, %s, 0, '', %d)",
			mode, activeID, failCount, lastErr, updatedAt, bh.ID, t4.UTC().UnixNano())
	}

	// Activating failed, superseded, or already-active versions returns ErrInvalidTransition and changes nothing.
	failed := UpstreamVersion{
		ID:                  strings.Repeat("4", 32),
		Slot:                1,
		Seq:                 4,
		Origin:              "upstream",
		State:               "failed",
		PayloadRef:          "slot1/v4.enc",
		PayloadSHA256:       sha,
		OutboundFingerprint: fp,
		FailureCode:         "bad_sig",
		CreatedAt:           t4.UTC(),
	}
	insertUpstreamVersionRow(t, ctx, s, failed)

	for _, id := range []string{failed.ID, c1.ID, bh.ID} {
		_, _, err := s.ActivateUpstreamVersion(ctx, id, t5)
		if !errors.Is(err, ErrInvalidTransition) {
			t.Fatalf("ActivateUpstreamVersion(%s) err = %v, want ErrInvalidTransition", id, err)
		}
	}
	stillFailed, err := s.GetUpstreamVersion(ctx, failed.ID)
	if err != nil || stillFailed != failed {
		t.Fatalf("failed version changed after rejected activation: got (%+v, %v), want %+v", stillFailed, err, failed)
	}
	stillSuperseded, err := s.GetUpstreamVersion(ctx, c1.ID)
	if err != nil || stillSuperseded != wantPrev2 {
		t.Fatalf("superseded version changed after rejected activation: got (%+v, %v), want %+v", stillSuperseded, err, wantPrev2)
	}
	stillActive, err := s.ActiveUpstreamVersion(ctx, 1)
	if err != nil || stillActive != active3 {
		t.Fatalf("active version changed after rejected activation: got (%+v, %v), want %+v", stillActive, err, active3)
	}
	mode, activeID, _, _, _, updatedAt = readUpstreamSlotRow(t, ctx, s, 1)
	if mode != "blackhole" || activeID != bh.ID || updatedAt != t4.UTC().UnixNano() {
		t.Fatalf("slot 1 row changed after rejected activation: (%q, %q, %d)", mode, activeID, updatedAt)
	}

	// Unknown valid ID returns ErrNotFound.
	_, _, err = s.ActivateUpstreamVersion(ctx, strings.Repeat("9", 32), t5)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("ActivateUpstreamVersion(missing) err = %v, want ErrNotFound", err)
	}

	// Invalid ID or invalid time returns ErrInvalidArgument without leaking rejected ID.
	for _, badID := range []string{"bad-id", strings.Repeat("A", 32)} {
		_, _, err = s.ActivateUpstreamVersion(ctx, badID, t5)
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("ActivateUpstreamVersion(%q) err = %v, want ErrInvalidArgument", badID, err)
		}
		if strings.Contains(err.Error(), badID) {
			t.Fatalf("ActivateUpstreamVersion(%q) error leaked rejected value: %v", badID, err)
		}
	}
	for _, badNow := range []time.Time{{}, time.Unix(0, 0).UTC()} {
		_, _, err = s.ActivateUpstreamVersion(ctx, c1.ID, badNow)
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("ActivateUpstreamVersion(now=%v) err = %v, want ErrInvalidArgument", badNow, err)
		}
	}
}
