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
