package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

var baseTime = time.Date(2026, 1, 2, 3, 4, 5, 6, time.UTC)

func probeAt(target string, second int) ProbeRecord {
	return ProbeRecord{
		Target:     target,
		Stage:      "tls",
		Family:     FamilyIPv4,
		Outcome:    OutcomeSuccess,
		ObservedAt: baseTime.Add(time.Duration(second) * time.Second),
		Duration:   150 * time.Millisecond,
		Bytes:      512,
	}
}

func TestLatestProbesOrderingAndLimit(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)

	// Inserted out of order; seconds 5 appears twice to exercise the ID tie-break.
	var ids = map[int][]int64{}
	for _, sec := range []int{3, 5, 1, 5, 4} {
		r, err := s.AppendProbe(ctx, probeAt("exit-01", sec))
		if err != nil {
			t.Fatal(err)
		}
		ids[sec] = append(ids[sec], r.ID)
	}
	if _, err := s.AppendProbe(ctx, probeAt("relay-01", 10)); err != nil {
		t.Fatal(err)
	}
	failure := probeAt("exit-01", 2)
	failure.Outcome, failure.ErrorCode, failure.Bytes = OutcomeTimeout, "tls_handshake_timeout", 0
	if _, err := s.AppendProbe(ctx, failure); err != nil {
		t.Fatal(err)
	}

	all, err := s.LatestProbes(ctx, "exit-01", MaxLimit)
	if err != nil {
		t.Fatal(err)
	}
	wantIDs := []int64{ids[5][1], ids[5][0], ids[4][0], ids[3][0]}
	if len(all) != 6 {
		t.Fatalf("got %d probes, want 6", len(all))
	}
	for i, id := range wantIDs {
		if all[i].ID != id {
			t.Errorf("probe[%d].ID = %d, want %d", i, all[i].ID, id)
		}
	}
	if all[4].Outcome != OutcomeTimeout || all[4].ErrorCode != "tls_handshake_timeout" {
		t.Errorf("probe[4] = %+v, want the timeout record", all[4])
	}
	for i, r := range all {
		if r.Target != "exit-01" {
			t.Errorf("probe[%d] has target %q", i, r.Target)
		}
		if i > 0 && r.ObservedAt.After(all[i-1].ObservedAt) {
			t.Errorf("probe[%d] is newer than probe[%d]", i, i-1)
		}
	}

	top, err := s.LatestProbes(ctx, "exit-01", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(top) != 2 || top[0].ID != wantIDs[0] || top[1].ID != wantIDs[1] {
		t.Errorf("limit 2 returned %+v", top)
	}

	none, err := s.LatestProbes(ctx, "unknown", 5)
	if err != nil || len(none) != 0 {
		t.Errorf("unknown target = %v, %v; want empty", none, err)
	}

	for _, limit := range []int{0, -1, MaxLimit + 1} {
		if _, err := s.LatestProbes(ctx, "exit-01", limit); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("limit %d: err = %v, want ErrInvalidArgument", limit, err)
		}
	}
}

func TestAppendProbeRoundTripsFields(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	in := ProbeRecord{
		ID:         42, // ignored
		Target:     "exit-01.hel1",
		Stage:      "http",
		Family:     FamilyIPv6,
		Outcome:    OutcomeFailure,
		ObservedAt: time.Date(2026, 5, 6, 7, 8, 9, 123456789, time.FixedZone("x", 3*3600)),
		Duration:   2*time.Second + 7,
		Bytes:      0,
		ErrorCode:  "http_status_5xx",
	}
	got, err := s.AppendProbe(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID == 42 || got.ID < 1 {
		t.Errorf("ID = %d, want a store-assigned ID", got.ID)
	}
	if !got.ObservedAt.Equal(in.ObservedAt) || got.ObservedAt.Location() != time.UTC {
		t.Errorf("ObservedAt = %v, want %v in UTC", got.ObservedAt, in.ObservedAt)
	}
	list, err := s.LatestProbes(ctx, in.Target, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0] != got {
		t.Errorf("stored = %+v, want %+v", list, got)
	}
}

func TestAppendProbeRejectsInvalidRecords(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	cases := map[string]func(r *ProbeRecord){
		"empty target":      func(r *ProbeRecord) { r.Target = "" },
		"url target":        func(r *ProbeRecord) { r.Target = "https://user:pass@example.com" },
		"long target":       func(r *ProbeRecord) { r.Target = strings.Repeat("a", 64) },
		"empty stage":       func(r *ProbeRecord) { r.Stage = "" },
		"stage with spaces": func(r *ProbeRecord) { r.Stage = "tls handshake" },
		"unknown family":    func(r *ProbeRecord) { r.Family = "ipv5" },
		"unknown outcome":   func(r *ProbeRecord) { r.Outcome = "maybe" },
		"zero time":         func(r *ProbeRecord) { r.ObservedAt = time.Time{} },
		"negative duration": func(r *ProbeRecord) { r.Duration = -1 },
		"negative bytes":    func(r *ProbeRecord) { r.Bytes = -1 },
		"success with code": func(r *ProbeRecord) { r.ErrorCode = "refused" },
		"failure without code": func(r *ProbeRecord) {
			r.Outcome = OutcomeFailure
		},
		"free-form error text": func(r *ProbeRecord) {
			r.Outcome, r.ErrorCode = OutcomeFailure, "dial tcp 192.0.2.1:443: connection refused"
		},
		"raw body as error code": func(r *ProbeRecord) {
			r.Outcome, r.ErrorCode = OutcomeFailure, "<html>"+strings.Repeat("x", 100)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := probeAt("exit-01", 1)
			mutate(&r)
			_, err := s.AppendProbe(ctx, r)
			if !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("err = %v, want ErrInvalidArgument", err)
			}
			if r.ErrorCode != "" && strings.Contains(err.Error(), r.ErrorCode) {
				t.Errorf("error echoes rejected input: %v", err)
			}
		})
	}
	list, err := s.LatestProbes(ctx, "exit-01", MaxLimit)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Errorf("rejected records stored: %d", len(list))
	}
}
