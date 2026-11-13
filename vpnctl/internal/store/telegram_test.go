package store

import (
	"context"
	"errors"
	"math"
	"sync"
	"testing"
	"time"
)

func TestBotOffsetStartsAtZero(t *testing.T) {
	s, _ := openTemp(t)
	offset, err := s.BotOffset(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if offset != 0 {
		t.Errorf("offset = %d, want 0", offset)
	}
}

func TestClaimBotUpdateAdvancesOffsetMonotonically(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	claim := func(id int64, want bool) {
		t.Helper()
		got, err := s.ClaimBotUpdate(ctx, id)
		if err != nil {
			t.Fatalf("ClaimBotUpdate(%d): %v", id, err)
		}
		if got != want {
			t.Fatalf("ClaimBotUpdate(%d) = %v, want %v", id, got, want)
		}
	}
	claim(10, true)
	if offset, _ := s.BotOffset(ctx); offset != 11 {
		t.Fatalf("offset after 10 = %d, want 11", offset)
	}
	// An older update must not move the offset backwards.
	claim(9, true)
	if offset, _ := s.BotOffset(ctx); offset != 11 {
		t.Fatalf("offset after 9 = %d, want 11", offset)
	}
	claim(10, false)
	claim(9, false)
	if offset, _ := s.BotOffset(ctx); offset != 11 {
		t.Fatalf("offset after duplicates = %d, want 11", offset)
	}
}

func TestClaimBotUpdateRejectsInvalidIDs(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	for _, id := range []int64{0, -1, math.MaxInt64} {
		if _, err := s.ClaimBotUpdate(ctx, id); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("ClaimBotUpdate(%d) err = %v, want ErrInvalidArgument", id, err)
		}
	}
}

func TestClaimBotUpdateIsAtomicAcrossConcurrentCallers(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)

	const callers = 16
	var wg sync.WaitGroup
	results := make(chan bool, callers)
	errs := make(chan error, callers)
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			claimed, err := s.ClaimBotUpdate(ctx, 42)
			if err != nil {
				errs <- err
				return
			}
			results <- claimed
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Fatalf("claim error: %v", err)
	}
	wins := 0
	for claimed := range results {
		if claimed {
			wins++
		}
	}
	if wins != 1 {
		t.Errorf("%d concurrent claims succeeded, want 1", wins)
	}
}

func TestClaimBotUpdateAcrossTwoStores(t *testing.T) {
	ctx := context.Background()
	path := tempPath(t)
	a, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	type result struct {
		claimed bool
		err     error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for _, s := range []*Store{a, b} {
		go func(s *Store) {
			<-start
			claimed, err := s.ClaimBotUpdate(ctx, 77)
			results <- result{claimed, err}
		}(s)
	}
	close(start)

	wins := 0
	for range 2 {
		res := <-results
		if res.err != nil {
			t.Fatalf("claim error: %v", res.err)
		}
		if res.claimed {
			wins++
		}
	}
	if wins != 1 {
		t.Errorf("%d of two stores claimed the update, want 1", wins)
	}
	for name, s := range map[string]*Store{"first": a, "second": b} {
		if offset, err := s.BotOffset(ctx); err != nil || offset != 78 {
			t.Errorf("%s store offset = %d, %v; want 78", name, offset, err)
		}
	}
}

func TestClaimBotUpdatePrunesOldIDs(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	last := int64(maxClaimedUpdates + 25)
	for id := int64(1); id <= last; id++ {
		if ok, err := s.ClaimBotUpdate(ctx, id); err != nil || !ok {
			t.Fatalf("ClaimBotUpdate(%d) = %v, %v", id, ok, err)
		}
	}
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM telegram_updates`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count > maxClaimedUpdates {
		t.Errorf("retained %d processed IDs, want at most %d", count, maxClaimedUpdates)
	}
	// The newest ID stays deduplicated; the oldest has left the window and is
	// claimable again, which is harmless because the offset is far past it.
	if ok, err := s.ClaimBotUpdate(ctx, last); err != nil || ok {
		t.Errorf("newest duplicate = %v, %v; want false, nil", ok, err)
	}
	if ok, err := s.ClaimBotUpdate(ctx, 1); err != nil || !ok {
		t.Errorf("pruned ID = %v, %v; want true, nil", ok, err)
	}
	if offset, _ := s.BotOffset(ctx); offset != last+1 {
		t.Errorf("offset = %d, want %d", offset, last+1)
	}
}

func TestBotStateSurvivesReopen(t *testing.T) {
	ctx := context.Background()
	s, path := openTemp(t)
	if ok, err := s.ClaimBotUpdate(ctx, 100); err != nil || !ok {
		t.Fatalf("claim = %v, %v", ok, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if offset, err := reopened.BotOffset(ctx); err != nil || offset != 101 {
		t.Errorf("offset after reopen = %d, %v; want 101", offset, err)
	}
	if ok, err := reopened.ClaimBotUpdate(ctx, 100); err != nil || ok {
		t.Errorf("duplicate after reopen = %v, %v; want false, nil", ok, err)
	}
}

func TestClaimBotUpdateHonorsCancellation(t *testing.T) {
	s, _ := openTemp(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.ClaimBotUpdate(ctx, 1); err == nil {
		t.Fatal("ClaimBotUpdate succeeded with a canceled context")
	}
}

func TestVersionOneDatabaseUpgradesAndKeepsData(t *testing.T) {
	ctx := context.Background()
	path := tempPath(t)
	v1, err := open(ctx, path, migrations[:1])
	if err != nil {
		t.Fatal(err)
	}
	probe, err := v1.AppendProbe(ctx, ProbeRecord{
		Target:     "exit-01",
		Stage:      "tcp",
		Family:     FamilyIPv4,
		Outcome:    OutcomeSuccess,
		ObservedAt: time.Unix(1700000000, 0).UTC(),
		Duration:   time.Millisecond,
		Bytes:      1,
	})
	if err != nil {
		t.Fatal(err)
	}
	op, err := v1.CreateOperation(ctx, "rotate_ip", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := pragmaInt(t, v1.db, "user_version"); got != 1 {
		t.Fatalf("pre-upgrade user_version = %d, want 1", got)
	}
	if err := v1.Close(); err != nil {
		t.Fatal(err)
	}

	upgraded, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("Open upgraded database: %v", err)
	}
	defer upgraded.Close()
	if got := pragmaInt(t, upgraded.db, "user_version"); got != int64(len(migrations)) {
		t.Errorf("user_version = %d, want %d", got, len(migrations))
	}
	for _, table := range []string{"probes", "operations", "telegram_offsets", "telegram_updates"} {
		if !tableExists(t, upgraded.db, table) {
			t.Errorf("table %q missing after upgrade", table)
		}
	}
	probes, err := upgraded.LatestProbes(ctx, "exit-01", 1)
	if err != nil || len(probes) != 1 || probes[0].ID != probe.ID {
		t.Errorf("probes after upgrade = %+v, %v", probes, err)
	}
	if _, err := upgraded.GetOperation(ctx, op.ID); err != nil {
		t.Errorf("operation after upgrade: %v", err)
	}
	if ok, err := upgraded.ClaimBotUpdate(ctx, 7); err != nil || !ok {
		t.Errorf("claim after upgrade = %v, %v", ok, err)
	}
}
