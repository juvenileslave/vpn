package store

import (
	"context"
	"errors"
	"sync"
	"testing"
)

func TestOperationLifecycle(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)

	op, err := s.CreateOperation(ctx, "rotate_ip", "")
	if err != nil {
		t.Fatal(err)
	}
	if op.State != StatePending || op.Revision != 1 || len(op.ID) != 32 {
		t.Fatalf("created = %+v", op)
	}
	got, err := s.GetOperation(ctx, op.ID)
	if err != nil || got != op {
		t.Fatalf("GetOperation = %+v, %v; want %+v", got, err, op)
	}

	steps := []struct {
		state State
		step  string
	}{
		{StateRunning, "create_ip"},
		{StateRunning, "poweroff"},
		{StateRunning, "assign_ip"},
		{StateSucceeded, "assign_ip"},
	}
	for i, st := range steps {
		next, err := s.UpdateOperation(ctx, op.ID, op.Revision, st.state, st.step)
		if err != nil {
			t.Fatalf("update %d: %v", i, err)
		}
		if next.Revision != op.Revision+1 || next.State != st.state || next.Step != st.step {
			t.Fatalf("update %d = %+v", i, next)
		}
		if next.CreatedAt != op.CreatedAt || next.UpdatedAt.Before(op.UpdatedAt) {
			t.Errorf("update %d timestamps: %+v", i, next)
		}
		stored, err := s.GetOperation(ctx, op.ID)
		if err != nil || stored != next {
			t.Fatalf("stored after update %d = %+v, %v; want %+v", i, stored, err, next)
		}
		op = next
	}
	t.Logf("lifecycle: final state=%s revision=%d", op.State, op.Revision)
}

func TestOperationNotFound(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	const missing = "0123456789abcdef0123456789abcdef"
	if _, err := s.GetOperation(ctx, missing); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetOperation err = %v, want ErrNotFound", err)
	}
	if _, err := s.UpdateOperation(ctx, missing, 1, StateRunning, "a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateOperation err = %v, want ErrNotFound", err)
	}
	for _, id := range []string{"", "x", "' OR 1=1 --", missing + "0"} {
		if _, err := s.GetOperation(ctx, id); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("GetOperation(%q) err = %v, want ErrInvalidArgument", id, err)
		}
	}
}

func TestStaleRevisionIsRejectedWithoutChange(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	op, err := s.CreateOperation(ctx, "rotate_ip", "")
	if err != nil {
		t.Fatal(err)
	}
	cur, err := s.UpdateOperation(ctx, op.ID, 1, StateRunning, "create_ip")
	if err != nil {
		t.Fatal(err)
	}
	for _, rev := range []int64{1, 3, 100} {
		if _, err := s.UpdateOperation(ctx, op.ID, rev, StateFailed, "create_ip"); !errors.Is(err, ErrConflict) {
			t.Errorf("revision %d: err = %v, want ErrConflict", rev, err)
		}
	}
	stored, err := s.GetOperation(ctx, op.ID)
	if err != nil || stored != cur {
		t.Errorf("after stale writes = %+v, %v; want %+v", stored, err, cur)
	}
	t.Logf("stale revisions rejected; stored revision=%d state=%s", stored.Revision, stored.State)
}

func TestTerminalStatesAreImmutable(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	for _, terminal := range []State{StateSucceeded, StateFailed} {
		t.Run(string(terminal), func(t *testing.T) {
			op, err := s.CreateOperation(ctx, "rotate_ip", "")
			if err != nil {
				t.Fatal(err)
			}
			if op, err = s.UpdateOperation(ctx, op.ID, 1, StateRunning, "a"); err != nil {
				t.Fatal(err)
			}
			if op, err = s.UpdateOperation(ctx, op.ID, 2, terminal, "a"); err != nil {
				t.Fatal(err)
			}
			for _, next := range []State{StatePending, StateRunning, StateSucceeded, StateFailed} {
				if _, err := s.UpdateOperation(ctx, op.ID, op.Revision, next, "b"); !errors.Is(err, ErrTerminal) {
					t.Errorf("%s -> %s: err = %v, want ErrTerminal", terminal, next, err)
				}
			}
			stored, err := s.GetOperation(ctx, op.ID)
			if err != nil || stored != op {
				t.Errorf("stored = %+v, %v; want %+v", stored, err, op)
			}
		})
	}
}

func TestInvalidTransitions(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	pending, err := s.CreateOperation(ctx, "rotate_ip", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, next := range []State{StatePending, StateSucceeded, StateFailed} {
		if _, err := s.UpdateOperation(ctx, pending.ID, 1, next, "a"); !errors.Is(err, ErrInvalidTransition) {
			t.Errorf("pending -> %s: err = %v, want ErrInvalidTransition", next, err)
		}
	}
	running, err := s.UpdateOperation(ctx, pending.ID, 1, StateRunning, "a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateOperation(ctx, running.ID, 2, StatePending, "a"); !errors.Is(err, ErrInvalidTransition) {
		t.Errorf("running -> pending: err = %v", err)
	}
	if _, err := s.UpdateOperation(ctx, running.ID, 2, StateRunning, "a"); !errors.Is(err, ErrInvalidTransition) {
		t.Errorf("running -> running without step change: err = %v", err)
	}
	if _, err := s.UpdateOperation(ctx, running.ID, 2, "paused", "b"); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("unknown state: err = %v", err)
	}
	if _, err := s.UpdateOperation(ctx, running.ID, 0, StateRunning, "b"); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("zero revision: err = %v", err)
	}
	if _, err := s.UpdateOperation(ctx, running.ID, 2, StateRunning, "Bad Step"); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("invalid step: err = %v", err)
	}
	if _, err := s.CreateOperation(ctx, "", ""); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("empty kind: err = %v", err)
	}
	stored, err := s.GetOperation(ctx, running.ID)
	if err != nil || stored != running {
		t.Errorf("stored = %+v, %v; want %+v", stored, err, running)
	}
}

// Competing writers use separate Store handles on one file, as two processes
// would, plus goroutines sharing each handle.
func TestCompetingWritersOnlyOneSucceeds(t *testing.T) {
	ctx := context.Background()
	first, path := openTemp(t)
	second, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	op, err := first.CreateOperation(ctx, "rotate_ip", "")
	if err != nil {
		t.Fatal(err)
	}
	stores := []*Store{first, second}
	const writers = 8
	start := make(chan struct{})
	errs := make([]error, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, errs[i] = stores[i%2].UpdateOperation(ctx, op.ID, 1, StateRunning, "create_ip")
		}(i)
	}
	close(start)
	wg.Wait()

	succeeded := 0
	for i, err := range errs {
		switch {
		case err == nil:
			succeeded++
		case !errors.Is(err, ErrConflict):
			t.Errorf("writer %d: err = %v, want nil or ErrConflict", i, err)
		}
	}
	if succeeded != 1 {
		t.Fatalf("%d writers succeeded, want exactly 1", succeeded)
	}
	for _, s := range stores {
		got, err := s.GetOperation(ctx, op.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Revision != 2 || got.State != StateRunning {
			t.Errorf("final = %+v, want running at revision 2", got)
		}
	}
	t.Logf("competing writers: %d succeeded, %d got ErrConflict", succeeded, writers-succeeded)
}
