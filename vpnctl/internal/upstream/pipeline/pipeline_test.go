package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/juvenileslave/vpn/vpnctl/internal/store"
	"github.com/juvenileslave/vpn/vpnctl/internal/upstream/candidate"
	"github.com/juvenileslave/vpn/vpnctl/internal/upstream/payload"
	"github.com/juvenileslave/vpn/vpnctl/internal/upstream/selector"
	"github.com/juvenileslave/vpn/vpnctl/internal/upstream/source"
)

const testDecl = `schema: 1
sources:
  - id: sub-a
    kind: subscription
    slot: 1
    interval: 5m
    subscription_url: https://example.com/sub/a
`

type fetchReply struct {
	cands   []candidate.Candidate
	rejects []candidate.Reject
	err     error
}

type fakeFetcher struct {
	mu       sync.Mutex
	replies  map[string]fetchReply
	calls    int
	declared []string
}

func (f *fakeFetcher) Fetch(_ context.Context, src source.Source, _ string) ([]candidate.Candidate, []candidate.Reject, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.declared = append(f.declared, src.ID())
	reply, ok := f.replies[src.ID()]
	if !ok {
		return nil, nil, errors.New("no reply")
	}
	return reply.cands, reply.rejects, reply.err
}

type fakeProber struct {
	mu      sync.Mutex
	probes  map[string][]selector.Probe
	errs    map[string]error
	started chan string
	release chan struct{}
}

func (p *fakeProber) Probe(ctx context.Context, cand candidate.Candidate) ([]selector.Probe, error) {
	if p.started != nil {
		select {
		case p.started <- cand.ID:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if p.release != nil {
			select {
			case <-p.release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.errs[cand.ID]; err != nil {
		return nil, err
	}
	return p.probes[cand.ID], nil
}

type fakeValidator struct {
	mu      sync.Mutex
	calls   int
	last    json.RawMessage
	wantErr error
}

func (v *fakeValidator) Validate(_ context.Context, _ int, outbound json.RawMessage) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.calls++
	v.last = append(json.RawMessage(nil), outbound...)
	return v.wantErr
}

type publishCall struct {
	slot      int
	versionID string
	outbound  []byte
}

type fakePublisher struct {
	mu        sync.Mutex
	published []byte
	readBack  []byte
	publishes []publishCall
	restores  []publishCall
	verifies  int

	publishErr  error
	readBackErr error
	verifyErr   error
	restoreErr  error
}

func (p *fakePublisher) Publish(_ context.Context, slot int, versionID string, outbound json.RawMessage) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.publishErr != nil {
		return p.publishErr
	}
	p.published = append([]byte(nil), outbound...)
	p.publishes = append(p.publishes, publishCall{slot: slot, versionID: versionID, outbound: append([]byte(nil), outbound...)})
	return nil
}

func (p *fakePublisher) ReadBack(_ context.Context, _ int) (json.RawMessage, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.readBackErr != nil {
		return nil, p.readBackErr
	}
	if p.readBack != nil {
		return append(json.RawMessage(nil), p.readBack...), nil
	}
	return append(json.RawMessage(nil), p.published...), nil
}

func (p *fakePublisher) Verify(_ context.Context, _ int) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.verifies++
	return p.verifyErr
}

func (p *fakePublisher) Restore(_ context.Context, slot int, versionID string, outbound json.RawMessage) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.restoreErr != nil {
		return p.restoreErr
	}
	p.restores = append(p.restores, publishCall{slot: slot, versionID: versionID, outbound: append([]byte(nil), outbound...)})
	return nil
}

type fixture struct {
	store     *store.Store
	payloads  *payload.Store
	decl      *source.Declaration
	fetcher   *fakeFetcher
	prober    *fakeProber
	validator *fakeValidator
	publisher *fakePublisher
	now       time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity: %v", err)
	}
	keyPath := filepath.Join(t.TempDir(), "identity.txt")
	if err := os.WriteFile(keyPath, []byte(identity.String()+"\n"), 0o600); err != nil {
		t.Fatalf("write identity: %v", err)
	}
	dir := filepath.Join(t.TempDir(), "payloads")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir payloads: %v", err)
	}
	ps, err := payload.Open(payload.Options{Dir: dir, Recipient: identity.Recipient().String(), IdentityFile: keyPath})
	if err != nil {
		t.Fatalf("payload.Open: %v", err)
	}

	declPath := filepath.Join(t.TempDir(), "sources.yaml")
	if err := os.WriteFile(declPath, []byte(testDecl), 0o600); err != nil {
		t.Fatalf("write declaration: %v", err)
	}
	decl, err := source.Load(declPath)
	if err != nil {
		t.Fatalf("source.Load: %v", err)
	}

	return &fixture{
		store:    st,
		payloads: ps,
		decl:     decl,
		fetcher: &fakeFetcher{replies: map[string]fetchReply{
			"sub-a": {},
		}},
		prober:    &fakeProber{probes: map[string][]selector.Probe{}, errs: map[string]error{}},
		validator: &fakeValidator{},
		publisher: &fakePublisher{},
		now:       time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC),
	}
}

func (f *fixture) pipeline(t *testing.T) *Pipeline {
	t.Helper()
	p, err := New(Options{
		Store:       f.store,
		Payloads:    f.payloads,
		Fetcher:     f.fetcher,
		Prober:      f.prober,
		Validator:   f.validator,
		Publisher:   f.publisher,
		Now:         func() time.Time { return f.now },
		Concurrency: 2,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func cand(id string, outbound string) candidate.Candidate {
	return candidate.Candidate{
		ID:       id,
		Scheme:   candidate.SchemeVLESS,
		Label:    "label",
		Outbound: json.RawMessage(outbound),
	}
}

func success(latency time.Duration) []selector.Probe {
	return []selector.Probe{{Outcome: "success", Latency: latency}, {Outcome: "success", Latency: latency}}
}

func failure() []selector.Probe {
	return []selector.Probe{{Outcome: "failure"}, {Outcome: "timeout"}}
}

func sha(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestNewRejectsIncompleteOptions(t *testing.T) {
	if _, err := New(Options{}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("New(Options{}) error = %v, want ErrInvalidOptions", err)
	}
	if _, err := New(Options{Store: &store.Store{}, Payloads: &payload.Store{}, Fetcher: &fakeFetcher{}, Prober: &fakeProber{}, Validator: &fakeValidator{}, Publisher: &fakePublisher{}, Concurrency: -1}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("negative concurrency error = %v, want ErrInvalidOptions", err)
	}
}

func TestRefreshRejectsUndeclaredSlot(t *testing.T) {
	f := newFixture(t)
	p := f.pipeline(t)

	if _, err := p.Refresh(context.Background(), nil, 1); !errors.Is(err, ErrUnknownSlot) {
		t.Fatalf("nil declaration error = %v, want ErrUnknownSlot", err)
	}
	if _, err := p.Refresh(context.Background(), f.decl, 2); !errors.Is(err, ErrUnknownSlot) {
		t.Fatalf("undeclared slot error = %v, want ErrUnknownSlot", err)
	}
	for _, slot := range []int{0, 64} {
		if _, err := p.Refresh(context.Background(), f.decl, slot); !errors.Is(err, ErrUnknownSlot) {
			t.Fatalf("slot %d error = %v, want ErrUnknownSlot", slot, err)
		}
	}
}

func TestRefreshActivatesFastestHealthyCandidate(t *testing.T) {
	f := newFixture(t)
	fast := cand(strings.Repeat("a", 64), `{"protocol":"vless","tag":"upstream-slot-1","settings":{"fast":true}}`)
	slow := cand(strings.Repeat("b", 64), `{"protocol":"vless","tag":"upstream-slot-1","settings":{"slow":true}}`)
	f.fetcher.replies["sub-a"] = fetchReply{
		cands:   []candidate.Candidate{slow, fast},
		rejects: []candidate.Reject{{Entry: 3, Line: 3, Scheme: "vmess", Reason: "unsupported scheme"}},
	}
	f.prober.probes[fast.ID] = success(20 * time.Millisecond)
	f.prober.probes[slow.ID] = success(80 * time.Millisecond)
	p := f.pipeline(t)

	res, err := p.Refresh(context.Background(), f.decl, 1)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if !res.Active || res.VersionID == "" || res.Healthy != 2 || res.Candidates != 2 || res.Rejects != 1 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if f.publisher.verifies != 1 {
		t.Fatalf("Verify calls = %d, want 1", f.publisher.verifies)
	}
	if len(f.publisher.publishes) != 1 || f.publisher.publishes[0].versionID != res.VersionID {
		t.Fatalf("publishes = %+v", f.publisher.publishes)
	}
	wantOutbound := `{"protocol":"vless","tag":"upstream-slot-1","settings":{"fast":true}}`
	if string(f.publisher.publishes[0].outbound) != wantOutbound {
		t.Fatalf("published outbound = %s, want %s", f.publisher.publishes[0].outbound, wantOutbound)
	}
	if f.validator.calls != 1 || string(f.validator.last) != wantOutbound {
		t.Fatalf("validator calls = %d last = %s", f.validator.calls, f.validator.last)
	}

	active, err := f.store.ActiveUpstreamVersion(context.Background(), 1)
	if err != nil {
		t.Fatalf("ActiveUpstreamVersion: %v", err)
	}
	if active.ID != res.VersionID || active.Origin != "upstream" || active.State != "active" {
		t.Fatalf("active version = %+v", active)
	}
	plain, err := f.payloads.Get(context.Background(), payload.Ref{ID: active.PayloadRef, SHA256: active.PayloadSHA256})
	if err != nil {
		t.Fatalf("payload Get: %v", err)
	}
	if string(plain) != wantOutbound {
		t.Fatalf("stored payload = %s", plain)
	}
	if active.OutboundFingerprint != sha([]byte(wantOutbound)) {
		t.Fatalf("fingerprint = %s", active.OutboundFingerprint)
	}
	slot, err := f.store.UpstreamSlot(context.Background(), 1)
	if err != nil {
		t.Fatalf("UpstreamSlot: %v", err)
	}
	if slot.Mode != "upstream" || slot.ActiveVersionID != res.VersionID {
		t.Fatalf("slot = %+v", slot)
	}
}

func TestRefreshActivatesBlackholeWithoutHealthyUpstream(t *testing.T) {
	f := newFixture(t)
	bad := cand(strings.Repeat("c", 64), `{"protocol":"vless","tag":"upstream-slot-1"}`)
	f.fetcher.replies["sub-a"] = fetchReply{cands: []candidate.Candidate{bad}}
	f.prober.probes[bad.ID] = failure()
	p := f.pipeline(t)

	res, err := p.Refresh(context.Background(), f.decl, 1)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if res.Active || res.Healthy != 0 || res.VersionID == "" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if f.publisher.verifies != 0 {
		t.Fatalf("Verify calls = %d, want 0 for blackhole", f.publisher.verifies)
	}
	want := `{"protocol":"blackhole","tag":"upstream-slot-1"}`
	if len(f.publisher.publishes) != 1 || string(f.publisher.publishes[0].outbound) != want {
		t.Fatalf("published = %+v", f.publisher.publishes)
	}
	active, err := f.store.ActiveUpstreamVersion(context.Background(), 1)
	if err != nil {
		t.Fatalf("ActiveUpstreamVersion: %v", err)
	}
	if active.Origin != "blackhole" || active.ID != res.VersionID {
		t.Fatalf("active version = %+v", active)
	}
}

func TestRefreshFailsClosedWhenAllSourcesFail(t *testing.T) {
	f := newFixture(t)
	f.fetcher.replies["sub-a"] = fetchReply{err: errors.New("https://example.com/sub/a: 500")}
	p := f.pipeline(t)

	res, err := p.Refresh(context.Background(), f.decl, 1)
	if err == nil || !strings.Contains(err.Error(), "fetch_failed") {
		t.Fatalf("Refresh error = %v, want fetch_failed", err)
	}
	if strings.Contains(err.Error(), "example.com") {
		t.Fatalf("error leaks locator: %v", err)
	}
	if res.Reason != "fetch_failed" || res.VersionID != "" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if len(f.publisher.publishes) != 0 || f.publisher.verifies != 0 {
		t.Fatalf("publisher used on fetch failure: %+v", f.publisher)
	}
	slot, err := f.store.UpstreamSlot(context.Background(), 1)
	if err != nil {
		t.Fatalf("UpstreamSlot: %v", err)
	}
	if slot.Mode != "blackhole" || slot.FailureCount != 1 || slot.LastErrorCode != "fetch_failed" {
		t.Fatalf("slot = %+v", slot)
	}
}

func TestRefreshRestoresPreviousVersionOnReadbackMismatch(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	prevOutbound := []byte(`{"protocol":"vless","tag":"upstream-slot-1","settings":{"prev":true}}`)
	prevRef, err := f.payloads.Put(ctx, prevOutbound)
	if err != nil {
		t.Fatalf("payload Put: %v", err)
	}
	prev, err := f.store.CreateUpstreamVersion(ctx, store.UpstreamVersion{
		Slot:                1,
		Origin:              "upstream",
		PayloadRef:          prevRef.ID,
		PayloadSHA256:       prevRef.SHA256,
		OutboundFingerprint: sha(prevOutbound),
	}, f.now)
	if err != nil {
		t.Fatalf("CreateUpstreamVersion: %v", err)
	}
	if _, _, err := f.store.ActivateUpstreamVersion(ctx, prev.ID, f.now); err != nil {
		t.Fatalf("ActivateUpstreamVersion: %v", err)
	}

	good := cand(strings.Repeat("d", 64), `{"protocol":"vless","tag":"upstream-slot-1","settings":{"next":true}}`)
	f.fetcher.replies["sub-a"] = fetchReply{cands: []candidate.Candidate{good}}
	f.prober.probes[good.ID] = success(10 * time.Millisecond)
	f.publisher.readBack = []byte(`{"protocol":"blackhole","tag":"upstream-slot-1"}`)
	p := f.pipeline(t)

	res, err := p.Refresh(ctx, f.decl, 1)
	if err == nil || !strings.Contains(err.Error(), "readback_mismatch") {
		t.Fatalf("Refresh error = %v, want readback_mismatch", err)
	}
	if !res.RolledBack {
		t.Fatalf("RolledBack = false, result %+v", res)
	}
	if len(f.publisher.restores) != 1 {
		t.Fatalf("restores = %+v", f.publisher.restores)
	}
	restore := f.publisher.restores[0]
	if restore.slot != 1 || restore.versionID != prev.ID || string(restore.outbound) != string(prevOutbound) {
		t.Fatalf("restore = %+v", restore)
	}

	failed, err := f.store.GetUpstreamVersion(ctx, res.VersionID)
	if err != nil {
		t.Fatalf("GetUpstreamVersion: %v", err)
	}
	if failed.State != "failed" || failed.FailureCode != "readback_mismatch" {
		t.Fatalf("failed version = %+v", failed)
	}
	active, err := f.store.ActiveUpstreamVersion(ctx, 1)
	if err != nil {
		t.Fatalf("ActiveUpstreamVersion: %v", err)
	}
	if active.ID != prev.ID {
		t.Fatalf("active = %s, want %s", active.ID, prev.ID)
	}
	slot, err := f.store.UpstreamSlot(ctx, 1)
	if err != nil {
		t.Fatalf("UpstreamSlot: %v", err)
	}
	if slot.Mode != "upstream" || slot.ActiveVersionID != prev.ID || slot.FailureCount != 1 {
		t.Fatalf("slot = %+v", slot)
	}
}

func TestRefreshPublishFailureWithoutPreviousRestoresBlackhole(t *testing.T) {
	f := newFixture(t)
	good := cand(strings.Repeat("e", 64), `{"protocol":"vless","tag":"upstream-slot-1"}`)
	f.fetcher.replies["sub-a"] = fetchReply{cands: []candidate.Candidate{good}}
	f.prober.probes[good.ID] = success(10 * time.Millisecond)
	f.publisher.publishErr = errors.New("panel unavailable")
	p := f.pipeline(t)

	res, err := p.Refresh(context.Background(), f.decl, 1)
	if err == nil || !strings.Contains(err.Error(), "publish_failed") {
		t.Fatalf("Refresh error = %v, want publish_failed", err)
	}
	if res.VersionID == "" || !res.RolledBack {
		t.Fatalf("unexpected result: %+v", res)
	}
	if len(f.publisher.restores) != 1 {
		t.Fatalf("restores = %+v", f.publisher.restores)
	}
	restore := f.publisher.restores[0]
	want := `{"protocol":"blackhole","tag":"upstream-slot-1"}`
	if restore.versionID != "" || string(restore.outbound) != want {
		t.Fatalf("restore = %+v", restore)
	}
	failed, err := f.store.GetUpstreamVersion(context.Background(), res.VersionID)
	if err != nil {
		t.Fatalf("GetUpstreamVersion: %v", err)
	}
	if failed.State != "failed" || failed.FailureCode != "publish_failed" {
		t.Fatalf("failed version = %+v", failed)
	}
	slot, err := f.store.UpstreamSlot(context.Background(), 1)
	if err != nil {
		t.Fatalf("UpstreamSlot: %v", err)
	}
	if slot.Mode != "blackhole" || slot.FailureCount != 1 {
		t.Fatalf("slot = %+v", slot)
	}
}

func TestRefreshSingleFlightPerSlot(t *testing.T) {
	f := newFixture(t)
	good := cand(strings.Repeat("f", 64), `{"protocol":"vless","tag":"upstream-slot-1"}`)
	f.fetcher.replies["sub-a"] = fetchReply{cands: []candidate.Candidate{good}}
	f.prober.probes[good.ID] = success(10 * time.Millisecond)
	f.prober.started = make(chan string, 1)
	f.prober.release = make(chan struct{})
	p := f.pipeline(t)

	done := make(chan error, 1)
	go func() {
		_, err := p.Refresh(context.Background(), f.decl, 1)
		done <- err
	}()

	select {
	case <-f.prober.started:
	case <-time.After(5 * time.Second):
		t.Fatal("probe did not start")
	}
	if _, err := p.Refresh(context.Background(), f.decl, 1); !errors.Is(err, ErrInProgress) {
		t.Fatalf("second Refresh error = %v, want ErrInProgress", err)
	}
	close(f.prober.release)
	if err := <-done; err != nil {
		t.Fatalf("first Refresh: %v", err)
	}
	if _, err := p.Refresh(context.Background(), f.decl, 1); err != nil {
		t.Fatalf("Refresh after completion: %v", err)
	}
}

func TestRefreshHonorsSourceFilter(t *testing.T) {
	f := newFixture(t)
	declPath := filepath.Join(t.TempDir(), "filtered.yaml")
	decl := `schema: 1
sources:
  - id: sub-a
    kind: subscription
    slot: 1
    interval: 5m
    subscription_url: https://example.com/sub/a
    filter:
      countries: [JP]
      min_successful_probes: 2
`
	if err := os.WriteFile(declPath, []byte(decl), 0o600); err != nil {
		t.Fatalf("write declaration: %v", err)
	}
	loaded, err := source.Load(declPath)
	if err != nil {
		t.Fatalf("source.Load: %v", err)
	}
	f.decl = loaded

	only := cand(strings.Repeat("1", 64), `{"protocol":"vless","tag":"upstream-slot-1"}`)
	f.fetcher.replies["sub-a"] = fetchReply{cands: []candidate.Candidate{only}}
	f.prober.probes[only.ID] = []selector.Probe{{Outcome: "success", Latency: 10 * time.Millisecond, Country: "US"}}
	p := f.pipeline(t)

	res, err := p.Refresh(context.Background(), f.decl, 1)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if res.Active {
		t.Fatalf("candidate passed a country filter it violates: %+v", res)
	}
	active, err := f.store.ActiveUpstreamVersion(context.Background(), 1)
	if err != nil {
		t.Fatalf("ActiveUpstreamVersion: %v", err)
	}
	if active.Origin != "blackhole" {
		t.Fatalf("active origin = %s, want blackhole", active.Origin)
	}
}
