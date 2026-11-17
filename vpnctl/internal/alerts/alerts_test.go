package alerts

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/juvenileslave/vpn/vpnctl/internal/metrics"
	"github.com/juvenileslave/vpn/vpnctl/internal/notify"
	"github.com/juvenileslave/vpn/vpnctl/internal/store"
)

const testMetricsToken = "synthetic-token-0123456789"

// fakeMetrics is a TLS Prometheus-compatible endpoint with a controllable
// scalar value or result mode. It never leaves loopback.
type fakeMetrics struct {
	srv    *httptest.Server
	client *metrics.Client

	mu       sync.Mutex
	mode     string
	value    float64
	requests int
	auth     string
}

func newFakeMetrics(t *testing.T) *fakeMetrics {
	t.Helper()
	f := &fakeMetrics{mode: "value", value: 10}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	client, err := metrics.NewClient(metrics.Options{
		BaseURL:     f.srv.URL,
		HTTPClient:  f.srv.Client(),
		Timeout:     2 * time.Second,
		BearerToken: testMetricsToken,
	})
	if err != nil {
		t.Fatalf("metrics.NewClient: %v", err)
	}
	f.client = client
	return f
}

func (f *fakeMetrics) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests++
	f.auth = r.Header.Get("Authorization")
	mode, value := f.mode, f.value
	f.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	switch mode {
	case "empty":
		io.WriteString(w, `{"status":"success","data":{"resultType":"vector","result":[]}}`)
	case "nan":
		io.WriteString(w, `{"status":"success","data":{"resultType":"scalar","result":[1700000000,"NaN"]}}`)
	case "error":
		io.WriteString(w, `{"status":"error","errorType":"bad_data","error":"synthetic failure with SECRET-BODY"}`)
	default:
		body, _ := json.Marshal(map[string]any{
			"status": "success",
			"data": map[string]any{
				"resultType": "scalar",
				"result":     []any{1700000000, strconv.FormatFloat(value, 'g', -1, 64)},
			},
		})
		w.Write(body)
	}
}

func (f *fakeMetrics) setValue(v float64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mode, f.value = "value", v
}

func (f *fakeMetrics) setMode(mode string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mode = mode
}

func (f *fakeMetrics) requestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests
}

// fakeSink records accepted alerts and can fail a fixed number of attempts.
type fakeSink struct {
	mu       sync.Mutex
	sent     []notify.Alert
	failures int
}

func (s *fakeSink) Send(_ context.Context, a notify.Alert) error {
	if err := a.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failures > 0 {
		s.failures--
		return errors.New("synthetic sink failure")
	}
	s.sent = append(s.sent, a)
	return nil
}

func (s *fakeSink) alerts() []notify.Alert {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]notify.Alert(nil), s.sent...)
}

func (s *fakeSink) setFailures(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures = n
}

func testRule(name string) metrics.Rule {
	return metrics.Rule{
		Name:        name,
		Query:       "secret_metric_expr",
		Aggregation: metrics.AggMax,
		Comparison:  metrics.CmpGreater,
		Threshold:   90,
		Severity:    metrics.SeverityWarning,
	}
}

func testWorkerConfig(now *time.Time) Config {
	return Config{
		Interval:     time.Minute,
		Grace:        0,
		FlapSamples:  1,
		Retention:    time.Hour,
		OutboxMaxAge: time.Hour,
		RetryBase:    time.Minute,
		RetryMax:     4 * time.Minute,
		MaxAttempts:  3,
		Scope:        "synthetic",
		Now:          func() time.Time { return *now },
	}
}

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func newTestWorker(t *testing.T, st *store.Store, q metrics.Querier, sink notify.Sink, rules []metrics.Rule, cfg Config) *Worker {
	t.Helper()
	w, err := NewWorker(st, q, sink, rules, cfg)
	if err != nil {
		t.Fatalf("NewWorker: %v", err)
	}
	return w
}

func TestCheckTypedResults(t *testing.T) {
	ctx := context.Background()
	f := newFakeMetrics(t)
	rules := []metrics.Rule{testRule("rule-a")}
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	f.setValue(95)
	res, err := Check(ctx, f.client, rules, at)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || res[0].State != metrics.StateFiring || res[0].Value == nil || *res[0].Value != 95 {
		t.Fatalf("firing result = %+v", res)
	}
	if res[0].Comparison != ">" || res[0].Threshold != 90 {
		t.Fatalf("comparison = %+v", res[0])
	}

	f.setValue(10)
	res, err = Check(ctx, f.client, rules, at)
	if err != nil || res[0].State != metrics.StateOK || res[0].Value == nil || *res[0].Value != 10 {
		t.Fatalf("ok result = %+v, %v", res, err)
	}

	for _, tc := range []struct {
		mode   string
		reason string
	}{
		{"empty", "no_data"},
		{"nan", "non_finite"},
		{"error", "query_error"},
	} {
		f.setMode(tc.mode)
		res, err = Check(ctx, f.client, rules, at)
		if err != nil {
			t.Fatalf("%s: %v", tc.mode, err)
		}
		if res[0].State != metrics.StateUnknown || res[0].Reason != tc.reason || res[0].Value != nil {
			t.Fatalf("%s result = %+v", tc.mode, res[0])
		}
		if strings.Contains(res[0].Reason, "SECRET") {
			t.Fatalf("raw response leaked into result: %+v", res[0])
		}
	}
}

func TestCheckRejectsInvalidRulesBeforeQuery(t *testing.T) {
	f := newFakeMetrics(t)
	bad := testRule("rule-a")
	bad.Threshold = 0
	bad.Comparison = "??"
	if _, err := Check(context.Background(), f.client, []metrics.Rule{bad}, time.Now()); err == nil {
		t.Fatal("expected validation error")
	}
	if n := f.requestCount(); n != 0 {
		t.Fatalf("requests = %d, want 0", n)
	}
	if _, err := NewWorker(openTestStore(t), f.client, &fakeSink{}, []metrics.Rule{bad}, testWorkerConfig(new(time.Time))); err == nil {
		t.Fatal("NewWorker accepted invalid rules")
	}
}

func TestDecideTransitions(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	rule := testRule("rule-a")
	cfg := testWorkerConfig(&now)
	cfg.FlapSamples = 2
	cfg.Grace = 2 * time.Minute

	alert := func(state metrics.State) metrics.Alert {
		return metrics.Alert{
			Rule: "rule-a", Severity: metrics.SeverityWarning, State: state,
			Value: 95, Threshold: 90, Labels: map[string]string{"instance": "exit-01"},
		}
	}

	// The first observation establishes the state immediately.
	st, event := decide(nil, alert(metrics.StateOK), rule, cfg, now)
	if event != "" || st.State != store.AlertOK {
		t.Fatalf("initial ok = %+v, %q", st, event)
	}
	st, event = decide(nil, alert(metrics.StateFiring), rule, cfg, now)
	if event != store.EventFiring || st.State != store.AlertFiring {
		t.Fatalf("initial firing = %+v, %q", st, event)
	}
	st, event = decide(nil, alert(metrics.StateUnknown), rule, cfg, now)
	if event != "" || st.State != store.AlertUnknown {
		t.Fatalf("initial unknown = %+v, %q", st, event)
	}

	// ok -> firing needs two consecutive firing samples.
	cur, _ := decide(nil, alert(metrics.StateOK), rule, cfg, now)
	next, event := decide(&cur, alert(metrics.StateFiring), rule, cfg, now)
	if event != "" || next.PendingState != store.AlertFiring || next.PendingSamples != 1 {
		t.Fatalf("first flap sample = %+v, %q", next, event)
	}
	flapReset, event := decide(&next, alert(metrics.StateOK), rule, cfg, now)
	if event != "" || flapReset.PendingState != "" {
		t.Fatalf("flap reset = %+v, %q", flapReset, event)
	}
	next, event = decide(&flapReset, alert(metrics.StateFiring), rule, cfg, now)
	if event != "" {
		t.Fatalf("second run first sample = %+v, %q", next, event)
	}
	next, event = decide(&next, alert(metrics.StateFiring), rule, cfg, now)
	if event != store.EventFiring || next.State != store.AlertFiring {
		t.Fatalf("confirmed firing = %+v, %q", next, event)
	}

	// firing -> ok recovers immediately.
	recovered, event := decide(&next, alert(metrics.StateOK), rule, cfg, now)
	if event != store.EventRecovery || recovered.State != store.AlertOK {
		t.Fatalf("recovery = %+v, %q", recovered, event)
	}

	// firing -> unknown waits for grace and reports once.
	cur = next
	next, event = decide(&cur, alert(metrics.StateUnknown), rule, cfg, now)
	if event != "" || next.State != store.AlertFiring || next.PendingState != store.AlertUnknown {
		t.Fatalf("first unknown sample = %+v, %q", next, event)
	}
	next, event = decide(&next, alert(metrics.StateUnknown), rule, cfg, now.Add(time.Minute))
	if event != "" {
		t.Fatalf("unknown before grace = %+v, %q", next, event)
	}
	next, event = decide(&next, alert(metrics.StateUnknown), rule, cfg, now.Add(2*time.Minute))
	if event != store.EventUnknown || next.State != store.AlertUnknown {
		t.Fatalf("unknown after grace = %+v, %q", next, event)
	}
	next, event = decide(&next, alert(metrics.StateUnknown), rule, cfg, now.Add(3*time.Minute))
	if event != "" {
		t.Fatalf("repeated unknown = %+v, %q", next, event)
	}

	// unknown -> ok is not a recovery notification.
	backOK, event := decide(&next, alert(metrics.StateOK), rule, cfg, now.Add(4*time.Minute))
	if event != "" || backOK.State != store.AlertOK {
		t.Fatalf("unknown to ok = %+v, %q", backOK, event)
	}

	// A deleted rule keeps its last state until retention prunes it.
	missing := backOK
	missing.MissingSince = now.Add(4 * time.Minute)
	if missing.State != store.AlertOK {
		t.Fatalf("missing state = %+v", missing)
	}
}

func TestWorkerFiringRecoveryAndRestart(t *testing.T) {
	ctx := context.Background()
	f := newFakeMetrics(t)
	st := openTestStore(t)
	sink := &fakeSink{}
	rules := []metrics.Rule{testRule("rule-a")}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	cfg := testWorkerConfig(&now)

	f.setValue(95)
	w := newTestWorker(t, st, f.client, sink, rules, cfg)
	res, err := w.Cycle(ctx)
	if err != nil {
		t.Fatalf("cycle: %v", err)
	}
	if res.Notified != 1 || res.Delivered != 1 || len(sink.alerts()) != 1 {
		t.Fatalf("first cycle = %+v, sent %d", res, len(sink.alerts()))
	}
	msg := sink.alerts()[0].Message
	for _, want := range []string{"firing", "rule=rule-a", "severity=warning", "scope=synthetic", "value=95", "condition=> 90", "labels=", "observed_at="} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message %q misses %q", msg, want)
		}
	}
	if strings.Contains(msg, testMetricsToken) || strings.Contains(msg, "secret_metric_expr") {
		t.Fatalf("message leaked credentials or query: %q", msg)
	}

	res, err = w.Cycle(ctx)
	if err != nil || res.Notified != 0 || len(sink.alerts()) != 1 {
		t.Fatalf("unchanged cycle = %+v, %v", res, err)
	}

	// A restarted worker resumes the persisted firing state and sends nothing.
	w2 := newTestWorker(t, st, f.client, sink, rules, cfg)
	res, err = w2.Cycle(ctx)
	if err != nil || res.Notified != 0 || len(sink.alerts()) != 1 {
		t.Fatalf("restart cycle = %+v, %v", res, err)
	}

	f.setValue(10)
	res, err = w2.Cycle(ctx)
	if err != nil || res.Notified != 1 || len(sink.alerts()) != 2 {
		t.Fatalf("recovery cycle = %+v, %v", res, err)
	}
	if got := sink.alerts()[1].Message; !strings.Contains(got, "recovery") || !strings.Contains(got, "value=10") {
		t.Fatalf("recovery message = %q", got)
	}

	w3 := newTestWorker(t, st, f.client, sink, rules, cfg)
	if res, err := w3.Cycle(ctx); err != nil || res.Notified != 0 || len(sink.alerts()) != 2 {
		t.Fatalf("restart after recovery = %+v, %v", res, err)
	}
	if pending, expired, err := st.AlertOutboxStatus(ctx, now); err != nil || pending != 0 || expired != 0 {
		t.Fatalf("outbox status = %d/%d, %v", pending, expired, err)
	}
}

func TestWorkerFlapSuppression(t *testing.T) {
	ctx := context.Background()
	f := newFakeMetrics(t)
	st := openTestStore(t)
	sink := &fakeSink{}
	rules := []metrics.Rule{testRule("rule-a")}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	cfg := testWorkerConfig(&now)
	cfg.FlapSamples = 2
	w := newTestWorker(t, st, f.client, sink, rules, cfg)

	f.setValue(10)
	if _, err := w.Cycle(ctx); err != nil {
		t.Fatal(err)
	}
	f.setValue(95)
	if res, err := w.Cycle(ctx); err != nil || res.Notified != 0 || len(sink.alerts()) != 0 {
		t.Fatalf("first flap sample = %+v, %v, sent %d", res, err, len(sink.alerts()))
	}
	if res, err := w.Cycle(ctx); err != nil || res.Notified != 1 || len(sink.alerts()) != 1 {
		t.Fatalf("confirmed firing = %+v, %v, sent %d", res, err, len(sink.alerts()))
	}
	f.setValue(10)
	if res, err := w.Cycle(ctx); err != nil || res.Notified != 1 || len(sink.alerts()) != 2 {
		t.Fatalf("recovery = %+v, %v, sent %d", res, err, len(sink.alerts()))
	}
	if got := sink.alerts()[1].Message; !strings.Contains(got, "recovery") {
		t.Fatalf("second message = %q", got)
	}
}

func TestWorkerUnknownGraceThenNoFalseRecovery(t *testing.T) {
	ctx := context.Background()
	f := newFakeMetrics(t)
	st := openTestStore(t)
	sink := &fakeSink{}
	rules := []metrics.Rule{testRule("rule-a")}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	cfg := testWorkerConfig(&now)
	cfg.Grace = 2 * time.Minute
	w := newTestWorker(t, st, f.client, sink, rules, cfg)

	f.setValue(10)
	if _, err := w.Cycle(ctx); err != nil {
		t.Fatal(err)
	}
	f.setMode("empty")
	now = now.Add(time.Minute)
	if res, err := w.Cycle(ctx); err != nil || res.Notified != 0 || len(sink.alerts()) != 0 {
		t.Fatalf("unknown before grace = %+v, %v", res, err)
	}
	now = now.Add(time.Minute)
	if res, err := w.Cycle(ctx); err != nil || res.Notified != 0 {
		t.Fatalf("unknown still before grace = %+v, %v", res, err)
	}
	now = now.Add(time.Minute)
	res, err := w.Cycle(ctx)
	if err != nil || res.Notified != 1 || len(sink.alerts()) != 1 {
		t.Fatalf("unknown after grace = %+v, %v", res, err)
	}
	msg := sink.alerts()[0].Message
	if !strings.Contains(msg, "unknown") || !strings.Contains(msg, "reason=no_data") {
		t.Fatalf("unknown message = %q", msg)
	}

	now = now.Add(time.Minute)
	if res, err := w.Cycle(ctx); err != nil || res.Notified != 0 || len(sink.alerts()) != 1 {
		t.Fatalf("repeated unknown = %+v, %v", res, err)
	}

	f.setValue(10)
	now = now.Add(time.Minute)
	if res, err := w.Cycle(ctx); err != nil || res.Notified != 0 || len(sink.alerts()) != 1 {
		t.Fatalf("unknown to ok = %+v, %v, sent %d", res, err, len(sink.alerts()))
	}
	stored, err := st.GetAlertState(ctx, "rule-a")
	if err != nil || stored.State != store.AlertOK {
		t.Fatalf("state after unknown = %+v, %v", stored, err)
	}
}

func TestWorkerMuteSuppressesNotificationsButKeepsState(t *testing.T) {
	ctx := context.Background()
	f := newFakeMetrics(t)
	st := openTestStore(t)
	sink := &fakeSink{}
	rules := []metrics.Rule{testRule("rule-a")}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	cfg := testWorkerConfig(&now)
	if err := st.SetAlertMute(ctx, "rule-a", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	f.setValue(95)
	w := newTestWorker(t, st, f.client, sink, rules, cfg)
	res, err := w.Cycle(ctx)
	if err != nil || res.Notified != 0 || len(sink.alerts()) != 0 {
		t.Fatalf("muted cycle = %+v, %v, sent %d", res, err, len(sink.alerts()))
	}
	stored, err := st.GetAlertState(ctx, "rule-a")
	if err != nil || stored.State != store.AlertFiring {
		t.Fatalf("muted state = %+v, %v", stored, err)
	}
}

func TestWorkerReportsRemovedRuleOnceAndPrunesAfterRetention(t *testing.T) {
	ctx := context.Background()
	f := newFakeMetrics(t)
	st := openTestStore(t)
	sink := &fakeSink{}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	cfg := testWorkerConfig(&now)
	f.setValue(10)

	w := newTestWorker(t, st, f.client, sink, []metrics.Rule{testRule("rule-a"), testRule("rule-b")}, cfg)
	if _, err := w.Cycle(ctx); err != nil {
		t.Fatal(err)
	}

	now = now.Add(time.Minute)
	w2 := newTestWorker(t, st, f.client, sink, []metrics.Rule{testRule("rule-a")}, cfg)
	res, err := w2.Cycle(ctx)
	if err != nil || res.Notified != 1 || len(sink.alerts()) != 1 {
		t.Fatalf("removed cycle = %+v, %v, sent %d", res, err, len(sink.alerts()))
	}
	msg := sink.alerts()[0].Message
	if !strings.Contains(msg, "removed") || !strings.Contains(msg, "rule=rule-b") || !strings.Contains(msg, "last_state=ok") {
		t.Fatalf("removed message = %q", msg)
	}

	now = now.Add(time.Minute)
	if res, err := w2.Cycle(ctx); err != nil || res.Notified != 0 || len(sink.alerts()) != 1 {
		t.Fatalf("second removed cycle = %+v, %v", res, err)
	}
	if _, err := st.GetAlertState(ctx, "rule-b"); err != nil {
		t.Fatalf("removed state must be retained before retention: %v", err)
	}

	now = now.Add(2 * time.Hour)
	if _, err := w2.Cycle(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetAlertState(ctx, "rule-b"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("removed state after retention err = %v", err)
	}
	if _, err := st.GetAlertState(ctx, "rule-a"); err != nil {
		t.Fatalf("present state missing: %v", err)
	}
}

func TestWorkerSkipsWhileAnotherInstanceHoldsRunLock(t *testing.T) {
	ctx := context.Background()
	f := newFakeMetrics(t)
	st := openTestStore(t)
	sink := &fakeSink{}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	cfg := testWorkerConfig(&now)
	if ok, err := st.ClaimAlertRun(ctx, "other-instance", now, time.Hour); err != nil || !ok {
		t.Fatalf("foreign lock = %v, %v", ok, err)
	}
	f.setValue(95)
	w := newTestWorker(t, st, f.client, sink, []metrics.Rule{testRule("rule-a")}, cfg)
	res, err := w.Cycle(ctx)
	if err != nil || !res.Skipped {
		t.Fatalf("cycle = %+v, %v", res, err)
	}
	if n := f.requestCount(); n != 0 {
		t.Fatalf("requests = %d, want 0", n)
	}
	if len(sink.alerts()) != 0 {
		t.Fatalf("sent = %d", len(sink.alerts()))
	}
}

func TestWorkerOutboxRetry(t *testing.T) {
	ctx := context.Background()
	f := newFakeMetrics(t)
	st := openTestStore(t)
	sink := &fakeSink{}
	sink.setFailures(1)
	rules := []metrics.Rule{testRule("rule-a")}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	cfg := testWorkerConfig(&now)
	cfg.RetryBase = time.Minute
	w := newTestWorker(t, st, f.client, sink, rules, cfg)

	f.setValue(95)
	res, err := w.Cycle(ctx)
	if err != nil || res.Notified != 1 || res.Delivered != 0 || res.Undelivered != 1 {
		t.Fatalf("failed cycle = %+v, %v", res, err)
	}
	if res.PendingOutbox != 1 || len(sink.alerts()) != 0 {
		t.Fatalf("outbox = %+v, sent %d", res, len(sink.alerts()))
	}

	now = now.Add(30 * time.Second)
	if res, err := w.Cycle(ctx); err != nil || res.Delivered != 0 || res.Undelivered != 0 {
		t.Fatalf("backoff cycle = %+v, %v", res, err)
	}
	now = now.Add(30 * time.Second)
	res, err = w.Cycle(ctx)
	if err != nil || res.Delivered != 1 || res.Notified != 0 || len(sink.alerts()) != 1 {
		t.Fatalf("retry cycle = %+v, %v, sent %d", res, err, len(sink.alerts()))
	}
	if res.PendingOutbox != 0 {
		t.Fatalf("pending outbox = %d", res.PendingOutbox)
	}
}

func TestWorkerAbandonsAfterMaxAttempts(t *testing.T) {
	ctx := context.Background()
	f := newFakeMetrics(t)
	st := openTestStore(t)
	sink := &fakeSink{}
	sink.setFailures(2)
	rules := []metrics.Rule{testRule("rule-a")}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	cfg := testWorkerConfig(&now)
	cfg.MaxAttempts = 2
	cfg.RetryBase = time.Minute
	w := newTestWorker(t, st, f.client, sink, rules, cfg)

	f.setValue(95)
	if res, err := w.Cycle(ctx); err != nil || res.Undelivered != 1 {
		t.Fatalf("first failure = %+v, %v", res, err)
	}
	now = now.Add(time.Minute)
	res, err := w.Cycle(ctx)
	if err != nil || res.Undelivered != 1 || res.ExpiredOutbox != 1 {
		t.Fatalf("abandoned cycle = %+v, %v", res, err)
	}
	if pending, expired, err := st.AlertOutboxStatus(ctx, now); err != nil || pending != 0 || expired != 1 {
		t.Fatalf("status after abandon = %d/%d, %v", pending, expired, err)
	}
	now = now.Add(2 * time.Hour)
	if res, err := w.Cycle(ctx); err != nil || res.Delivered != 0 || len(sink.alerts()) != 0 {
		t.Fatalf("post-abandon cycle = %+v, %v", res, err)
	}
	if pending, expired, err := st.AlertOutboxStatus(ctx, now); err != nil || pending != 0 || expired != 0 {
		t.Fatalf("status after retention = %d/%d, %v", pending, expired, err)
	}
}

func TestBuildMessageBoundsAndSanitizes(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	st := store.AlertState{
		Rule:        "rule-a",
		State:       store.AlertFiring,
		Severity:    "critical",
		Comparison:  ">=",
		Value:       95,
		Threshold:   90,
		Fingerprint: strings.Repeat("a", 64),
		Labels:      map[string]string{},
	}
	for i := range 60 {
		st.Labels[strings.Repeat("k", 20)+string(rune('a'+i%26))+string(rune('0'+i/26))] = strings.Repeat("v", 250)
	}
	st.Labels["control"] = "a\nb\x00c"
	msg := buildMessage(st, store.EventFiring, "", "synthetic", now)
	if got := len([]rune(msg)); got > maxMessageRunes {
		t.Fatalf("message runes = %d, want <= %d", got, maxMessageRunes)
	}
	if strings.ContainsRune(msg, 0) {
		t.Fatal("message contains NUL")
	}
	for _, want := range []string{"rule=rule-a", "severity=critical", "scope=synthetic", "condition=>= 90", "observed_at="} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message misses %q: %q", want, msg)
		}
	}
	if strings.Contains(msg, "a\nb") {
		t.Fatal("newline from a label was not sanitized")
	}
}

func TestWorkerPreservesPerRuleDeliveryOrder(t *testing.T) {
	ctx := context.Background()
	f := newFakeMetrics(t)
	st := openTestStore(t)
	sink := &fakeSink{}
	rules := []metrics.Rule{testRule("rule-a")}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	cfg := testWorkerConfig(&now)
	cfg.RetryBase = time.Minute
	w := newTestWorker(t, st, f.client, sink, rules, cfg)

	// The firing notification fails once and waits for its backoff.
	sink.setFailures(1)
	f.setValue(95)
	res, err := w.Cycle(ctx)
	if err != nil || res.Notified != 1 || res.Undelivered != 1 || len(sink.alerts()) != 0 {
		t.Fatalf("firing cycle = %+v, %v, sent %d", res, err, len(sink.alerts()))
	}

	// The recovery is due immediately, but the earlier firing row is still
	// undelivered, so it must not overtake it.
	now = now.Add(30 * time.Second)
	f.setValue(10)
	res, err = w.Cycle(ctx)
	if err != nil || res.Notified != 1 || res.Delivered != 0 || res.Undelivered != 0 || len(sink.alerts()) != 0 {
		t.Fatalf("recovery cycle = %+v, %v, sent %d", res, err, len(sink.alerts()))
	}

	now = now.Add(30 * time.Second)
	res, err = w.Cycle(ctx)
	if err != nil || res.Delivered != 2 || res.Notified != 0 || len(sink.alerts()) != 2 {
		t.Fatalf("ordered retry = %+v, %v, sent %d", res, err, len(sink.alerts()))
	}
	first, second := sink.alerts()[0].Message, sink.alerts()[1].Message
	if !strings.Contains(first, "firing") || !strings.Contains(second, "recovery") {
		t.Fatalf("delivery order = %q, %q", first, second)
	}
}

func TestWorkerExpiresUndeliveredAfterMaxAge(t *testing.T) {
	ctx := context.Background()
	f := newFakeMetrics(t)
	st := openTestStore(t)
	sink := &fakeSink{}
	rules := []metrics.Rule{testRule("rule-a")}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	cfg := testWorkerConfig(&now)
	cfg.OutboxMaxAge = time.Minute
	w := newTestWorker(t, st, f.client, sink, rules, cfg)

	sink.setFailures(1)
	f.setValue(95)
	if res, err := w.Cycle(ctx); err != nil || res.Undelivered != 1 || res.PendingOutbox != 1 {
		t.Fatalf("failing cycle = %+v, %v", res, err)
	}

	now = now.Add(2 * time.Minute)
	res, err := w.Cycle(ctx)
	if err != nil || res.Delivered != 0 || res.ExpiredOutbox != 1 {
		t.Fatalf("expired cycle = %+v, %v", res, err)
	}
	if pending, expired, err := st.AlertOutboxStatus(ctx, now); err != nil || pending != 0 || expired != 1 {
		t.Fatalf("status = %d/%d, %v", pending, expired, err)
	}
	rows, err := st.ListOpenAlertOutbox(ctx, 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("expired row = %+v, %v", rows, err)
	}

	// Retention removes the abandoned row; it is never retried.
	now = now.Add(2 * time.Hour)
	if res, err := w.Cycle(ctx); err != nil || res.ExpiredOutbox != 0 {
		t.Fatalf("retention cycle = %+v, %v", res, err)
	}
	if pending, expired, err := st.AlertOutboxStatus(ctx, now); err != nil || pending != 0 || expired != 0 {
		t.Fatalf("status after retention = %d/%d, %v", pending, expired, err)
	}
}

func TestWorkerReportsRenamedRule(t *testing.T) {
	ctx := context.Background()
	f := newFakeMetrics(t)
	st := openTestStore(t)
	sink := &fakeSink{}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	cfg := testWorkerConfig(&now)
	f.setValue(10)

	w := newTestWorker(t, st, f.client, sink, []metrics.Rule{testRule("rule-a"), testRule("rule-b")}, cfg)
	if res, err := w.Cycle(ctx); err != nil || res.Notified != 0 {
		t.Fatalf("baseline cycle = %+v, %v", res, err)
	}

	now = now.Add(time.Minute)
	f.setValue(95)
	w2 := newTestWorker(t, st, f.client, sink, []metrics.Rule{testRule("rule-a"), testRule("rule-c")}, cfg)
	res, err := w2.Cycle(ctx)
	if err != nil || res.Notified != 3 || len(sink.alerts()) != 3 {
		t.Fatalf("rename cycle = %+v, %v, sent %d", res, err, len(sink.alerts()))
	}
	var removed, renamed bool
	for _, alert := range sink.alerts() {
		if strings.Contains(alert.Message, "removed") && strings.Contains(alert.Message, "rule=rule-b") {
			removed = true
		}
		if strings.Contains(alert.Message, "firing") && strings.Contains(alert.Message, "rule=rule-c") {
			renamed = true
		}
	}
	if !removed || !renamed {
		t.Fatalf("rename notifications = %+v", sink.alerts())
	}
	if _, err := st.GetAlertState(ctx, "rule-b"); err != nil {
		t.Fatalf("renamed source state must be retained: %v", err)
	}
	if stored, err := st.GetAlertState(ctx, "rule-c"); err != nil || stored.State != store.AlertFiring {
		t.Fatalf("new rule state = %+v, %v", stored, err)
	}
}

func TestWorkerRestartPreservesOutbox(t *testing.T) {
	ctx := context.Background()
	f := newFakeMetrics(t)
	path := filepath.Join(t.TempDir(), "state.db")
	st, err := store.Open(ctx, path)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	rules := []metrics.Rule{testRule("rule-a")}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	cfg := testWorkerConfig(&now)
	cfg.RetryBase = time.Minute

	sink := &fakeSink{}
	sink.setFailures(1)
	f.setValue(95)
	w := newTestWorker(t, st, f.client, sink, rules, cfg)
	if res, err := w.Cycle(ctx); err != nil || res.Notified != 1 || res.Undelivered != 1 {
		st.Close()
		t.Fatalf("first cycle = %+v, %v", res, err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := store.Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	working := &fakeSink{}
	now = now.Add(time.Minute)
	w2 := newTestWorker(t, reopened, f.client, working, rules, cfg)
	res, err := w2.Cycle(ctx)
	if err != nil || res.Notified != 0 || res.Delivered != 1 || len(working.alerts()) != 1 {
		t.Fatalf("restart cycle = %+v, %v, sent %d", res, err, len(working.alerts()))
	}
	if got := working.alerts()[0].Message; !strings.Contains(got, "firing") || !strings.Contains(got, "rule=rule-a") {
		t.Fatalf("recovered outbox message = %q", got)
	}
	if res, err := w2.Cycle(ctx); err != nil || res.Notified != 0 || len(working.alerts()) != 1 {
		t.Fatalf("unchanged cycle = %+v, %v, sent %d", res, err, len(working.alerts()))
	}
}

func TestRunStopsOnCancelledContext(t *testing.T) {
	f := newFakeMetrics(t)
	st := openTestStore(t)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	cfg := testWorkerConfig(&now)
	w := newTestWorker(t, st, f.client, &fakeSink{}, []metrics.Rule{testRule("rule-a")}, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := w.Run(ctx); err != nil {
		t.Fatalf("Run = %v", err)
	}
	if n := f.requestCount(); n != 0 {
		t.Fatalf("requests = %d, want 0", n)
	}
}

func TestNewWorkerRejectsUnusableConfig(t *testing.T) {
	f := newFakeMetrics(t)
	st := openTestStore(t)
	sink := &fakeSink{}
	rules := []metrics.Rule{testRule("rule-a")}
	now := time.Now()
	base := testWorkerConfig(&now)
	cases := map[string]func(*Config){
		"zero interval":   func(c *Config) { c.Interval = 0 },
		"negative jitter": func(c *Config) { c.Jitter = -time.Second },
		"zero flap":       func(c *Config) { c.FlapSamples = 0 },
		"zero retention":  func(c *Config) { c.Retention = 0 },
		"retry inversion": func(c *Config) { c.RetryMax = time.Second },
		"zero attempts":   func(c *Config) { c.MaxAttempts = 0 },
		"bad scope":       func(c *Config) { c.Scope = "Bad Scope" },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := base
			mod(&cfg)
			if _, err := NewWorker(st, f.client, sink, rules, cfg); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	if _, err := NewWorker(nil, f.client, sink, rules, base); err == nil {
		t.Fatal("nil store accepted")
	}
	if _, err := NewWorker(st, nil, sink, rules, base); err == nil {
		t.Fatal("nil querier accepted")
	}
	if _, err := NewWorker(st, f.client, nil, rules, base); err == nil {
		t.Fatal("nil sink accepted")
	}
}
