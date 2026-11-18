package entrance

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/juvenileslave/vpn/vpnctl/internal/probe"
	"github.com/juvenileslave/vpn/vpnctl/internal/store"
)

const (
	testTarget = "exit-test"
	testRunID  = "0123456789abcdef0123456789abcdef"
)

type ids struct {
	endpoint string
	config   string
	sni      string
}

func testIDs() ids {
	return ids{
		endpoint: strings.Repeat("a", 64),
		config:   strings.Repeat("b", 64),
		sni:      strings.Repeat("c", 64),
	}
}

func testPlan(vantages []probe.Vantage, now time.Time) probe.DiagnosisPlan {
	return probe.DiagnosisPlan{
		Target:           testTarget,
		Family:           probe.IPv4,
		EndpointIdentity: testIDs().endpoint,
		ConfigIdentity:   testIDs().config,
		SNIIdentity:      testIDs().sni,
		Vantages:         vantages,
		Now:              now,
		Window:           10 * time.Minute,
		ThroughputFloor:  1 << 20,
	}
}

func vantage(name, network, kind string) probe.Vantage {
	return probe.Vantage{Name: name, Network: network, Kind: kind}
}

type failure struct {
	stage   probe.Stage
	outcome probe.Outcome
	code    string
}

// buildRun records one accepted five-stage attempt. A nil failure means every
// stage succeeded; otherwise the failing stage stops the ladder and the rest
// are explicitly skipped, exactly as the accepted runner records them.
func buildRun(v probe.Vantage, at time.Time, ident ids, runID string, fail *failure) probe.RunReport {
	target := testTarget
	report := probe.RunReport{
		Schema:           1,
		RunID:            runID,
		Target:           target,
		Family:           probe.IPv4,
		Vantage:          v,
		EndpointIdentity: ident.endpoint,
		ConfigIdentity:   ident.config,
		SNIIdentity:      ident.sni,
		ThroughputFloor:  1 << 20,
		Complete:         true,
		Outcome:          "success",
		Events:           make([]probe.Event, 0, 5),
	}
	start := at
	var previousEnd time.Time
	add := func(event probe.Event) {
		event.Target, event.Family, event.Vantage = target, probe.IPv4, v
		event.Scope = "node_path"
		event.ObservedAt = start
		if !previousEnd.IsZero() && event.ObservedAt.Before(previousEnd) {
			event.ObservedAt = previousEnd
		}
		previousEnd = event.ObservedAt.Add(event.Duration)
		start = previousEnd
		report.Events = append(report.Events, event)
	}
	blocked := false
	for _, stage := range []probe.Stage{probe.StageTCP, probe.StageTLS, probe.StageAuth, probe.StageTransferSmall, probe.StageThroughput} {
		event := probe.Event{Stage: stage, Outcome: probe.OutcomeSuccess, Duration: 5 * time.Millisecond}
		switch stage {
		case probe.StageAuth:
			event.ExpectedBytes, event.Bytes, event.Integrity = 256, 256, true
			event.BodyDuration = 2 * time.Millisecond
		case probe.StageTransferSmall:
			event.ExpectedBytes, event.Bytes, event.Integrity = probe.SmallBytes, probe.SmallBytes, true
			event.BodyDuration = 2 * time.Millisecond
		case probe.StageThroughput:
			event.ExpectedBytes, event.Bytes, event.Integrity = probe.LargeBytes, probe.LargeBytes, true
			event.BodyDuration = 2 * time.Millisecond
		}
		if blocked {
			event.Outcome, event.ErrorCode = probe.OutcomeSkipped, "stage_not_run"
			event.Duration, event.BodyDuration, event.Bytes, event.Integrity = 0, 0, 0, false
		} else if fail != nil && fail.stage == stage {
			event.Outcome, event.ErrorCode = fail.outcome, fail.code
			event.Bytes, event.ExpectedBytes, event.Integrity, event.BodyDuration = 0, 0, false, 0
			report.Outcome, report.ErrorCode = "failure", fail.code
			blocked = true
		}
		add(event)
	}
	return report
}

func TestCleanGateRequiresTwoIndependentRUVantages(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 10, 0, 0, time.UTC)
	at := now.Add(-time.Minute)
	plan := testPlan([]probe.Vantage{
		vantage("ru-wifi", "ru-wifi-net", "in_country"),
		vantage("ru-mobile", "ru-mobile-net", "in_country"),
	}, now)
	gate := Evaluate(plan, []probe.RunReport{
		buildRun(plan.Vantages[0], at, testIDs(), testRunID, nil),
		buildRun(plan.Vantages[1], at, testIDs(), "fedcba9876543210fedcba9876543210", nil),
	})
	if gate.State != StateClean || !gate.Usable || gate.Reason != ReasonCleanEntrance {
		t.Fatalf("gate = %+v", gate)
	}
	if gate.Scope.IndependentRUNetworks != 2 || !gate.Scope.RUVantageVerified || gate.Scope.QueryTruncated {
		t.Fatalf("scope = %+v", gate.Scope)
	}
	if len(gate.Vantages) != 2 || len(gate.Vantages[0].Stages) != 5 {
		t.Fatalf("vantages = %+v", gate.Vantages)
	}
}

func TestSingleRUVantageIsUnknown(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 10, 0, 0, time.UTC)
	plan := testPlan([]probe.Vantage{
		vantage("ru-wifi", "ru-wifi-net", "in_country"),
		vantage("outside", "outside-net", "outside"),
	}, now)
	gate := Evaluate(plan, []probe.RunReport{
		buildRun(plan.Vantages[0], now.Add(-time.Minute), testIDs(), testRunID, nil),
		buildRun(plan.Vantages[1], now.Add(-time.Minute), testIDs(), "fedcba9876543210fedcba9876543210", nil),
	})
	if gate.State != StateUnknown || gate.Usable || gate.Reason != ReasonIndependentVantage {
		t.Fatalf("gate = %+v", gate)
	}
}

func TestDatacenterOnlyEvidenceNeverBecomesRU(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 10, 0, 0, time.UTC)
	plan := testPlan([]probe.Vantage{
		vantage("local-dc", "dc-a", "local_dc"),
		vantage("outside", "dc-b", "outside"),
	}, now)
	gate := Evaluate(plan, []probe.RunReport{
		buildRun(plan.Vantages[0], now.Add(-time.Minute), testIDs(), testRunID, nil),
		buildRun(plan.Vantages[1], now.Add(-time.Minute), testIDs(), "fedcba9876543210fedcba9876543210", nil),
	})
	if gate.State != StateUnknown || gate.Usable || gate.Reason != ReasonNoRUVantage {
		t.Fatalf("gate = %+v", gate)
	}
}

func TestFailureClassification(t *testing.T) {
	cases := []struct {
		name  string
		fail  failure
		state State
		class FailureClass
		code  string
	}{
		{"tcp", failure{probe.StageTCP, probe.OutcomeTimeout, "timeout"}, StateFailed, FailureEntrance, ReasonEntranceTCP},
		{"sni", failure{probe.StageTLS, probe.OutcomeHandshakeFailed, "handshake_failed"}, StateFailed, FailureEntrance, ReasonEntranceSNI},
		{"certificate", failure{probe.StageTLS, probe.OutcomeCertificateUntrusted, "certificate_untrusted"}, StateFailed, FailureEntrance, ReasonEntranceCertificate},
		{"cover", failure{probe.StageTLS, probe.OutcomeCoverMismatch, "cover_mismatch"}, StateFailed, FailureEntrance, ReasonEntranceCover},
		{"reality", failure{probe.StageAuth, probe.OutcomeHandshakeFailed, "handshake_failed"}, StateFailed, FailureEntrance, ReasonEntranceReality},
		{"transfer", failure{probe.StageTransferSmall, probe.OutcomeSizeMismatch, "size_mismatch"}, StateFailed, FailureExit, ReasonExitTransfer},
		{"throughput", failure{probe.StageThroughput, probe.OutcomeEarlyEOF, "early_eof"}, StateFailed, FailureExit, ReasonExitThroughput},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Date(2026, 11, 17, 12, 10, 0, 0, time.UTC)
			plan := testPlan([]probe.Vantage{
				vantage("ru-wifi", "ru-wifi-net", "in_country"),
				vantage("ru-mobile", "ru-mobile-net", "in_country"),
			}, now)
			fail := tc.fail
			gate := Evaluate(plan, []probe.RunReport{
				buildRun(plan.Vantages[0], now.Add(-time.Minute), testIDs(), testRunID, &fail),
				buildRun(plan.Vantages[1], now.Add(-time.Minute), testIDs(), "fedcba9876543210fedcba9876543210", nil),
			})
			if gate.State != tc.state || gate.Usable || gate.Reason != tc.code || gate.FailureCode != tc.code ||
				gate.FailureClass != tc.class {
				t.Fatalf("gate = %+v", gate)
			}
		})
	}
}

func TestClientSideFailureIsUnknownNotEntrance(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 10, 0, 0, time.UTC)
	plan := testPlan([]probe.Vantage{
		vantage("ru-wifi", "ru-wifi-net", "in_country"),
		vantage("ru-mobile", "ru-mobile-net", "in_country"),
	}, now)
	fail := failure{probe.StageAuth, probe.Outcome("xray_start_failed"), "xray_start_failed"}
	gate := Evaluate(plan, []probe.RunReport{
		buildRun(plan.Vantages[0], now.Add(-time.Minute), testIDs(), testRunID, &fail),
		buildRun(plan.Vantages[1], now.Add(-time.Minute), testIDs(), "fedcba9876543210fedcba9876543210", nil),
	})
	if gate.State != StateUnknown || gate.Usable || gate.Reason != ReasonClientFailure ||
		gate.FailureClass != FailureClient {
		t.Fatalf("gate = %+v", gate)
	}
}

func TestSingleRUVantageFailureIsUncorroboratedUnknown(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 10, 0, 0, time.UTC)
	plan := testPlan([]probe.Vantage{
		vantage("ru-wifi", "ru-wifi-net", "in_country"),
		vantage("outside", "outside-net", "outside"),
	}, now)
	fail := failure{probe.StageTCP, probe.OutcomeTimeout, "timeout"}
	gate := Evaluate(plan, []probe.RunReport{
		buildRun(plan.Vantages[0], now.Add(-time.Minute), testIDs(), testRunID, &fail),
		buildRun(plan.Vantages[1], now.Add(-time.Minute), testIDs(), "fedcba9876543210fedcba9876543210", nil),
	})
	if gate.State != StateUnknown || gate.Usable || gate.Reason != ReasonUncorroboratedFailure {
		t.Fatalf("gate = %+v", gate)
	}
	if gate.Vantages[0].State != StateFailed || gate.Vantages[0].FailureClass != FailureEntrance ||
		gate.Vantages[0].FailureCode != ReasonEntranceTCP {
		t.Fatalf("vantage = %+v", gate.Vantages[0])
	}
}

func TestMissingStaleAndContradictoryEvidence(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 10, 0, 0, time.UTC)
	vantages := []probe.Vantage{
		vantage("ru-wifi", "ru-wifi-net", "in_country"),
		vantage("ru-mobile", "ru-mobile-net", "in_country"),
	}
	t.Run("missing", func(t *testing.T) {
		plan := testPlan(vantages, now)
		gate := Evaluate(plan, []probe.RunReport{
			buildRun(plan.Vantages[0], now.Add(-time.Minute), testIDs(), testRunID, nil),
		})
		if gate.State != StateUnknown || gate.Usable || gate.Reason != ReasonInsufficientEvidence {
			t.Fatalf("gate = %+v", gate)
		}
	})
	t.Run("stale", func(t *testing.T) {
		plan := testPlan(vantages, now)
		gate := Evaluate(plan, []probe.RunReport{
			buildRun(plan.Vantages[0], now.Add(-time.Hour), testIDs(), testRunID, nil),
			buildRun(plan.Vantages[1], now.Add(-time.Hour), testIDs(), "fedcba9876543210fedcba9876543210", nil),
		})
		if gate.State != StateUnknown || gate.Usable || gate.Reason != ReasonInsufficientEvidence {
			t.Fatalf("gate = %+v", gate)
		}
	})
	t.Run("contradictory", func(t *testing.T) {
		plan := testPlan(vantages, now)
		fail := failure{probe.StageTCP, probe.OutcomeTimeout, "timeout"}
		gate := Evaluate(plan, []probe.RunReport{
			buildRun(plan.Vantages[0], now.Add(-2*time.Minute), testIDs(), testRunID, nil),
			buildRun(plan.Vantages[0], now.Add(-time.Minute), testIDs(), "fedcba9876543210fedcba9876543210", &fail),
			buildRun(plan.Vantages[1], now.Add(-time.Minute), testIDs(), "00112233445566778899aabbccddeeff", nil),
		})
		if gate.State != StateUnknown || gate.Usable || gate.Reason != ReasonContradictoryEvidence {
			t.Fatalf("gate = %+v", gate)
		}
	})
}

func TestOutsideFailureDoesNotBlockIndependentRUClean(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 10, 0, 0, time.UTC)
	plan := testPlan([]probe.Vantage{
		vantage("ru-wifi", "ru-wifi-net", "in_country"),
		vantage("ru-mobile", "ru-mobile-net", "in_country"),
		vantage("outside", "outside-net", "outside"),
	}, now)
	fail := failure{probe.StageTCP, probe.OutcomeTimeout, "timeout"}
	gate := Evaluate(plan, []probe.RunReport{
		buildRun(plan.Vantages[0], now.Add(-time.Minute), testIDs(), testRunID, nil),
		buildRun(plan.Vantages[1], now.Add(-time.Minute), testIDs(), "fedcba9876543210fedcba9876543210", nil),
		buildRun(plan.Vantages[2], now.Add(-time.Minute), testIDs(), "00112233445566778899aabbccddeeff", &fail),
	})
	if gate.State != StateClean || !gate.Usable {
		t.Fatalf("gate = %+v", gate)
	}
}

func TestInvalidPlanAndTruncatedQuery(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 10, 0, 0, time.UTC)
	t.Run("invalid", func(t *testing.T) {
		plan := testPlan([]probe.Vantage{vantage("ru-wifi", "net-a", "in_country")}, now)
		plan.EndpointIdentity = "not-a-digest"
		gate := Evaluate(plan, nil)
		if gate.State != StateUnknown || gate.Usable || gate.Reason != ReasonInvalidEvidencePlan {
			t.Fatalf("gate = %+v", gate)
		}
	})
	t.Run("truncated fresh clean still passes", func(t *testing.T) {
		plan := testPlan([]probe.Vantage{
			vantage("ru-wifi", "net-a", "in_country"),
			vantage("ru-mobile", "net-b", "in_country"),
		}, now)
		plan.QueryTruncated = true
		gate := Evaluate(plan, []probe.RunReport{
			buildRun(plan.Vantages[0], now.Add(-time.Minute), testIDs(), testRunID, nil),
			buildRun(plan.Vantages[1], now.Add(-time.Minute), testIDs(), "fedcba9876543210fedcba9876543210", nil),
		})
		if gate.State != StateClean || !gate.Usable || !gate.Scope.QueryTruncated {
			t.Fatalf("gate = %+v", gate)
		}
	})
	t.Run("truncated without evidence is unknown", func(t *testing.T) {
		plan := testPlan([]probe.Vantage{vantage("ru-wifi", "net-a", "in_country")}, now)
		plan.QueryTruncated = true
		gate := Evaluate(plan, nil)
		if gate.State != StateUnknown || gate.Usable || gate.Reason != ReasonInsufficientEvidence {
			t.Fatalf("gate = %+v", gate)
		}
	})
}

func TestSameNetworkVantagesAreNotIndependent(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 10, 0, 0, time.UTC)
	plan := testPlan([]probe.Vantage{
		vantage("ru-wifi", "ru-shared-net", "in_country"),
		vantage("ru-mobile", "ru-shared-net", "in_country"),
	}, now)
	gate := Evaluate(plan, []probe.RunReport{
		buildRun(plan.Vantages[0], now.Add(-time.Minute), testIDs(), testRunID, nil),
		buildRun(plan.Vantages[1], now.Add(-time.Minute), testIDs(), "fedcba9876543210fedcba9876543210", nil),
	})
	if gate.State != StateUnknown || gate.Usable || gate.Reason != ReasonIndependentVantage {
		t.Fatalf("gate = %+v", gate)
	}
}

func TestNewerAcceptedRunSupersedesOlderIncompleteRun(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 10, 0, 0, time.UTC)
	plan := testPlan([]probe.Vantage{
		vantage("ru-wifi", "net-a", "in_country"),
		vantage("ru-mobile", "net-b", "in_country"),
	}, now)
	gate := Evaluate(plan, []probe.RunReport{
		incompleteRun(plan.Vantages[0], now.Add(-2*time.Minute), testIDs(), testRunID),
		buildRun(plan.Vantages[0], now.Add(-time.Minute), testIDs(), testRunID, nil),
		incompleteRun(plan.Vantages[1], now.Add(-2*time.Minute), testIDs(), "fedcba9876543210fedcba9876543210"),
		buildRun(plan.Vantages[1], now.Add(-time.Minute), testIDs(), "fedcba9876543210fedcba9876543210", nil),
	})
	if gate.State != StateClean || !gate.Usable {
		t.Fatalf("gate = %+v", gate)
	}
}

func TestNewerIncompleteRunBlocksOlderClean(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 10, 0, 0, time.UTC)
	plan := testPlan([]probe.Vantage{
		vantage("ru-wifi", "net-a", "in_country"),
		vantage("ru-mobile", "net-b", "in_country"),
	}, now)
	gate := Evaluate(plan, []probe.RunReport{
		buildRun(plan.Vantages[0], now.Add(-2*time.Minute), testIDs(), testRunID, nil),
		incompleteRun(plan.Vantages[0], now.Add(-time.Minute), testIDs(), testRunID),
		buildRun(plan.Vantages[1], now.Add(-2*time.Minute), testIDs(), "fedcba9876543210fedcba9876543210", nil),
		incompleteRun(plan.Vantages[1], now.Add(-time.Minute), testIDs(), "fedcba9876543210fedcba9876543210"),
	})
	if gate.State != StateUnknown || gate.Usable || gate.Reason != ReasonInsufficientEvidence {
		t.Fatalf("gate = %+v", gate)
	}
}

func TestAddressLikeLabelsAreRejected(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 10, 0, 0, time.UTC)
	tests := map[string]func(*probe.DiagnosisPlan){
		"IPv4 target":    func(plan *probe.DiagnosisPlan) { plan.Target = "192.0.2.10" },
		"DNS vantage":    func(plan *probe.DiagnosisPlan) { plan.Vantages[0].Name = "wifi.example.test" },
		"IPv4 network":   func(plan *probe.DiagnosisPlan) { plan.Vantages[0].Network = "192.0.2.0" },
		"IPv6 in target": func(plan *probe.DiagnosisPlan) { plan.Target = "2001:db8::1" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			plan := testPlan([]probe.Vantage{
				vantage("ru-wifi", "net-a", "in_country"),
				vantage("ru-mobile", "net-b", "in_country"),
			}, now)
			mutate(&plan)
			if gate := Evaluate(plan, nil); gate.State != StateUnknown ||
				gate.Usable || gate.Reason != ReasonInvalidEvidencePlan {
				t.Fatalf("gate = %+v", gate)
			}
		})
	}
}

func incompleteRun(v probe.Vantage, at time.Time, ident ids, runID string) probe.RunReport {
	report := buildRun(v, at, ident, runID, nil)
	report.Events = report.Events[:2]
	report.Complete = false
	return report
}

func TestPersistedGateRecordIsScopedByLabelOnly(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	database, err := store.Open(ctx, filepath.Join(directory, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	now := time.Date(2026, 11, 17, 12, 10, 0, 0, time.UTC)
	plan := testPlan([]probe.Vantage{
		vantage("ru-wifi", "ru-wifi-net", "in_country"),
		vantage("ru-mobile", "ru-mobile-net", "in_country"),
	}, now)
	gate := Evaluate(plan, []probe.RunReport{
		buildRun(plan.Vantages[0], now.Add(-time.Minute), testIDs(), testRunID, nil),
		buildRun(plan.Vantages[1], now.Add(-time.Minute), testIDs(), "fedcba9876543210fedcba9876543210", nil),
	})
	if err := AppendGate(ctx, database, gate); err != nil {
		t.Fatal(err)
	}
	records, err := database.LatestProbes(ctx, testTarget, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %+v", records)
	}
	record := records[0]
	if record.Stage != StageGate || record.Outcome != store.OutcomeSuccess || record.ErrorCode != "" {
		t.Fatalf("record = %+v", record)
	}
	if record.RunID != "" || record.Vantage != "" || record.Network != "" || record.VantageKind != "" ||
		record.Scope != "" || record.EndpointIdentity != "" || record.ConfigIdentity != "" || record.SNIIdentity != "" {
		t.Fatalf("gate marker leaked ladder scope: %+v", record)
	}
	// Gate decisions are not ladder evidence and must not be replayed as runs.
	runs, truncated, err := probe.ReadRuns(ctx, database, testTarget)
	if err != nil || truncated {
		t.Fatalf("read runs: %v, truncated=%t", err, truncated)
	}
	if len(runs) != 0 {
		t.Fatalf("gate marker was replayed as ladder evidence: %+v", runs)
	}
}

func TestPersistedGateRecordKeepsFailureCodeAndNoSecrets(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	now := time.Date(2026, 11, 17, 12, 10, 0, 0, time.UTC)
	plan := testPlan([]probe.Vantage{
		vantage("ru-wifi", "ru-wifi-net", "in_country"),
		vantage("ru-mobile", "ru-mobile-net", "in_country"),
	}, now)
	fail := failure{probe.StageTLS, probe.OutcomeHandshakeFailed, "handshake_failed"}
	gate := Evaluate(plan, []probe.RunReport{
		buildRun(plan.Vantages[0], now.Add(-time.Minute), testIDs(), testRunID, &fail),
		buildRun(plan.Vantages[1], now.Add(-time.Minute), testIDs(), "fedcba9876543210fedcba9876543210", nil),
	})
	if err := AppendGate(ctx, database, gate); err != nil {
		t.Fatal(err)
	}
	records, err := database.LatestProbes(ctx, testTarget, 10)
	if err != nil || len(records) != 1 {
		t.Fatalf("records = %+v, err = %v", records, err)
	}
	record := records[0]
	if record.Outcome != store.OutcomeFailure || record.ErrorCode != ReasonEntranceSNI {
		t.Fatalf("record = %+v", record)
	}
	serialized := strings.Join([]string{record.Target, record.Stage, record.ErrorCode,
		record.Vantage, record.Network, record.RunID, record.EndpointIdentity}, "|")
	for _, unsafe := range []string{"192.0.2", "cover.example", "http://", "client.json"} {
		if strings.Contains(serialized, unsafe) {
			t.Fatalf("persisted gate record contains %q: %q", unsafe, serialized)
		}
	}
}
