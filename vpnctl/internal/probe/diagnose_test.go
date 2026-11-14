package probe

import (
	"strings"
	"testing"
	"time"
)

var diagnosisNow = time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)

func testPlan() DiagnosisPlan {
	return DiagnosisPlan{
		Target: "exit-test", Family: IPv4, EndpointIdentity: identity("endpoint"),
		ConfigIdentity: identity("contract"), SNIIdentity: identity("target-sni"), ControlIdentity: identity("control-sni"),
		Vantages: []Vantage{{Name: "inside", Network: "synthetic-a", Kind: "in_country"},
			{Name: "outside", Network: "synthetic-b", Kind: "outside"}},
		Now: diagnosisNow, Window: 10 * time.Minute, ThroughputFloor: 1 << 20,
	}
}

func testRun(plan DiagnosisPlan, index int) RunReport {
	vantage := plan.Vantages[index]
	run := RunReport{
		Schema: 1, RunID: strings.Repeat(string(rune('a'+index)), 32), Target: plan.Target, Family: plan.Family,
		Vantage: vantage, EndpointIdentity: plan.EndpointIdentity, ConfigIdentity: plan.ConfigIdentity,
		SNIIdentity: plan.SNIIdentity, ControlIdentity: plan.ControlIdentity, ThroughputFloor: plan.ThroughputFloor,
		Complete: true, Events: make([]Event, 0, 6),
	}
	for index, stage := range ladderStages {
		event := Event{
			Target: plan.Target, Vantage: vantage, Family: plan.Family, Scope: "node_path", Stage: stage,
			Outcome: OutcomeSuccess, ObservedAt: plan.Now.Add(time.Duration(index-60) * time.Second), Duration: time.Second,
		}
		if index >= 2 {
			event.ExpectedBytes = 256
			if stage == StageTransferSmall {
				event.ExpectedBytes = SmallBytes
			}
			if stage == StageThroughput {
				event.ExpectedBytes = LargeBytes
			}
			event.Bytes, event.BodyDuration, event.Integrity = event.ExpectedBytes, 100*time.Millisecond, true
		}
		run.Events = append(run.Events, event)
	}
	return run
}

func failStage(run *RunReport, stage Stage, outcome Outcome, bytes int64) {
	failed := false
	for index := range run.Events {
		event := &run.Events[index]
		if failed {
			event.Outcome, event.ErrorCode, event.Bytes, event.Duration, event.BodyDuration, event.Integrity =
				OutcomeSkipped, "stage_not_run", 0, 0, 0, false
		}
		if event.Stage == stage {
			event.Outcome, event.ErrorCode, event.Bytes, event.Integrity = outcome, string(outcome), bytes, false
			failed = true
		}
	}
}

func controlTLS(run *RunReport, outcome Outcome) {
	event := Event{
		Target: run.Target, Vantage: run.Vantage, Family: run.Family, Scope: "same_address_control", Stage: StageControlTLS,
		Outcome: outcome, ObservedAt: diagnosisNow.Add(-50 * time.Second), Duration: time.Second,
	}
	if outcome != OutcomeSuccess {
		event.ErrorCode = string(outcome)
	}
	run.Events = append(run.Events, event)
}

func TestClassifierConservativeTruthTable(t *testing.T) {
	tests := []struct {
		name    string
		change  func(*DiagnosisPlan, *[]RunReport)
		verdict string
	}{
		{name: "healthy is not a block", verdict: "unknown"},
		{name: "ip timeout with outside control", verdict: "ip_block", change: func(_ *DiagnosisPlan, runs *[]RunReport) {
			failStage(&(*runs)[0], StageTCP, OutcomeTimeout, 0)
		}},
		{name: "single vantage timeout", verdict: "unknown", change: func(plan *DiagnosisPlan, runs *[]RunReport) {
			plan.Vantages = plan.Vantages[:1]
			*runs = (*runs)[:1]
			failStage(&(*runs)[0], StageTCP, OutcomeTimeout, 0)
		}},
		{name: "missing outside", verdict: "unknown", change: func(_ *DiagnosisPlan, runs *[]RunReport) {
			*runs = (*runs)[:1]
			failStage(&(*runs)[0], StageTCP, OutcomeTimeout, 0)
		}},
		{name: "two names same network", verdict: "unknown", change: func(plan *DiagnosisPlan, runs *[]RunReport) {
			plan.Vantages[1].Network = plan.Vantages[0].Network
			(*runs)[1] = testRun(*plan, 1)
			failStage(&(*runs)[0], StageTCP, OutcomeTimeout, 0)
		}},
		{name: "outside shares the timed out network despite another dc", verdict: "unknown", change: func(plan *DiagnosisPlan, runs *[]RunReport) {
			plan.Vantages[1].Network = plan.Vantages[0].Network
			plan.Vantages = append(plan.Vantages, Vantage{Name: "dc", Network: "synthetic-c", Kind: "local_dc"})
			(*runs)[1] = testRun(*plan, 1)
			*runs = append(*runs, testRun(*plan, 2))
			failStage(&(*runs)[0], StageTCP, OutcomeTimeout, 0)
		}},
		{name: "outside tcp alone is partial", verdict: "unknown", change: func(_ *DiagnosisPlan, runs *[]RunReport) {
			failStage(&(*runs)[0], StageTCP, OutcomeTimeout, 0)
			(*runs)[1].Events = (*runs)[1].Events[:1]
			(*runs)[1].Complete = false
		}},
		{name: "outside auth failure contradicts ip hypothesis", verdict: "unknown", change: func(_ *DiagnosisPlan, runs *[]RunReport) {
			failStage(&(*runs)[0], StageTCP, OutcomeTimeout, 0)
			failStage(&(*runs)[1], StageAuth, OutcomeAuthFailed, 0)
		}},
		{name: "sni with same address verified control", verdict: "sni_filter", change: func(_ *DiagnosisPlan, runs *[]RunReport) {
			failStage(&(*runs)[0], StageTLS, OutcomeHandshakeFailed, 0)
			controlTLS(&(*runs)[0], OutcomeSuccess)
		}},
		{name: "sni without explicit control", verdict: "unknown", change: func(plan *DiagnosisPlan, runs *[]RunReport) {
			plan.ControlIdentity = ""
			failStage(&(*runs)[0], StageTLS, OutcomeHandshakeFailed, 0)
		}},
		{name: "failed control", verdict: "unknown", change: func(_ *DiagnosisPlan, runs *[]RunReport) {
			failStage(&(*runs)[0], StageTLS, OutcomeTimeout, 0)
			controlTLS(&(*runs)[0], OutcomeHandshakeFailed)
		}},
		{name: "different control identity", verdict: "unknown", change: func(_ *DiagnosisPlan, runs *[]RunReport) {
			failStage(&(*runs)[0], StageTLS, OutcomeTimeout, 0)
			controlTLS(&(*runs)[0], OutcomeSuccess)
			(*runs)[0].ControlIdentity = identity("other")
		}},
		{name: "control contradicts its verification fact", verdict: "unknown", change: func(_ *DiagnosisPlan, runs *[]RunReport) {
			failStage(&(*runs)[0], StageTLS, OutcomeTimeout, 0)
			controlTLS(&(*runs)[0], OutcomeSuccess)
			(*runs)[0].Events[5].Certificate = &Certificate{Verified: false, SANMatch: true}
		}},
		{name: "wrong certificate is not sni filter", verdict: "unknown", change: func(_ *DiagnosisPlan, runs *[]RunReport) {
			failStage(&(*runs)[0], StageTLS, OutcomeHostnameMismatch, 0)
			controlTLS(&(*runs)[0], OutcomeSuccess)
		}},
		{name: "cover identity mismatch is not a block", verdict: "unknown", change: func(_ *DiagnosisPlan, runs *[]RunReport) {
			failStage(&(*runs)[0], StageTLS, OutcomeCoverMismatch, 0)
		}},
		{name: "authenticated measured 17 kib close", verdict: "dpi_stream_stall", change: func(_ *DiagnosisPlan, runs *[]RunReport) {
			failStage(&(*runs)[0], StageThroughput, OutcomeEarlyEOF, 17<<10)
		}},
		{name: "boundary timeout is not measured close", verdict: "unknown", change: func(_ *DiagnosisPlan, runs *[]RunReport) {
			failStage(&(*runs)[0], StageThroughput, OutcomeTimeout, 17<<10)
		}},
		{name: "stream close outside boundary", verdict: "unknown", change: func(_ *DiagnosisPlan, runs *[]RunReport) {
			failStage(&(*runs)[0], StageThroughput, OutcomeEarlyEOF, 21<<10)
		}},
		{name: "handshake without complete small transfer", verdict: "unknown", change: func(_ *DiagnosisPlan, runs *[]RunReport) {
			failStage(&(*runs)[0], StageTransferSmall, OutcomeEarlyEOF, 17<<10)
		}},
		{name: "wrong uuid never a tcp block", verdict: "unknown", change: func(_ *DiagnosisPlan, runs *[]RunReport) {
			failStage(&(*runs)[0], StageAuth, OutcomeAuthFailed, 0)
		}},
		{name: "measured low complete throughput", verdict: "throttling", change: func(plan *DiagnosisPlan, runs *[]RunReport) {
			event := &(*runs)[0].Events[4]
			event.Duration, event.BodyDuration = time.Second, time.Second
			planFloor := int64(40 << 20)
			for index := range *runs {
				(*runs)[index].ThroughputFloor = planFloor
			}
			plan.ThroughputFloor = planFloor
		}},
		{name: "zero throughput duration", verdict: "unknown", change: func(_ *DiagnosisPlan, runs *[]RunReport) {
			(*runs)[0].Events[4].BodyDuration = 0
		}},
		{name: "size mismatch is not throttling", verdict: "unknown", change: func(_ *DiagnosisPlan, runs *[]RunReport) {
			failStage(&(*runs)[0], StageThroughput, OutcomeSizeMismatch, LargeBytes-1)
		}},
		{name: "integrity mismatch is not throttling", verdict: "unknown", change: func(_ *DiagnosisPlan, runs *[]RunReport) {
			failStage(&(*runs)[0], StageThroughput, OutcomeIntegrityMismatch, LargeBytes)
		}},
		{name: "all independent tcp fail", verdict: "node_outage", change: func(_ *DiagnosisPlan, runs *[]RunReport) {
			for index := range *runs {
				failStage(&(*runs)[index], StageTCP, OutcomeRefused, 0)
			}
		}},
		{name: "all tls fail but control alive is sni not outage", verdict: "sni_filter", change: func(_ *DiagnosisPlan, runs *[]RunReport) {
			for index := range *runs {
				failStage(&(*runs)[index], StageTLS, OutcomeTimeout, 0)
				controlTLS(&(*runs)[index], OutcomeSuccess)
			}
		}},
		{name: "all fail without outside", verdict: "unknown", change: func(plan *DiagnosisPlan, runs *[]RunReport) {
			plan.Vantages[1].Kind = "local_dc"
			(*runs)[1] = testRun(*plan, 1)
			for index := range *runs {
				failStage(&(*runs)[index], StageTCP, OutcomeRefused, 0)
			}
		}},
		{name: "ipv4 outside is not ipv6 control", verdict: "unknown", change: func(_ *DiagnosisPlan, runs *[]RunReport) {
			failStage(&(*runs)[0], StageTCP, OutcomeTimeout, 0)
			(*runs)[1].Family = IPv6
		}},
		{name: "different endpoint is not control", verdict: "unknown", change: func(_ *DiagnosisPlan, runs *[]RunReport) {
			failStage(&(*runs)[0], StageTCP, OutcomeTimeout, 0)
			(*runs)[1].EndpointIdentity = identity("other")
		}},
		{name: "different transfer endpoint contract", verdict: "unknown", change: func(_ *DiagnosisPlan, runs *[]RunReport) {
			failStage(&(*runs)[0], StageTCP, OutcomeTimeout, 0)
			(*runs)[1].ConfigIdentity = identity("other")
		}},
		{name: "stale outside", verdict: "unknown", change: func(_ *DiagnosisPlan, runs *[]RunReport) {
			failStage(&(*runs)[0], StageTCP, OutcomeTimeout, 0)
			for index := range (*runs)[1].Events {
				(*runs)[1].Events[index].ObservedAt = diagnosisNow.Add(-time.Hour)
			}
		}},
		{name: "future outside", verdict: "unknown", change: func(_ *DiagnosisPlan, runs *[]RunReport) {
			(*runs)[1].Events[4].ObservedAt = diagnosisNow.Add(time.Hour)
		}},
		{name: "contradictory contemporaneous run", verdict: "unknown", change: func(_ *DiagnosisPlan, runs *[]RunReport) {
			older := testRun(testPlan(), 0)
			older.RunID = strings.Repeat("f", 32)
			failStage(&(*runs)[0], StageTCP, OutcomeTimeout, 0)
			*runs = append(*runs, older)
		}},
		{name: "stage after failed authentication is false success", verdict: "unknown", change: func(_ *DiagnosisPlan, runs *[]RunReport) {
			(*runs)[0].Events[2].Outcome, (*runs)[0].Events[2].ErrorCode = OutcomeAuthFailed, "auth_failed"
		}},
		{name: "duplicate stage", verdict: "unknown", change: func(_ *DiagnosisPlan, runs *[]RunReport) {
			(*runs)[0].Events = append((*runs)[0].Events, (*runs)[0].Events[0])
		}},
		{name: "globalping http cannot stand in for auth", verdict: "unknown", change: func(_ *DiagnosisPlan, runs *[]RunReport) {
			(*runs)[1].Events[2].Scope = "external_http"
		}},
		{name: "query limit is incomplete evidence", verdict: "unknown", change: func(plan *DiagnosisPlan, _ *[]RunReport) { plan.QueryTruncated = true }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := testPlan()
			runs := []RunReport{testRun(plan, 0), testRun(plan, 1)}
			if test.change != nil {
				test.change(&plan, &runs)
			}
			verdict := Classify(plan, runs)
			if verdict.Verdict != test.verdict {
				t.Fatalf("got %+v; want %s", verdict, test.verdict)
			}
			if verdict.Scope.Global {
				t.Fatal("single evidence set emitted a global claim")
			}
			if verdict.MissingEvidence == nil {
				t.Fatal("missing evidence omitted")
			}
			if test.verdict == "unknown" && (verdict.Outcome != "insufficient_evidence" || len(verdict.MissingEvidence) == 0) {
				t.Fatalf("unknown lacks insufficient-evidence outcome: %+v", verdict)
			}
			if test.verdict != "unknown" && (verdict.Confidence != "moderate" || len(verdict.MissingEvidence) != 0) {
				t.Fatalf("unsupported confidence/evidence contract: %+v", verdict)
			}
		})
	}
}
