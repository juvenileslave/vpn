package probe

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/juvenileslave/vpn/vpnctl/internal/globalping"
	"github.com/juvenileslave/vpn/vpnctl/internal/store"
)

func testDatabase(t *testing.T) *store.Store {
	t.Helper()
	database, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	return database
}

func TestPersistedRunsRetainClassificationAndFamilyIsolation(t *testing.T) {
	plan, database := testPlan(), testDatabase(t)
	inside, outside := testRun(plan, 0), testRun(plan, 1)
	failStage(&inside, StageTCP, OutcomeTimeout, 0)
	for _, report := range []*RunReport{&inside, &outside} {
		if err := AppendRun(context.Background(), database, report); err != nil {
			t.Fatal(err)
		}
	}
	runs, truncated, err := ReadRuns(context.Background(), database, plan.Target)
	if err != nil {
		t.Fatal(err)
	}
	plan.QueryTruncated = truncated
	if verdict := Classify(plan, runs); verdict.Verdict != "ip_block" {
		t.Fatalf("persisted diagnosis = %+v", verdict)
	}
	plan.Family = IPv6
	if verdict := Classify(plan, runs); verdict.Verdict != "unknown" || len(verdict.Scope.Vantages) != 0 {
		t.Fatalf("IPv4 rows contaminated IPv6 diagnosis: %+v", verdict)
	}
}

func TestPartialOrMixedContextStoredRunCannotBecomeControl(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		t.Run(strings.Join([]string{"mixed", map[bool]string{true: "true", false: "false"}[mixed]}, "-"), func(t *testing.T) {
			plan, database := testPlan(), testDatabase(t)
			inside, outside := testRun(plan, 0), testRun(plan, 1)
			failStage(&inside, StageTCP, OutcomeTimeout, 0)
			if err := AppendRun(context.Background(), database, &inside); err != nil {
				t.Fatal(err)
			}
			if !mixed {
				outside.Events = outside.Events[:1]
			}
			for index, event := range outside.Events {
				identity := plan.ConfigIdentity
				if mixed && index == 2 {
					identity = strings.Repeat("f", 64)
				}
				_, err := database.AppendProbe(context.Background(), store.ProbeRecord{
					Target: plan.Target, Stage: string(event.Stage), Family: store.FamilyIPv4, Outcome: store.OutcomeSuccess,
					ObservedAt: event.ObservedAt, Duration: event.Duration, Bytes: event.Bytes, ExpectedBytes: event.ExpectedBytes,
					BodyDuration: event.BodyDuration, ThroughputFloor: plan.ThroughputFloor,
					RunID: outside.RunID, Vantage: outside.Vantage.Name, Network: outside.Vantage.Network,
					VantageKind: outside.Vantage.Kind, Scope: "node_path", EndpointIdentity: plan.EndpointIdentity,
					ConfigIdentity: identity, SNIIdentity: plan.SNIIdentity,
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			runs, _, err := ReadRuns(context.Background(), database, plan.Target)
			if err != nil {
				t.Fatal(err)
			}
			if verdict := Classify(plan, runs); verdict.Verdict != "unknown" {
				t.Fatalf("unsafe control = %+v", verdict)
			}
		})
	}
}

func TestGlobalpingRetainsHTTPOnlyScopeAndRedactsCertificateText(t *testing.T) {
	request, database := fixtureRequest(t), testDatabase(t)
	input := GlobalpingInput{Port: request.Target.Port, Family: IPv4, Measurement: globalping.Measurement{
		Target: request.Target.Address.String(), Status: globalping.StatusFinished, UpdatedAt: time.Now().Add(-time.Second),
		Results: []globalping.Result{{Probe: globalping.Probe{ASN: 64500, Country: "RU", Network: "private-value-canary"},
			HTTP: globalping.HTTPResult{Status: globalping.TestFinished, StatusCode: 200,
				ResolvedAddress: request.Target.Address.String(), Timings: &globalping.HTTPTimings{Total: time.Second},
				TLS: &globalping.TLSInfo{Authorized: true, IssuerCN: "private-value-canary", SubjectCN: "private-value-canary"}}}},
	}}
	path := privateFixture(t, "globalping.json", input)
	count, err := AppendGlobalping(context.Background(), database, request, path)
	if err != nil || count != 1 {
		t.Fatalf("HTTP import = %d, %v", count, err)
	}
	records, err := database.LatestProbes(context.Background(), request.Node, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Stage != "globalping_http" || records[0].Scope != "external_http" || records[0].VantageKind != "external_http" {
		t.Fatalf("HTTP evidence scope = %+v", records)
	}
	runs, _, err := ReadRuns(context.Background(), database, request.Node)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 0 {
		t.Fatal("Globalping HTTP became an authorized ladder")
	}
	if strings.Contains(records[0].Network, "private-value-canary") || strings.Contains(records[0].ErrorCode, "private-value-canary") {
		t.Fatal("untrusted network/certificate text persisted")
	}
}

func TestAppendRunCannotPersistUnverifiedTransferAsSuccess(t *testing.T) {
	plan, database := testPlan(), testDatabase(t)
	report := testRun(plan, 0)
	report.Events[2].Integrity = false
	if err := AppendRun(context.Background(), database, &report); err == nil {
		t.Fatal("unverified auth response persisted as success")
	}
	runs, _, err := ReadRuns(context.Background(), database, plan.Target)
	if err != nil {
		t.Fatal(err)
	}
	if verdict := Classify(plan, runs); verdict.Verdict != "unknown" {
		t.Fatalf("partial append became success: %+v", verdict)
	}
}
