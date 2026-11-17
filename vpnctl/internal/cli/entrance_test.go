package cli

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/juvenileslave/vpn/vpnctl/internal/entrance"
	"github.com/juvenileslave/vpn/vpnctl/internal/probe"
	"github.com/juvenileslave/vpn/vpnctl/internal/store"
)

func TestEntranceGateEmptyStoreIsUnknownAndSecretFree(t *testing.T) {
	inputs, database := diagnosisInputs(t)
	for _, format := range []string{"text", "json"} {
		t.Run(format, func(t *testing.T) {
			code, stdout, stderr := run("entrance", "gate", "--node", "exit-test",
				"--inputs", inputs, "--store", database, "--format", format)
			if code != ExitInsufficient {
				t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
			}
			if format == "json" {
				var output entranceOutput
				if err := json.Unmarshal([]byte(stdout), &output); err != nil {
					t.Fatal(err)
				}
				if output.Gate == nil || output.Gate.State != entrance.StateUnknown ||
					output.Gate.Usable || len(output.Gate.MissingEvidence) == 0 {
					t.Fatalf("output = %+v", output.Gate)
				}
			}
			if strings.Contains(stdout+stderr, "192.0.2") ||
				strings.Contains(stdout+stderr, "cover.example") {
				t.Fatalf("gate output leaked identifiers: %q %q", stdout, stderr)
			}
		})
	}
}

func TestEntranceGatePersistsDecisionMarker(t *testing.T) {
	inputs, database := diagnosisInputs(t)
	code, _, stderr := run("entrance", "gate", "--node", "exit-test",
		"--inputs", inputs, "--store", database, "--json")
	if code != ExitInsufficient {
		t.Fatalf("code = %d, stderr = %q", code, stderr)
	}
	ctx := context.Background()
	databaseStore, err := store.Open(ctx, database)
	if err != nil {
		t.Fatal(err)
	}
	defer databaseStore.Close()
	records, err := databaseStore.LatestProbes(ctx, "exit-test", 10)
	if err != nil || len(records) != 1 {
		t.Fatalf("records = %+v, err = %v", records, err)
	}
	if records[0].Stage != entrance.StageGate || records[0].Outcome != store.OutcomeFailure ||
		records[0].ErrorCode != entrance.ReasonInsufficientEvidence {
		t.Fatalf("record = %+v", records[0])
	}
}

func TestEntranceGateUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"entrance"},
		{"entrance", "gate"},
		{"entrance", "gate", "--node", "exit-test"},
		{"entrance", "gate", "--node", "exit-test", "--store", "x", "--inputs", "y", "--family", "ipx"},
		{"entrance", "gate", "--node", "exit-test", "--store", "x", "--inputs", "y", "--format", "xml"},
	} {
		if code, _, _ := run(args...); code != ExitUsage {
			t.Fatalf("%q = %d", args, code)
		}
	}
}

func TestEntranceRotationPlanRequiresConfirmation(t *testing.T) {
	directory := t.TempDir()
	database := filepath.Join(directory, "state.db")
	args := []string{"entrance", "rotation", "plan", "--node", "exit-test", "--provider", "hetzner",
		"--current", "entrance-a", "--candidate", "entrance-b", "--store", database, "--json"}
	code, stdout, stderr := run(args...)
	if code != ExitRefused {
		t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
	var output entranceOutput
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatal(err)
	}
	if output.Rotation == nil || output.Rotation.State != entrance.RotationRefused ||
		output.Rotation.Mutation != "provider_write_not_implemented" || len(output.Rotation.Rollback) == 0 {
		t.Fatalf("rotation = %+v", output.Rotation)
	}
	if strings.Contains(stdout+stderr, "entrance-a") || strings.Contains(stdout+stderr, "entrance-b") {
		t.Fatalf("rotation output echoed labels: %q", stdout)
	}

	code, stdout, stderr = run(append(args, "--confirm")...)
	if code != ExitOK {
		t.Fatalf("confirmed code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatal(err)
	}
	if output.Rotation == nil || output.Rotation.State != entrance.RotationReady {
		t.Fatalf("confirmed rotation = %+v", output.Rotation)
	}
	mutationRefused := false
	for _, step := range output.Rotation.Steps {
		if step.Kind == "mutation" && step.Status == entrance.StepRefused {
			mutationRefused = true
		}
	}
	if !mutationRefused {
		t.Fatalf("confirmed plan does not refuse mutation: %+v", output.Rotation.Steps)
	}

	ctx := context.Background()
	databaseStore, err := store.Open(ctx, database)
	if err != nil {
		t.Fatal(err)
	}
	defer databaseStore.Close()
	records, err := databaseStore.LatestProbes(ctx, "exit-test", 10)
	if err != nil || len(records) != 2 {
		t.Fatalf("records = %+v, err = %v", records, err)
	}
	for _, record := range records {
		if record.Stage != entrance.StageRotationPlan {
			t.Fatalf("record = %+v", record)
		}
	}
}

func TestEntranceRotationRejectsAddressLikeLabels(t *testing.T) {
	directory := t.TempDir()
	code, stdout, stderr := run("entrance", "rotation", "plan", "--node", "exit-test",
		"--provider", "hetzner", "--current", "192.0.2.10", "--candidate", "entrance-b",
		"--store", filepath.Join(directory, "state.db"), "--json")
	if code != ExitError {
		t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
	var output entranceOutput
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatal(err)
	}
	if output.ErrorCode != "rotation_invalid" {
		t.Fatalf("output = %+v", output)
	}
	if strings.Contains(stdout+stderr, "192.0.2.10") {
		t.Fatalf("invalid label was echoed: %q %q", stdout, stderr)
	}
}

// entranceInputs declares two independent in-country vantages plus one outside
// control. It is a separate fixture from diagnosisInputs because the gate must
// be proven clean from two in-country networks, not from the single network
// used by the scoped diagnosis tests.
func entranceInputs(t *testing.T) (string, string) {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	endpoint := probe.Endpoint{Address: netip.MustParseAddr("192.0.2.100"), Port: 18081,
		URL: "http://payload.example.test/fixture", SHA256: strings.Repeat("a", 64)}
	auth, small, large := endpoint, endpoint, endpoint
	auth.Bytes, small.Bytes, large.Bytes = 256, probe.SmallBytes, probe.LargeBytes
	inputs := probe.Inputs{Schema: 1, LocalVantage: "ru-wifi", Vantages: []probe.Vantage{
		{Name: "ru-wifi", Network: "ru-wifi-net", Kind: "in_country"},
		{Name: "ru-mobile", Network: "ru-mobile-net", Kind: "in_country"},
		{Name: "outside", Network: "outside-net", Kind: "outside"}},
		Nodes: []probe.NodeInput{{Name: "exit-test", IPv4: "192.0.2.10", Port: 18443, ServerName: "cover.example.test",
			ProfileFile: filepath.Join(directory, "client.json"), Endpoints: probe.Endpoints{Auth: auth, Small: small, Large: large}}},
		Budgets:         probe.BudgetInput{Overall: "30s", Setup: "1s", TCP: "1s", TLS: "1s", Auth: "3s", Small: "5s", Large: "10s", Control: "1s"},
		ThroughputFloor: 1 << 20, EvidenceWindow: "10m"}
	data, err := json.Marshal(inputs)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "inputs.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, filepath.Join(directory, "state.db")
}

func entranceTestPlan(t *testing.T, inputsPath string, now time.Time) probe.DiagnosisPlan {
	t.Helper()
	inputs, err := probe.LoadInputs(inputsPath)
	if err != nil {
		t.Fatal(err)
	}
	request, err := inputs.Diagnose("exit-test", probe.IPv4, "")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := inputs.DiagnosisPlan(request, now)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

// gateRun records one accepted five-stage attempt. An empty failStage means
// every stage succeeded; otherwise the failing stage stops the ladder and the
// remaining stages are explicitly skipped.
func gateRun(plan probe.DiagnosisPlan, vantage probe.Vantage, runID string, at time.Time, failStage probe.Stage) probe.RunReport {
	report := probe.RunReport{
		Schema:           1,
		RunID:            runID,
		Target:           plan.Target,
		Family:           plan.Family,
		Vantage:          vantage,
		EndpointIdentity: plan.EndpointIdentity,
		ConfigIdentity:   plan.ConfigIdentity,
		SNIIdentity:      plan.SNIIdentity,
		ThroughputFloor:  plan.ThroughputFloor,
		Complete:         true,
		Outcome:          "success",
		Events:           make([]probe.Event, 0, 5),
	}
	start := at
	var previousEnd time.Time
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
			event.Duration, event.BodyDuration, event.Bytes, event.ExpectedBytes = 0, 0, 0, 0
			event.Integrity = false
		} else if failStage == stage {
			event.Outcome, event.ErrorCode = probe.OutcomeTimeout, "timeout"
			event.Bytes, event.ExpectedBytes, event.Integrity, event.BodyDuration = 0, 0, false, 0
			report.Outcome, report.ErrorCode = "failure", "timeout"
			blocked = true
		}
		event.Target, event.Family, event.Vantage = plan.Target, plan.Family, vantage
		event.Scope = "node_path"
		event.ObservedAt = start
		if !previousEnd.IsZero() && event.ObservedAt.Before(previousEnd) {
			event.ObservedAt = previousEnd
		}
		previousEnd = event.ObservedAt.Add(event.Duration)
		start = previousEnd
		report.Events = append(report.Events, event)
	}
	return report
}

func seedGateRuns(t *testing.T, database string, plan probe.DiagnosisPlan, at time.Time, failVantage string, failStage probe.Stage) {
	t.Helper()
	ctx := context.Background()
	databaseStore, err := store.Open(ctx, database)
	if err != nil {
		t.Fatal(err)
	}
	defer databaseStore.Close()
	for index, vantage := range plan.Vantages {
		if vantage.Kind != "in_country" {
			continue
		}
		stage := probe.Stage("")
		if vantage.Name == failVantage {
			stage = failStage
		}
		report := gateRun(plan, vantage, strings.Repeat(string(rune('a'+index)), 32), at, stage)
		if err := probe.AppendRun(ctx, databaseStore, &report); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEntranceGateCleanEvidenceIsUsable(t *testing.T) {
	inputsPath, database := entranceInputs(t)
	plan := entranceTestPlan(t, inputsPath, time.Now().UTC())
	seedGateRuns(t, database, plan, time.Now().UTC().Add(-time.Minute), "", "")
	code, stdout, stderr := run("entrance", "gate", "--node", "exit-test",
		"--inputs", inputsPath, "--store", database, "--json")
	if code != ExitOK {
		t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
	var output entranceOutput
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatal(err)
	}
	if output.Gate == nil || output.Gate.State != entrance.StateClean || !output.Gate.Usable ||
		output.Gate.Scope.IndependentRUNetworks != 2 || !output.Gate.Scope.RUVantageVerified {
		t.Fatalf("gate = %+v", output.Gate)
	}
	if strings.Contains(stdout+stderr, "192.0.2") || strings.Contains(stdout+stderr, "cover.example") {
		t.Fatalf("gate output leaked identifiers: %q %q", stdout, stderr)
	}
}

func TestEntranceGateEntranceFailureBlocksPublication(t *testing.T) {
	inputsPath, database := entranceInputs(t)
	plan := entranceTestPlan(t, inputsPath, time.Now().UTC())
	seedGateRuns(t, database, plan, time.Now().UTC().Add(-time.Minute), "ru-wifi", probe.StageTCP)
	code, stdout, stderr := run("entrance", "gate", "--node", "exit-test",
		"--inputs", inputsPath, "--store", database, "--json")
	if code != ExitProbeFailure {
		t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
	var output entranceOutput
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatal(err)
	}
	if output.Gate == nil || output.Gate.State != entrance.StateFailed || output.Gate.Usable ||
		output.Gate.FailureClass != entrance.FailureEntrance || output.Gate.FailureCode != entrance.ReasonEntranceTCP {
		t.Fatalf("gate = %+v", output.Gate)
	}
}

func TestEntranceGateExitCodeMapping(t *testing.T) {
	cases := map[entrance.State]int{
		entrance.StateClean:   ExitOK,
		entrance.StateUnknown: ExitInsufficient,
		entrance.StateFailed:  ExitProbeFailure,
	}
	for state, want := range cases {
		if code := entranceExitCode(state); code != want {
			t.Fatalf("state %q = %d, want %d", state, code, want)
		}
	}
}
