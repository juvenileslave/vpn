package cli

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/juvenileslave/vpn/vpnctl/internal/probe"
)

func diagnosisInputs(t *testing.T) (string, string) {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	endpoint := probe.Endpoint{Address: netip.MustParseAddr("192.0.2.100"), Port: 18081,
		URL: "http://payload.example.test/fixture", SHA256: strings.Repeat("a", 64)}
	auth, small, large := endpoint, endpoint, endpoint
	auth.Bytes, small.Bytes, large.Bytes = 256, probe.SmallBytes, probe.LargeBytes
	inputs := probe.Inputs{Schema: 1, LocalVantage: "inside", Vantages: []probe.Vantage{
		{Name: "inside", Network: "synthetic-a", Kind: "in_country"}, {Name: "outside", Network: "synthetic-b", Kind: "outside"}},
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

func TestDiagnoseEmptyStoreIsExplicitlyInsufficientTextAndJSON(t *testing.T) {
	for _, format := range []string{"text", "json"} {
		t.Run(format, func(t *testing.T) {
			inputs, database := diagnosisInputs(t)
			code, stdout, stderr := run("diagnose", "--node", "exit-test", "--inputs", inputs, "--store", database, "--format", format)
			if code != ExitInsufficient || stderr != "" {
				t.Fatalf("diagnose = %d, %q, %q", code, stdout, stderr)
			}
			if format == "json" {
				var output probeOutput
				if err := json.Unmarshal([]byte(stdout), &output); err != nil {
					t.Fatal(err)
				}
				if output.Diagnosis == nil || output.Diagnosis.Verdict != "unknown" || output.Diagnosis.Scope.Global ||
					len(output.Diagnosis.MissingEvidence) != 2 || output.Diagnosis.Outcome != "insufficient_evidence" {
					t.Fatalf("insufficient evidence = %+v", output.Diagnosis)
				}
			} else if !strings.Contains(stdout, "diagnosis: unknown") || !strings.Contains(stdout, "missing_evidence:") || !strings.Contains(stdout, "global=false") {
				t.Fatalf("text omitted evidence contract: %s", stdout)
			}
			if strings.Contains(stdout, "cover.example.test") || strings.Contains(stdout, "192.0.2.10") {
				t.Fatal("raw target was printed")
			}
		})
	}
}

func TestProbeArgumentsAndDecodeErrorsNeverEchoSecrets(t *testing.T) {
	for _, args := range [][]string{
		{"probe", "ladder", "--password", "private-value-canary"},
		{"diagnose", "--node", "exit-test", "--inputs", "private-value-canary", "--store", "unused", "--family", "private-value-canary"},
	} {
		code, stdout, stderr := run(args...)
		if code != ExitUsage || strings.Contains(stdout+stderr, "private-value-canary") {
			t.Fatalf("arguments leaked: %d, %q, %q", code, stdout, stderr)
		}
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "private-value-canary.json")
	if err := os.WriteFile(path, []byte(`{"client_secret":"private-value-canary"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := run("diagnose", "--node", "exit-test", "--inputs", path, "--store", filepath.Join(directory, "state.db"), "--json")
	if code != ExitError || strings.Contains(stdout+stderr, "private-value-canary") {
		t.Fatalf("decoder leaked: %d, %q, %q", code, stdout, stderr)
	}
	var output probeOutput
	if err := json.Unmarshal([]byte(stdout), &output); err != nil || output.ErrorCode != "inputs_invalid" {
		t.Fatalf("error output = %+v, %v", output, err)
	}
}

func TestProbeMissingXrayIsUsageFailureNotNetworkSuccess(t *testing.T) {
	t.Setenv("VPNCTL_XRAY_PATH", "")
	inputs, database := diagnosisInputs(t)
	code, stdout, _ := run("probe", "ladder", "--node", "exit-test", "--inputs", inputs, "--store", database)
	if code != ExitUsage || stdout != "" {
		t.Fatalf("missing core = %d, %q", code, stdout)
	}
	if _, err := os.Stat(database); !os.IsNotExist(err) {
		t.Fatal("usage failure opened the store")
	}
}
