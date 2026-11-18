package cli

import (
	"encoding/json"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/juvenileslave/vpn/vpnctl/internal/alerts"
	"github.com/juvenileslave/vpn/vpnctl/internal/metrics"
)

const validRulesYAML = `rules:
  - name: rule-a
    query: synthetic_metric
    aggregation: max
    comparison: ">"
    threshold: 90
    severity: warning
`

// observabilityConfig appends optional metrics and alerts sections with a
// synthetic endpoint and a per-test state database.
func observabilityConfig(t *testing.T, endpoint string) string {
	t.Helper()
	stateDB := filepath.Join(t.TempDir(), "alerts.db")
	return validConfig +
		"metrics:\n  endpoint: " + endpoint + "\n  timeout: 1s\n" +
		"alerts:\n  state_db: " + stateDB + "\n"
}

func TestCheckExitCode(t *testing.T) {
	cases := []struct {
		name    string
		results []alerts.CheckResult
		want    int
	}{
		{"empty", nil, ExitOK},
		{"ok", []alerts.CheckResult{{State: metrics.StateOK}}, ExitOK},
		{"unknown", []alerts.CheckResult{{State: metrics.StateUnknown}}, exitAlertsUnknown},
		{"firing", []alerts.CheckResult{{State: metrics.StateFiring}}, exitAlertsFiring},
		{"firing wins over unknown", []alerts.CheckResult{{State: metrics.StateUnknown}, {State: metrics.StateFiring}}, exitAlertsFiring},
		{"ok and unknown", []alerts.CheckResult{{State: metrics.StateOK}, {State: metrics.StateUnknown}}, exitAlertsUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := checkExitCode(tc.results); got != tc.want {
				t.Fatalf("checkExitCode = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestMetricsAndAlertsUsageErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"metrics without subcommand", []string{"metrics"}},
		{"unknown metrics subcommand", []string{"metrics", "watch"}},
		{"check without flags", []string{"metrics", "check"}},
		{"check without rules", []string{"metrics", "check", "--config", "config.yaml"}},
		{"check bad format", []string{"metrics", "check", "--config", "config.yaml", "--rules", "rules.yaml", "--format", "xml"}},
		{"run without flags", []string{"metrics", "run"}},
		{"alerts without subcommand", []string{"alerts"}},
		{"unknown alerts subcommand", []string{"alerts", "history"}},
		{"list without config", []string{"alerts", "list"}},
		{"mute without rule", []string{"alerts", "mute", "--config", "config.yaml"}},
		{"mute invalid rule", []string{"alerts", "mute", "--config", "config.yaml", "--rule", "Bad Rule"}},
		{"mute invalid until", []string{"alerts", "mute", "--config", "config.yaml", "--rule", "rule-a", "--until", "tomorrow"}},
		{"mute past until", []string{"alerts", "mute", "--config", "config.yaml", "--rule", "rule-a", "--until", "2000-01-01T00:00:00Z"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := run(tt.args...)
			if code != ExitUsage || stdout != "" || !strings.Contains(stderr, "usage:") {
				t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
			}
		})
	}
}

func TestMetricsCheckRejectsConfigAndRules(t *testing.T) {
	rulesPath := writeConfig(t, validRulesYAML)

	code, stdout, stderr := run("metrics", "check",
		"--config", writeConfig(t, "panel: [\n"), "--rules", rulesPath)
	if code != ExitError || stdout != "" || !strings.Contains(stderr, "config invalid") {
		t.Fatalf("invalid config = %d, %q, %q", code, stdout, stderr)
	}

	badRules := strings.Replace(validRulesYAML, `comparison: ">"`, `comparison: "??"`, 1)
	code, stdout, stderr = run("metrics", "check",
		"--config", writeConfig(t, observabilityConfig(t, "https://metrics.example.com")),
		"--rules", writeConfig(t, badRules))
	if code != ExitError || stdout != "" {
		t.Fatalf("invalid rules = %d, %q, %q", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "rules invalid") || !strings.Contains(stderr, "rules[0].comparison") {
		t.Fatalf("stderr = %q", stderr)
	}
}

func TestMetricsCheckReportsUnknownWithoutFalseOK(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	// Accept and immediately close so the TLS handshake fails without any
	// external service or real metric store.
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	configPath := writeConfig(t, observabilityConfig(t, "https://127.0.0.1:"+strconv.Itoa(port)))

	code, stdout, stderr := run("metrics", "check",
		"--config", configPath, "--rules", writeConfig(t, validRulesYAML))
	if code != exitAlertsUnknown {
		t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "unknown rule=rule-a") || strings.Contains(stdout, "ok rule=") {
		t.Fatalf("stdout = %q", stdout)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q", stderr)
	}
}

func TestAlertsMuteAndListPersist(t *testing.T) {
	configPath := writeConfig(t, observabilityConfig(t, "https://metrics.example.com"))
	until := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)

	code, stdout, stderr := run("alerts", "mute",
		"--config", configPath, "--rule", "rule-a", "--until", until)
	if code != ExitOK || stdout != "muted rule=rule-a until="+until+"\n" || stderr != "" {
		t.Fatalf("mute = %d, %q, %q", code, stdout, stderr)
	}

	code, stdout, stderr = run("alerts", "list", "--config", configPath, "--format", "json")
	if code != ExitOK || stderr != "" {
		t.Fatalf("list = %d, %q, %q", code, stdout, stderr)
	}
	var view alertsListView
	if err := json.Unmarshal([]byte(stdout), &view); err != nil {
		t.Fatalf("json: %v\n%s", err, stdout)
	}
	if len(view.Mutes) != 1 || view.Mutes[0].Rule != "rule-a" {
		t.Fatalf("mutes = %+v", view.Mutes)
	}
	if view.Outbox.Pending != 0 || view.Outbox.Expired != 0 {
		t.Fatalf("outbox = %+v", view.Outbox)
	}

	code, stdout, stderr = run("alerts", "list", "--config", configPath)
	if code != ExitOK || !strings.Contains(stdout, "mute rule=rule-a until=") || stderr != "" {
		t.Fatalf("text list = %d, %q, %q", code, stdout, stderr)
	}
}

func TestAlertsRequireConfiguration(t *testing.T) {
	code, stdout, stderr := run("alerts", "list", "--config", writeConfig(t, validConfig))
	if code != ExitError || stdout != "" || !strings.Contains(stderr, "alerts section is required") {
		t.Fatalf("list = %d, %q, %q", code, stdout, stderr)
	}
	code, stdout, stderr = run("metrics", "run",
		"--config", writeConfig(t, validConfig), "--rules", writeConfig(t, validRulesYAML))
	if code != ExitError || stdout != "" || !strings.Contains(stderr, "metrics section is required") {
		t.Fatalf("run without metrics = %d, %q, %q", code, stdout, stderr)
	}
}

func TestMetricsRunRequiresAlertsSectionBeforeQueries(t *testing.T) {
	content := validConfig + "metrics:\n  endpoint: https://metrics.example.com\n"
	code, stdout, stderr := run("metrics", "run",
		"--config", writeConfig(t, content), "--rules", writeConfig(t, validRulesYAML))
	if code != ExitError || stdout != "" || !strings.Contains(stderr, "alerts section is required") {
		t.Fatalf("run = %d, %q, %q", code, stdout, stderr)
	}
}
