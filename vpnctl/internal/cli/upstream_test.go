package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/juvenileslave/vpn/vpnctl/internal/store"
)

const upstreamTestDeclaration = `schema: 1
sources:
  - id: sub-a
    kind: subscription
    slot: 1
    interval: 5m
    subscription_url: https://example.com/api/sub/SECRETTOKEN
  - id: sub-b
    kind: subscription
    slot: 4
    interval: 1h
    subscription_url: https://example.com/api/sub/SECRETPATH
    enabled: false
`

func writeUpstreamDeclaration(t *testing.T, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sources.yaml")
	if err := os.WriteFile(path, []byte(upstreamTestDeclaration), mode); err != nil {
		t.Fatalf("write declaration: %v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod declaration: %v", err)
	}
	return path
}

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestUpstreamListShowsDeclarationsWithoutLocators(t *testing.T) {
	decl := writeUpstreamDeclaration(t, 0o600)
	dbPath := filepath.Join(t.TempDir(), "state.db")

	code, out, errOut := runCLI(t, "upstream", "list", "--sources", decl, "--store", dbPath)
	if code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", code, errOut)
	}
	for _, want := range []string{"sub-a", "subscription", "sub-b", "subscription", "5m0s", "1h0m0s"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
	for _, leak := range []string{"SECRETTOKEN", "SECRETPATH", "example.com"} {
		if strings.Contains(out, leak) || strings.Contains(errOut, leak) {
			t.Fatalf("output leaked %q: %s %s", leak, out, errOut)
		}
	}

	code, out, errOut = runCLI(t, "upstream", "list", "--sources", decl, "--store", dbPath, "--format", "json")
	if code != ExitOK {
		t.Fatalf("json exit = %d, stderr = %s", code, errOut)
	}
	var payload struct {
		Schema  int `json:"schema"`
		Sources []struct {
			ID     string `json:"id"`
			Slot   int    `json:"slot"`
			Kind   string `json:"kind"`
			Mode   string `json:"mode"`
			Active string `json:"active"`
		} `json:"sources"`
	}
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if payload.Schema != 1 || len(payload.Sources) != 2 {
		t.Fatalf("payload = %+v", payload)
	}
	if payload.Sources[0].ID != "sub-a" || payload.Sources[0].Slot != 1 || payload.Sources[0].Mode != "" {
		t.Fatalf("first source = %+v", payload.Sources[0])
	}
	if strings.Contains(out, "SECRETTOKEN") {
		t.Fatalf("json leaked locator: %s", out)
	}
}

func TestUpstreamVersionsNewestFirst(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	ref := func() string { return strings.Repeat("a", 32) }
	sha := strings.Repeat("b", 64)
	for i := range 2 {
		if _, err := st.CreateUpstreamVersion(ctx, store.UpstreamVersion{
			Slot:                1,
			Origin:              "upstream",
			PayloadRef:          ref(),
			PayloadSHA256:       sha,
			OutboundFingerprint: sha,
		}, now.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatalf("CreateUpstreamVersion: %v", err)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	code, out, errOut := runCLI(t, "upstream", "versions", "--store", dbPath, "--slot", "1")
	if code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", code, errOut)
	}
	if !strings.Contains(out, "SEQ") || !strings.Contains(out, "candidate") {
		t.Fatalf("unexpected output:\n%s", out)
	}
	second := strings.Index(out, " 2    ")
	first := strings.Index(out, " 1    ")
	if second < 0 || first < 0 || second > first {
		t.Fatalf("versions not newest first:\n%s", out)
	}

	code, out, errOut = runCLI(t, "upstream", "versions", "--store", dbPath, "--slot", "2")
	if code != ExitOK {
		t.Fatalf("empty slot exit = %d", code)
	}
	if strings.Count(strings.TrimSpace(out), "\n") != 0 {
		t.Fatalf("expected header only, got:\n%s", out)
	}
	if strings.Contains(out, sha) {
		t.Fatalf("output leaked payload digest: %s", out)
	}
}

func TestSlotShowTextAndJSON(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	if _, err := st.RecordUpstreamFailure(ctx, 3, "probe_failed", time.Time{}, now); err != nil {
		t.Fatalf("RecordUpstreamFailure: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	code, out, errOut := runCLI(t, "slot", "show", "--store", dbPath)
	if code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", code, errOut)
	}
	if !strings.Contains(out, "blackhole") || !strings.Contains(out, "probe_failed") {
		t.Fatalf("unexpected output:\n%s", out)
	}

	code, out, errOut = runCLI(t, "slot", "show", "--store", dbPath, "--slot", "3", "--format", "json")
	if code != ExitOK {
		t.Fatalf("json exit = %d, stderr = %s", code, errOut)
	}
	var payload struct {
		Slots []struct {
			Slot     int    `json:"slot"`
			Mode     string `json:"mode"`
			Failures int    `json:"failures"`
		} `json:"slots"`
	}
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("json: %v", err)
	}
	if len(payload.Slots) != 1 || payload.Slots[0].Slot != 3 || payload.Slots[0].Mode != "blackhole" || payload.Slots[0].Failures != 1 {
		t.Fatalf("payload = %+v", payload)
	}

	code, _, errOut = runCLI(t, "slot", "show", "--store", dbPath, "--slot", "9")
	if code != ExitError || !strings.Contains(errOut, "slot not found") {
		t.Fatalf("missing slot exit = %d, stderr = %s", code, errOut)
	}
}

func TestMutatingUpstreamCommandsRefuseBeforeIO(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "absent.db")

	tests := []struct {
		name string
		args []string
		want string
	}{
		{"refresh", []string{"upstream", "refresh", "--store", dbPath}, refreshRefusal},
		{"rollback", []string{"upstream", "rollback", "--store", dbPath}, rollbackRefusal},
		{"slot set", []string{"slot", "set", "--store", dbPath}, slotSetRefusal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, out, errOut := runCLI(t, tt.args...)
			if code != ExitRefused {
				t.Fatalf("exit = %d, want %d", code, ExitRefused)
			}
			if out != "" {
				t.Fatalf("stdout = %q, want empty", out)
			}
			if strings.TrimSpace(errOut) != tt.want {
				t.Fatalf("stderr = %q, want %q", errOut, tt.want)
			}
			if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
				t.Fatalf("refusal touched the store: %v", err)
			}
		})
	}
}

func TestUpstreamUsageErrors(t *testing.T) {
	decl := writeUpstreamDeclaration(t, 0o600)
	dbPath := filepath.Join(t.TempDir(), "state.db")
	tests := [][]string{
		{"upstream"},
		{"upstream", "unknown"},
		{"upstream", "list"},
		{"upstream", "list", "--sources", decl},
		{"upstream", "list", "--sources", decl, "--store", dbPath, "--format", "yaml"},
		{"upstream", "versions", "--store", dbPath},
		{"upstream", "versions", "--store", dbPath, "--slot", "0"},
		{"upstream", "versions", "--store", dbPath, "--slot", "1", "--limit", "0"},
		{"slot"},
		{"slot", "unknown"},
		{"slot", "show"},
		{"slot", "show", "--store", dbPath, "--slot", "64"},
		{"slot", "show", "--store", dbPath, "--slot", "0"},
		{"slot", "show", "--store", dbPath, "--slot", "-1"},
	}
	for _, args := range tests {
		code, out, errOut := runCLI(t, args...)
		if code != ExitUsage {
			t.Fatalf("%v exit = %d, want %d (stderr %s)", args, code, ExitUsage, errOut)
		}
		if out != "" {
			t.Fatalf("%v stdout = %q", args, out)
		}
	}
}

func TestUpstreamListRejectsInsecureDeclaration(t *testing.T) {
	decl := writeUpstreamDeclaration(t, 0o644)
	dbPath := filepath.Join(t.TempDir(), "state.db")

	code, out, errOut := runCLI(t, "upstream", "list", "--sources", decl, "--store", dbPath)
	if code != ExitError {
		t.Fatalf("exit = %d, want %d", code, ExitError)
	}
	if strings.Contains(out, "SECRETTOKEN") || strings.Contains(errOut, "SECRETTOKEN") || strings.Contains(errOut, decl) {
		t.Fatalf("error leaked the declaration: %s %s", out, errOut)
	}
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Fatalf("rejected declaration opened the store: %v", err)
	}
}
