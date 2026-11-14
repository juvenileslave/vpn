package cli

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/juvenileslave/vpn/vpnctl/internal/panel"
	"github.com/juvenileslave/vpn/vpnctl/internal/remnawave"
)

func TestPanelExplicitApplyRefusesBeforeFilesTokenNetworkOrState(t *testing.T) {
	t.Setenv("VPNCTL_PANEL_TOKEN", rand.Text())
	root := t.TempDir()
	for _, args := range [][]string{
		{"panel", "apply", "--apply"},
		{"panel", "apply", "--apply", "--config", filepath.Join(root, "missing.yaml"),
			"--bundle", filepath.Join(root, "missing.json"), "--objects", filepath.Join(root, "missing-objects.json")},
	} {
		code, stdout, stderr := run(args...)
		if code != ExitRefused || stdout != "" || !strings.Contains(stderr, "before I/O") {
			t.Fatalf("explicit apply result = %d, %q, %q", code, stdout, stderr)
		}
		if strings.Contains(stderr, root) || strings.Contains(stderr, os.Getenv("VPNCTL_PANEL_TOKEN")) {
			t.Fatal("refusal exposed input or token")
		}
	}
	files, err := os.ReadDir(root)
	if err != nil || len(files) != 0 {
		t.Fatal("explicit apply touched the state directory")
	}
}

func TestPanelUsageRejectsSecretLikeArgumentsWithoutEchoing(t *testing.T) {
	secret := rand.Text()
	for _, args := range [][]string{
		{"panel", "plan", "--apply"}, {"panel", "show", "--apply"},
		{"panel", "apply", "--exclusive"}, {"panel", "--unknown-" + secret},
		{"panel", "plan", "--config", secret, "extra"}, {"panel", "bogus-" + secret},
	} {
		code, stdout, stderr := run(args...)
		if code != ExitUsage || stdout != "" || strings.Contains(stderr, secret) {
			t.Fatalf("bad panel arguments result = %d; secret-safe = %t", code, !strings.Contains(stderr, secret))
		}
	}
	for _, args := range [][]string{{"panel", "--help"}, {"panel", "show", "--help"}} {
		code, stdout, stderr := run(args...)
		if code != ExitOK || stderr != "" || !strings.Contains(stdout, "vpnctl panel") {
			t.Fatal("panel help unavailable")
		}
	}
}

type cliPanelReader struct{ hits atomic.Int32 }

func (r *cliPanelReader) ListConfigProfiles(context.Context) ([]remnawave.ConfigProfile, error) {
	r.hits.Add(1)
	return []remnawave.ConfigProfile{}, nil
}
func (r *cliPanelReader) ListSnippets(context.Context) ([]remnawave.Snippet, error) {
	r.hits.Add(1)
	return []remnawave.Snippet{}, nil
}
func (r *cliPanelReader) ListHosts(context.Context) ([]remnawave.Host, error) {
	r.hits.Add(1)
	return []remnawave.Host{}, nil
}
func (r *cliPanelReader) ConfigProfile(context.Context, string) (remnawave.ConfigProfile, error) {
	return remnawave.ConfigProfile{}, remnawave.ErrNotFound
}
func (r *cliPanelReader) ComputedConfigProfile(context.Context, string) (remnawave.ConfigProfile, error) {
	return remnawave.ConfigProfile{}, remnawave.ErrNotFound
}
func (r *cliPanelReader) Host(context.Context, string) (remnawave.Host, error) {
	return remnawave.Host{}, remnawave.ErrNotFound
}

func TestPanelPlanAndImplicitApplyOutputSafeStableDiff(t *testing.T) {
	reader := &cliPanelReader{}
	bundle := panel.Bundle{ID: strings.Repeat("a", 64), Configs: map[string]json.RawMessage{
		"exit": json.RawMessage(`{"inbounds":[],"outbounds":[{"tag":"block","protocol":"blackhole","private":"not-in-output"}]}`),
	}}
	objects := panel.Objects{Schema: 1, Profiles: []panel.ProfileSpec{{Name: "owned-exit", Role: "exit"}}}
	var expected string
	for _, mode := range []string{"plan", "apply"} {
		var output strings.Builder
		var diagnostics strings.Builder
		code := panelRead(context.Background(), reader, bundle, objects, mode, &output, &diagnostics)
		if code != ExitOK || diagnostics.Len() != 0 {
			t.Fatalf("%s code = %d", mode, code)
		}
		var report panel.Report
		if err := json.Unmarshal([]byte(output.String()), &report); err != nil {
			t.Fatal(err)
		}
		if report.Mode != "plan" || report.AtomicWrites || len(report.Objects) != 1 || report.Objects[0].Action != "create" {
			t.Fatal("read-only candidate output lost intended diff")
		}
		if strings.Contains(output.String(), "not-in-output") {
			t.Fatal("candidate payload leaked")
		}
		if mode == "plan" {
			expected = output.String()
		} else if output.String() != expected {
			t.Fatal("implicit apply is not identical to plan")
		}
	}
	if reader.hits.Load() != 6 {
		t.Fatal("plan did not use only three collection reads")
	}
}

func TestPanelAdditionalCAEnforcesCertificateValidation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "trusted") }))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "test-ca.pem")
	certificate := server.Certificate()
	if _, err := x509.ParseCertificate(certificate.Raw); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	trusted, err := panelHTTPClient(path)
	if err != nil {
		t.Fatal(err)
	}
	response, err := trusted.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	untrusted, err := panelHTTPClient("")
	if err != nil {
		t.Fatal(err)
	}
	if response, err := untrusted.Get(server.URL); err == nil {
		response.Body.Close()
		t.Fatal("untrusted TLS certificate accepted")
	}
	if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := panelHTTPClient(path); err == nil {
		t.Fatal("invalid additional CA accepted")
	}
}
