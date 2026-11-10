package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const validConfig = `panel:
  url: https://panel.example.com
  token_env: VPNCTL_PANEL_TOKEN
nodes:
  - name: exit-01
    role: exit
    address: 192.0.2.10
    port: 443
probe:
  timeout: 5s
  interval: 60s
log_level: info
`

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func run(args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = Run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestVersion(t *testing.T) {
	code, stdout, stderr := run("version")
	if code != ExitOK || stderr != "" {
		t.Fatalf("code = %d, stderr = %q", code, stderr)
	}
	if !regexp.MustCompile(`^vpnctl \S+\n$`).MatchString(stdout) {
		t.Fatalf("stdout = %q, want one line `vpnctl <version>`", stdout)
	}
}

func TestValidateSuccess(t *testing.T) {
	path := writeConfig(t, validConfig)
	code, stdout, stderr := run("config", "validate", "--config", path)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %q", code, stderr)
	}
	if stdout != "config OK: "+path+"\n" || stderr != "" {
		t.Fatalf("stdout = %q, stderr = %q", stdout, stderr)
	}
}

func TestValidateFailureReportsEveryProblem(t *testing.T) {
	content := strings.Replace(validConfig, "https://", "http://", 1)
	content = strings.Replace(content, "port: 443", "port: 65536", 1)
	path := writeConfig(t, content)
	code, stdout, stderr := run("config", "validate", "--config", path)
	if code != ExitError || stdout != "" {
		t.Fatalf("code = %d, stdout = %q", code, stdout)
	}
	for _, want := range []string{path, "panel.url", "nodes[0].port"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr does not mention %q:\n%s", want, stderr)
		}
	}
}

func TestValidateDecodeFailure(t *testing.T) {
	for name, content := range map[string]string{
		"invalid yaml":  "panel: [\n",
		"unknown field": validConfig + "extra: 1\n",
		"empty file":    "",
	} {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := run("config", "validate", "--config", writeConfig(t, content))
			if code != ExitError || stdout != "" || stderr == "" {
				t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
			}
		})
	}
}

func TestValidateMissingFile(t *testing.T) {
	code, _, stderr := run("config", "validate", "--config", filepath.Join(t.TempDir(), "absent.yaml"))
	if code != ExitError || stderr == "" {
		t.Fatalf("code = %d, stderr = %q", code, stderr)
	}
}

func TestUsageErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"no command":            {},
		"unknown command":       {"deploy"},
		"version with argument": {"version", "extra"},
		"config without verb":   {"config"},
		"unknown config verb":   {"config", "lint"},
		"missing config flag":   {"config", "validate"},
		"empty config flag":     {"config", "validate", "--config", ""},
		"flag without value":    {"config", "validate", "--config"},
		"unknown flag":          {"config", "validate", "--strict"},
		"extra argument":        {"config", "validate", "--config", "a.yaml", "b.yaml"},
	} {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := run(args...)
			if code != ExitUsage {
				t.Fatalf("code = %d, want %d", code, ExitUsage)
			}
			if stdout != "" || !strings.Contains(stderr, "usage:") {
				t.Fatalf("stdout = %q, stderr = %q", stdout, stderr)
			}
		})
	}
}

func TestHelp(t *testing.T) {
	code, stdout, stderr := run("--help")
	if code != ExitOK || !strings.Contains(stdout, "usage:") || stderr != "" {
		t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
}
