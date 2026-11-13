package cli

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
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
bot:
  token_env: VPNCTL_BOT_TOKEN
  state_db: state.db
  operators:
    - id: 100000001
      role: admin
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
		"bot without config":    {"bot"},
		"bot empty config":      {"bot", "--config", ""},
		"bot unknown flag":      {"bot", "--strict"},
		"bot extra argument":    {"bot", "--config", "a.yaml", "b.yaml"},
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

const testBotToken = "123456:TEST-fake_token"

func botConfig(t *testing.T, apiBase string) string {
	t.Helper()
	content := strings.Replace(validConfig, "state_db: state.db", "state_db: "+filepath.Join(t.TempDir(), "state.db"), 1)
	if apiBase != "" {
		content = strings.Replace(content, "bot:\n", "bot:\n  api_base: "+apiBase+"\n", 1)
	}
	return content
}

func TestBotMissingBotToken(t *testing.T) {
	t.Setenv("VPNCTL_BOT_TOKEN", "")
	t.Setenv("VPNCTL_PANEL_TOKEN", "panel-token")
	code, stdout, stderr := run("bot", "--config", writeConfig(t, botConfig(t, "")))
	if code != ExitError || stdout != "" {
		t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "bot token environment variable is not set") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestBotMissingPanelToken(t *testing.T) {
	t.Setenv("VPNCTL_BOT_TOKEN", testBotToken)
	t.Setenv("VPNCTL_PANEL_TOKEN", "")
	code, stdout, stderr := run("bot", "--config", writeConfig(t, botConfig(t, "")))
	if code != ExitError || stdout != "" {
		t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "panel token environment variable is not set") {
		t.Errorf("stderr = %q", stderr)
	}
	if strings.Contains(stderr, testBotToken) {
		t.Errorf("stderr leaks the bot token: %q", stderr)
	}
}

func TestBotRejectsInvalidConfigBeforeReadingTokens(t *testing.T) {
	content := strings.Replace(validConfig,
		"  operators:\n    - id: 100000001\n      role: admin\n", "  operators: []\n", 1)
	code, stdout, stderr := run("bot", "--config", writeConfig(t, content))
	if code != ExitError || stdout != "" {
		t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "config invalid") || !strings.Contains(stderr, "bot.operators") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestBotUnauthorizedTokenStopsBeforePolling(t *testing.T) {
	t.Setenv("VPNCTL_BOT_TOKEN", testBotToken)
	t.Setenv("VPNCTL_PANEL_TOKEN", "panel-token")
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"ok":false,"error_code":401,"description":"Unauthorized"}`)
	}))
	defer srv.Close()

	code, stdout, stderr := run("bot", "--config", writeConfig(t, botConfig(t, srv.URL)))
	if code != ExitError || stdout != "" {
		t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "bot stopped:") || !strings.Contains(strings.ToLower(stderr), "unauthorized") {
		t.Errorf("stderr = %q", stderr)
	}
	if strings.Contains(stderr, testBotToken) {
		t.Errorf("stderr leaks the bot token: %q", stderr)
	}
	mu.Lock()
	defer mu.Unlock()
	wantPath := "/bot" + testBotToken + "/getMe"
	if len(paths) != 1 || paths[0] != wantPath {
		t.Errorf("requests = %v, want [%s]", paths, wantPath)
	}
}

func TestBotStoreFailureIsReported(t *testing.T) {
	t.Setenv("VPNCTL_BOT_TOKEN", testBotToken)
	t.Setenv("VPNCTL_PANEL_TOKEN", "panel-token")
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true,"result":{"id":1,"is_bot":true}}`)
	}))
	defer srv.Close()
	content := strings.Replace(validConfig, "state_db: state.db",
		"state_db: "+filepath.Join(t.TempDir(), "missing", "state.db"), 1)
	content = strings.Replace(content, "bot:\n", "bot:\n  api_base: "+srv.URL+"\n", 1)
	code, stdout, stderr := run("bot", "--config", writeConfig(t, content))
	if code != ExitError || stdout != "" {
		t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "open state store") {
		t.Errorf("stderr = %q", stderr)
	}
	if requests != 0 {
		t.Errorf("HTTP requests = %d before the store opened", requests)
	}
}

func TestBotUsageMentionsCommand(t *testing.T) {
	code, stdout, _ := run("--help")
	if code != ExitOK || !strings.Contains(stdout, "vpnctl bot --config PATH") {
		t.Fatalf("code = %d, stdout = %q", code, stdout)
	}
}

func TestHelp(t *testing.T) {
	code, stdout, stderr := run("--help")
	if code != ExitOK || !strings.Contains(stdout, "usage:") || stderr != "" {
		t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
}
