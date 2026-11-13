package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const validYAML = `panel:
  url: https://panel.example.com
  token_env: VPNCTL_PANEL_TOKEN
nodes:
  - name: exit-01
    role: exit
    address: 192.0.2.10
    port: 443
  - name: relay-01
    role: relay
    address: 2001:db8::10
    port: 443
  - name: cp-01
    role: cp
    address: cp.example.com
    port: 8443
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
    - id: 100000002
      role: viewer
  chat_ids: [-1000000000001]
`

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// mutate replaces old with new in validYAML and fails if old is absent, so a
// case can never silently test the unmodified valid config.
func mutate(t *testing.T, old, new string) string {
	t.Helper()
	if !strings.Contains(validYAML, old) {
		t.Fatalf("validYAML does not contain %q", old)
	}
	return strings.Replace(validYAML, old, new, 1)
}

func problemPaths(t *testing.T, err error) []string {
	t.Helper()
	var verr *ValidationError
	if !errors.As(err, &verr) {
		t.Fatalf("expected *ValidationError, got %T: %v", err, err)
	}
	paths := make([]string, len(verr.Problems))
	for i, p := range verr.Problems {
		paths[i] = p.Path
	}
	return paths
}

func TestLoadValid(t *testing.T) {
	cfg, err := Load(writeConfig(t, validYAML))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Panel.URL.String(); got != "https://panel.example.com" {
		t.Errorf("panel url = %q", got)
	}
	if cfg.Panel.TokenEnv != "VPNCTL_PANEL_TOKEN" {
		t.Errorf("token_env = %q", cfg.Panel.TokenEnv)
	}
	want := []Node{
		{Name: "exit-01", Role: "exit", Address: "192.0.2.10", Port: 443},
		{Name: "relay-01", Role: "relay", Address: "2001:db8::10", Port: 443},
		{Name: "cp-01", Role: "cp", Address: "cp.example.com", Port: 8443},
	}
	if len(cfg.Nodes) != len(want) {
		t.Fatalf("nodes = %+v", cfg.Nodes)
	}
	for i := range want {
		if cfg.Nodes[i] != want[i] {
			t.Errorf("nodes[%d] = %+v, want %+v", i, cfg.Nodes[i], want[i])
		}
	}
	if cfg.Probe.Timeout != 5*time.Second || cfg.Probe.Interval != time.Minute {
		t.Errorf("probe = %+v", cfg.Probe)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("log_level = %q", cfg.LogLevel)
	}
	if cfg.Bot.TokenEnv != "VPNCTL_BOT_TOKEN" || cfg.Bot.StateDB != "state.db" {
		t.Errorf("bot = %+v", cfg.Bot)
	}
	if cfg.Bot.APIBase != nil {
		t.Errorf("bot.api_base = %v, want nil", cfg.Bot.APIBase)
	}
	wantOperators := []Operator{{ID: 100000001, Role: RoleAdmin}, {ID: 100000002, Role: RoleViewer}}
	if len(cfg.Bot.Operators) != len(wantOperators) {
		t.Fatalf("operators = %+v", cfg.Bot.Operators)
	}
	for i := range wantOperators {
		if cfg.Bot.Operators[i] != wantOperators[i] {
			t.Errorf("operators[%d] = %+v, want %+v", i, cfg.Bot.Operators[i], wantOperators[i])
		}
	}
	if len(cfg.Bot.ChatIDs) != 1 || cfg.Bot.ChatIDs[0] != -1000000000001 {
		t.Errorf("chat_ids = %v", cfg.Bot.ChatIDs)
	}
}

func TestExampleConfigIsValid(t *testing.T) {
	if _, err := Load(filepath.Join("..", "..", "config.example.yaml")); err != nil {
		t.Fatalf("config.example.yaml: %v", err)
	}
}

func TestLoadAcceptsBoundaryValues(t *testing.T) {
	for name, content := range map[string]string{
		"port 1":           mutate(t, "port: 8443", "port: 1"),
		"port 65535":       mutate(t, "port: 8443", "port: 65535"),
		"single-label dns": mutate(t, "address: cp.example.com", "address: cp"),
		"url with path":    mutate(t, "url: https://panel.example.com", "url: https://panel.example.com:8443/api"),
		"debug level":      mutate(t, "log_level: info", "log_level: debug"),
		"loopback bot api": mutate(t, "bot:\n", "bot:\n  api_base: http://127.0.0.1:8081\n"),
		"https bot api":    mutate(t, "bot:\n", "bot:\n  api_base: https://bot.example.com\n"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeConfig(t, content)); err != nil {
				t.Fatalf("Load: %v", err)
			}
		})
	}
}

func TestLoadValidationErrors(t *testing.T) {
	tests := []struct {
		name     string
		content  func(t *testing.T) string
		wantPath string
	}{
		{"missing panel", func(t *testing.T) string {
			return mutate(t, "panel:\n  url: https://panel.example.com\n  token_env: VPNCTL_PANEL_TOKEN\n", "")
		}, "panel"},
		{"missing panel url", func(t *testing.T) string {
			return mutate(t, "  url: https://panel.example.com\n", "")
		}, "panel.url"},
		{"missing token_env", func(t *testing.T) string {
			return mutate(t, "  token_env: VPNCTL_PANEL_TOKEN\n", "")
		}, "panel.token_env"},
		{"http url", func(t *testing.T) string {
			return mutate(t, "url: https://panel.example.com", "url: http://panel.example.com")
		}, "panel.url"},
		{"userinfo in url", func(t *testing.T) string {
			return mutate(t, "url: https://panel.example.com", "url: https://admin:pw@panel.example.com")
		}, "panel.url"},
		{"url without host", func(t *testing.T) string {
			return mutate(t, "url: https://panel.example.com", "url: https:///api")
		}, "panel.url"},
		{"lowercase token_env", func(t *testing.T) string {
			return mutate(t, "token_env: VPNCTL_PANEL_TOKEN", "token_env: vpnctl_panel_token")
		}, "panel.token_env"},
		{"token_env starting with digit", func(t *testing.T) string {
			return mutate(t, "token_env: VPNCTL_PANEL_TOKEN", "token_env: 1TOKEN")
		}, "panel.token_env"},
		{"token value in token_env", func(t *testing.T) string {
			return mutate(t, "token_env: VPNCTL_PANEL_TOKEN", "token_env: abc-123.def")
		}, "panel.token_env"},
		{"empty nodes", func(t *testing.T) string {
			start := strings.Index(validYAML, "nodes:\n")
			end := strings.Index(validYAML, "probe:\n")
			return validYAML[:start] + "nodes: []\n" + validYAML[end:]
		}, "nodes"},
		{"missing nodes", func(t *testing.T) string {
			start := strings.Index(validYAML, "nodes:\n")
			end := strings.Index(validYAML, "probe:\n")
			return validYAML[:start] + validYAML[end:]
		}, "nodes"},
		{"duplicate node name", func(t *testing.T) string {
			return mutate(t, "name: relay-01", "name: exit-01")
		}, "nodes[1].name"},
		{"empty node name", func(t *testing.T) string {
			return mutate(t, "name: relay-01", `name: ""`)
		}, "nodes[1].name"},
		{"invalid role", func(t *testing.T) string {
			return mutate(t, "role: relay", "role: bridge")
		}, "nodes[1].role"},
		{"invalid address", func(t *testing.T) string {
			return mutate(t, "address: cp.example.com", "address: cp_example..com")
		}, "nodes[2].address"},
		{"malformed ipv4 address", func(t *testing.T) string {
			return mutate(t, "address: 192.0.2.10", "address: 192.0.2.300")
		}, "nodes[0].address"},
		{"ipv6 with zone", func(t *testing.T) string {
			return mutate(t, "address: 2001:db8::10", "address: fe80::1%eth0")
		}, "nodes[1].address"},
		{"missing port", func(t *testing.T) string {
			return mutate(t, "    port: 8443\n", "")
		}, "nodes[2].port"},
		{"port 0", func(t *testing.T) string {
			return mutate(t, "port: 8443", "port: 0")
		}, "nodes[2].port"},
		{"port 65536", func(t *testing.T) string {
			return mutate(t, "port: 8443", "port: 65536")
		}, "nodes[2].port"},
		{"missing probe", func(t *testing.T) string {
			return mutate(t, "probe:\n  timeout: 5s\n  interval: 60s\n", "")
		}, "probe"},
		{"zero timeout", func(t *testing.T) string {
			return mutate(t, "timeout: 5s", "timeout: 0s")
		}, "probe.timeout"},
		{"negative interval", func(t *testing.T) string {
			return mutate(t, "interval: 60s", "interval: -60s")
		}, "probe.interval"},
		{"duration without unit", func(t *testing.T) string {
			return mutate(t, "timeout: 5s", "timeout: 5")
		}, "probe.timeout"},
		{"missing interval", func(t *testing.T) string {
			return mutate(t, "  interval: 60s\n", "")
		}, "probe.interval"},
		{"invalid log level", func(t *testing.T) string {
			return mutate(t, "log_level: info", "log_level: verbose")
		}, "log_level"},
		{"missing log level", func(t *testing.T) string {
			return mutate(t, "log_level: info\n", "")
		}, "log_level"},
		{"missing bot", func(t *testing.T) string {
			start := strings.Index(validYAML, "bot:\n")
			return validYAML[:start]
		}, "bot"},
		{"missing bot token_env", func(t *testing.T) string {
			return mutate(t, "  token_env: VPNCTL_BOT_TOKEN\n", "")
		}, "bot.token_env"},
		{"lowercase bot token_env", func(t *testing.T) string {
			return mutate(t, "token_env: VPNCTL_BOT_TOKEN", "token_env: vpnctl_bot_token")
		}, "bot.token_env"},
		{"missing state_db", func(t *testing.T) string {
			return mutate(t, "  state_db: state.db\n", "")
		}, "bot.state_db"},
		{"empty operators", func(t *testing.T) string {
			start := strings.Index(validYAML, "  operators:\n")
			end := strings.Index(validYAML, "  chat_ids:")
			return validYAML[:start] + "  operators: []\n" + validYAML[end:]
		}, "bot.operators"},
		{"missing operators", func(t *testing.T) string {
			start := strings.Index(validYAML, "  operators:\n")
			end := strings.Index(validYAML, "  chat_ids:")
			return validYAML[:start] + validYAML[end:]
		}, "bot.operators"},
		{"duplicate operator id", func(t *testing.T) string {
			return mutate(t, "id: 100000002", "id: 100000001")
		}, "bot.operators[1].id"},
		{"zero operator id", func(t *testing.T) string {
			return mutate(t, "id: 100000001", "id: 0")
		}, "bot.operators[0].id"},
		{"negative operator id", func(t *testing.T) string {
			return mutate(t, "id: 100000001", "id: -5")
		}, "bot.operators[0].id"},
		{"missing operator id", func(t *testing.T) string {
			return mutate(t, "    - id: 100000001\n      role: admin", "    - role: admin")
		}, "bot.operators[0].id"},
		{"invalid operator role", func(t *testing.T) string {
			return mutate(t, "role: viewer", "role: root")
		}, "bot.operators[1].role"},
		{"missing operator role", func(t *testing.T) string {
			return mutate(t, "      role: viewer\n", "")
		}, "bot.operators[1].role"},
		{"zero chat id", func(t *testing.T) string {
			return mutate(t, "chat_ids: [-1000000000001]", "chat_ids: [0]")
		}, "bot.chat_ids[0]"},
		{"duplicate chat id", func(t *testing.T) string {
			return mutate(t, "chat_ids: [-1000000000001]", "chat_ids: [-1000000000001, -1000000000001]")
		}, "bot.chat_ids[1]"},
		{"cleartext remote bot api", func(t *testing.T) string {
			return mutate(t, "bot:\n", "bot:\n  api_base: http://bot.example.com\n")
		}, "bot.api_base"},
		{"bot api with path", func(t *testing.T) string {
			return mutate(t, "bot:\n", "bot:\n  api_base: https://bot.example.com/api\n")
		}, "bot.api_base"},
		{"bot api with userinfo", func(t *testing.T) string {
			return mutate(t, "bot:\n", "bot:\n  api_base: https://user:secret@bot.example.com\n")
		}, "bot.api_base"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, tt.content(t)))
			paths := problemPaths(t, err)
			if len(paths) != 1 || paths[0] != tt.wantPath {
				t.Fatalf("problem paths = %q, want [%q]; error:\n%v", paths, tt.wantPath, err)
			}
		})
	}
}

func TestLoadReportsEveryProblem(t *testing.T) {
	content := mutate(t, "url: https://panel.example.com", "url: http://panel.example.com")
	content = strings.Replace(content, "port: 443\n", "port: 0\n", 1)
	content = strings.Replace(content, "log_level: info", "log_level: loud", 1)
	_, err := Load(writeConfig(t, content))
	got := problemPaths(t, err)
	want := []string{"panel.url", "nodes[0].port", "log_level"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("problem paths = %q, want %q", got, want)
	}
}

func TestBotAPIBaseUserinfoIsNotEchoed(t *testing.T) {
	content := mutate(t, "bot:\n", "bot:\n  api_base: https://user:hunter2@bot.example.com\n")
	_, err := Load(writeConfig(t, content))
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("error must exist and must not echo userinfo: %v", err)
	}
}

func TestUserinfoIsNotEchoed(t *testing.T) {
	content := mutate(t, "url: https://panel.example.com", "url: https://user:hunter2@panel.example.com")
	_, err := Load(writeConfig(t, content))
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("error must exist and must not echo userinfo: %v", err)
	}
}

func TestLoadDecodeErrors(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantIs  error
	}{
		{"unknown top-level field", validYAML + "extra_field: 1\n", nil},
		{"unknown nested field", strings.Replace(validYAML, "  token_env:", "  token: abc\n  token_env:", 1), nil},
		{"duplicate key", validYAML + "log_level: debug\n", nil},
		{"invalid yaml", "panel: [unclosed\n", nil},
		{"nodes not a list", "nodes: 5\n", nil},
		{"non-integer port", strings.Replace(validYAML, "port: 443", "port: https", 1), nil},
		{"empty file", "", ErrEmpty},
		{"comments only", "# nothing here\n", ErrEmpty},
		{"multiple documents", validYAML + "---\n" + validYAML, ErrMultipleDocuments},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, tt.content))
			if err == nil {
				t.Fatal("expected an error")
			}
			var verr *ValidationError
			if errors.As(err, &verr) {
				t.Fatalf("expected a decode error, got validation error: %v", err)
			}
			if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
				t.Fatalf("error = %v, want %v", err, tt.wantIs)
			}
		})
	}
}

func TestUnknownFieldIsNamed(t *testing.T) {
	_, err := Load(writeConfig(t, validYAML+"extra_field: 1\n"))
	if err == nil || !strings.Contains(err.Error(), "extra_field") {
		t.Fatalf("error must name the unknown field: %v", err)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "absent.yaml"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("error = %v, want os.ErrNotExist", err)
	}
}
