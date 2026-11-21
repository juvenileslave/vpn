package validate

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fakeXray(t *testing.T, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "xray")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake xray: %v", err)
	}
	return path
}

func TestNewValidation(t *testing.T) {
	executable := fakeXray(t, "#!/bin/sh\nexit 0\n")
	notExecutable := filepath.Join(t.TempDir(), "xray")
	if err := os.WriteFile(notExecutable, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	for _, path := range []string{"", "xray", filepath.Join(t.TempDir(), "absent"), notExecutable} {
		if _, err := New(Options{XrayPath: path}); !errors.Is(err, ErrInvalidOptions) {
			t.Fatalf("New(%q) error = %v, want ErrInvalidOptions", path, err)
		}
	}
	if _, err := New(Options{XrayPath: executable}); err != nil {
		t.Fatalf("valid options rejected: %v", err)
	}
}

func TestValidateAcceptsConfig(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	logPath := filepath.Join(t.TempDir(), "args.log")
	path := fakeXray(t, "#!/bin/sh\nif [ \"$1\" = \"-version\" ]; then echo 'Xray 26.9.0'; exit 0; fi\nprintf '%s\\n' \"$*\" >> "+logPath+"\nexit 0\n")
	v, err := New(Options{XrayPath: path, VersionPrefix: "Xray 26.9.0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	before, _ := filepath.Glob(filepath.Join(os.TempDir(), "vpnctl-upstream-validate-*"))
	if err := v.Validate(context.Background(), 1, json.RawMessage(`{"protocol":"vless","tag":"upstream-slot-1"}`)); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	after, _ := filepath.Glob(filepath.Join(os.TempDir(), "vpnctl-upstream-validate-*"))
	if len(after) != len(before) {
		t.Fatalf("temporary validate directories leaked: before=%d after=%d", len(before), len(after))
	}
	args, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read args: %v", err)
	}
	if !strings.Contains(string(args), "-test -c ") {
		t.Fatalf("xray args = %q", args)
	}
}

func TestValidateRejectsConfig(t *testing.T) {
	path := fakeXray(t, "#!/bin/sh\nif [ \"$1\" = \"-version\" ]; then echo 'Xray 26.9.0'; exit 0; fi\nexit 1\n")
	v, err := New(Options{XrayPath: path})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = v.Validate(context.Background(), 1, json.RawMessage(`{"protocol":"vless"}`))
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("Validate error = %v, want ErrRejected", err)
	}
	if strings.Contains(err.Error(), os.TempDir()) {
		t.Fatalf("error leaked config path: %v", err)
	}
}

func TestValidateRejectsBadInputs(t *testing.T) {
	path := fakeXray(t, "#!/bin/sh\necho 'Xray 26.9.0'\n")
	v, err := New(Options{XrayPath: path})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, slot := range []int{0, 64} {
		if err := v.Validate(context.Background(), slot, json.RawMessage(`{}`)); !errors.Is(err, ErrConfig) {
			t.Fatalf("slot %d error = %v, want ErrConfig", slot, err)
		}
	}
	for _, raw := range []string{``, `[]`, `null`, `"text"`} {
		if err := v.Validate(context.Background(), 1, json.RawMessage(raw)); !errors.Is(err, ErrConfig) {
			t.Fatalf("outbound %q error = %v, want ErrConfig", raw, err)
		}
	}
	if err := v.Validate(nil, 1, json.RawMessage(`{}`)); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("nil context error = %v, want ErrInvalidOptions", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := v.Validate(ctx, 1, json.RawMessage(`{}`)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context error = %v", err)
	}
}

func TestValidateTimeout(t *testing.T) {
	path := fakeXray(t, "#!/bin/sh\nif [ \"$1\" = \"-version\" ]; then echo 'Xray 26.9.0'; exit 0; fi\nsleep 5\nexit 0\n")
	v, err := New(Options{XrayPath: path, Timeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = v.Validate(context.Background(), 1, json.RawMessage(`{"protocol":"vless"}`))
	if !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("timeout error = %v", err)
	}
}

func TestValidateVersionMismatch(t *testing.T) {
	path := fakeXray(t, "#!/bin/sh\necho 'Xray 25.1.0'\nexit 0\n")
	v, err := New(Options{XrayPath: path, VersionPrefix: "Xray 26."})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := v.Validate(context.Background(), 1, json.RawMessage(`{"protocol":"vless"}`)); !errors.Is(err, ErrCore) {
		t.Fatalf("version error = %v, want ErrCore", err)
	}
}
