package source

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func writeTempFile(t *testing.T, dir, name string, data []byte, mode fs.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(p), err)
	}
	if err := os.WriteFile(p, data, mode); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatalf("chmod %s to %04o: %v", p, mode, err)
	}
	return p
}

func assertValidationProblem(t *testing.T, err error, wantPaths ...string) *ValidationError {
	t.Helper()
	if err == nil {
		t.Fatalf("expected *ValidationError, got nil")
	}
	var verr *ValidationError
	if !errors.As(err, &verr) {
		t.Fatalf("expected *ValidationError, got %T: %v", err, err)
	}
	for _, wantPath := range wantPaths {
		found := false
		for _, p := range verr.Problems {
			if p.Path == wantPath {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected problem path %q in %v", wantPath, verr.Problems)
		}
	}
	return verr
}

func isLowerHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func assertNoSecrets(t *testing.T, label, text string, secrets ...string) {
	t.Helper()
	for _, secret := range secrets {
		if strings.Contains(text, secret) {
			t.Errorf("%s leaked %q: %q", label, secret, text)
		}
	}
}

func TestLoadValidDeclarations(t *testing.T) {
	dir := t.TempDir()
	wgPath := writeTempFile(t, dir, "wg0.conf", []byte("[Interface]\nPrivateKey = dummy\n"), 0o600)

	yamlDoc := fmt.Sprintf(`schema: 1
sources:
  - id: sub-default
    kind: subscription
    slot: 1
    interval: 1m
    subscription_url: https://example.com/sub/default
  - id: sub-disabled
    kind: subscription
    slot: 63
    interval: 24h
    enabled: false
    subscription_url: https://example.com/sub/disabled
    filter:
      countries: [JP, US, DE, NL]
      max_latency: 250ms
      min_successful_probes: 3
  - id: wg-primary
    kind: wireguard_file
    slot: 7
    interval: 15m
    wireguard_path: %q
    filter:
      countries: [CH, SE]
      max_latency: 1s
`, wgPath)

	declPath := writeTempFile(t, dir, "sources.yaml", []byte(yamlDoc), 0o600)
	decl, err := Load(declPath)
	if err != nil {
		t.Fatalf("Load returned unexpected error: %v", err)
	}
	if decl.Schema != 1 {
		t.Fatalf("Schema = %d, want 1", decl.Schema)
	}

	want := []struct {
		id       string
		kind     Kind
		slot     int
		interval time.Duration
		enabled  bool
		locator  string
		filter   Filter
	}{
		{
			id:       "sub-default",
			kind:     Subscription,
			slot:     1,
			interval: time.Minute,
			enabled:  true,
			locator:  "https://example.com/sub/default",
			filter:   Filter{MinSuccessfulProbes: 1},
		},
		{
			id:       "sub-disabled",
			kind:     Subscription,
			slot:     63,
			interval: 24 * time.Hour,
			enabled:  false,
			locator:  "https://example.com/sub/disabled",
			filter:   Filter{Countries: []string{"JP", "US", "DE", "NL"}, MaxLatency: 250 * time.Millisecond, MinSuccessfulProbes: 3},
		},
		{
			id:       "wg-primary",
			kind:     WireguardFile,
			slot:     7,
			interval: 15 * time.Minute,
			enabled:  true,
			locator:  wgPath,
			filter:   Filter{Countries: []string{"CH", "SE"}, MaxLatency: time.Second, MinSuccessfulProbes: 1},
		},
	}

	if len(decl.Sources) != len(want) {
		t.Fatalf("len(Sources) = %d, want %d", len(decl.Sources), len(want))
	}

	for i, tc := range want {
		t.Run(tc.id, func(t *testing.T) {
			got := decl.Sources[i]
			if got.ID() != tc.id {
				t.Errorf("ID() = %q, want %q", got.ID(), tc.id)
			}
			if got.Kind() != tc.kind {
				t.Errorf("Kind() = %q, want %q", got.Kind(), tc.kind)
			}
			if got.Slot() != tc.slot {
				t.Errorf("Slot() = %d, want %d", got.Slot(), tc.slot)
			}
			if got.Interval() != tc.interval {
				t.Errorf("Interval() = %v, want %v", got.Interval(), tc.interval)
			}
			if got.Enabled() != tc.enabled {
				t.Errorf("Enabled() = %v, want %v", got.Enabled(), tc.enabled)
			}
			if got.Locator() != tc.locator {
				t.Errorf("Locator() = %q, want %q", got.Locator(), tc.locator)
			}
			if !reflect.DeepEqual(got.Filter(), tc.filter) {
				t.Errorf("Filter() = %+v, want %+v", got.Filter(), tc.filter)
			}
			if !isLowerHex64(got.Fingerprint()) {
				t.Errorf("Fingerprint() = %q, want 64 lowercase hex chars", got.Fingerprint())
			}
		})
	}

	f := decl.Sources[1].Filter()
	f.Countries[0] = "ZZ"
	if got := decl.Sources[1].Filter().Countries[0]; got != "JP" {
		t.Errorf("mutating Filter().Countries affected source: got %q, want %q", got, "JP")
	}
}

func TestFingerprint(t *testing.T) {
	yamlDoc := `schema: 1
sources:
  - id: sub-a
    kind: subscription
    slot: 1
    interval: 5m
    subscription_url: https://example.com/sub/alpha-token
  - id: sub-b
    kind: subscription
    slot: 2
    interval: 5m
    subscription_url: https://example.com/sub/beta-token
  - id: wg-a
    kind: wireguard_file
    slot: 3
    interval: 5m
    wireguard_path: /etc/wireguard/alpha.conf
  - id: wg-b
    kind: wireguard_file
    slot: 4
    interval: 5m
    wireguard_path: /etc/wireguard/beta.conf
`
	decl1, err := Parse([]byte(yamlDoc))
	if err != nil {
		t.Fatalf("first Parse failed: %v", err)
	}
	decl2, err := Parse([]byte(yamlDoc))
	if err != nil {
		t.Fatalf("second Parse failed: %v", err)
	}

	seen := make(map[string]string, len(decl1.Sources))
	for i, src := range decl1.Sources {
		fp := src.Fingerprint()
		if !isLowerHex64(fp) {
			t.Errorf("%s: Fingerprint() = %q, want 64 lowercase hex chars", src.ID(), fp)
		}
		if fp != decl2.Sources[i].Fingerprint() {
			t.Errorf("%s: Fingerprint() not stable: %q vs %q", src.ID(), fp, decl2.Sources[i].Fingerprint())
		}
		if strings.Contains(fp, src.Locator()) {
			t.Errorf("%s: Fingerprint() %q contains locator %q", src.ID(), fp, src.Locator())
		}
		if prev, dup := seen[fp]; dup {
			t.Errorf("%s: Fingerprint() %q collides with %s", src.ID(), fp, prev)
		}
		seen[fp] = src.ID()
	}
}

func TestParseDecodeRejections(t *testing.T) {
	const validSub = "schema: 1\nsources:\n  - id: sub-a\n    kind: subscription\n    slot: 1\n    interval: 5m\n    subscription_url: https://example.com/sub\n"
	oversizedPrefix := validSub + "# "
	oversized := oversizedPrefix + strings.Repeat("a", MaxDeclarationBytes+1-len(oversizedPrefix))

	tests := []struct {
		name          string
		input         string
		wantErr       error
		wantErrSubstr string
	}{
		{
			name:  "unknown top-level field",
			input: "unexpected: true\n" + validSub,
		},
		{
			name:  "unknown source field",
			input: validSub + "    unknown_field: nope\n",
		},
		{
			name:    "second YAML document",
			input:   validSub + "---\nschema: 1\n",
			wantErr: ErrMultipleDocuments,
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: ErrEmpty,
		},
		{
			name:    "comments and whitespace only",
			input:   "# only a comment\n   \n",
			wantErr: ErrEmpty,
		},
		{
			name:          "oversized input",
			input:         oversized,
			wantErrSubstr: "exceeds",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			decl, err := Parse([]byte(tc.input))
			if err == nil {
				t.Fatalf("Parse succeeded unexpectedly: %v", decl)
			}
			if decl != nil {
				t.Fatalf("expected nil declaration on error, got %v", decl)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("error = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErrSubstr != "" && !strings.Contains(err.Error(), tc.wantErrSubstr) {
				t.Errorf("error = %q, want substring %q", err.Error(), tc.wantErrSubstr)
			}
		})
	}
}

func TestParseValidationRejections(t *testing.T) {
	const (
		validSubEntry = "  - id: sub-a\n    kind: subscription\n    slot: 1\n    interval: 5m\n    subscription_url: https://example.com/sub\n"
		validWGEntry  = "  - id: wg-a\n    kind: wireguard_file\n    slot: 2\n    interval: 5m\n    wireguard_path: /etc/wireguard/wg0.conf\n"
		validSubDecl  = "schema: 1\nsources:\n" + validSubEntry
		validWGDecl   = "schema: 1\nsources:\n" + validWGEntry
	)

	tests := []struct {
		name      string
		input     string
		wantPaths []string
	}{
		{
			name:      "schema 0",
			input:     "schema: 0\nsources:\n" + validSubEntry,
			wantPaths: []string{"schema"},
		},
		{
			name:      "schema 2",
			input:     "schema: 2\nsources:\n" + validSubEntry,
			wantPaths: []string{"schema"},
		},
		{
			name:      "duplicate id",
			input:     "schema: 1\nsources:\n" + validSubEntry + validSubEntry,
			wantPaths: []string{"sources[1].id"},
		},
		{
			name:      "slot 0",
			input:     strings.Replace(validSubDecl, "slot: 1", "slot: 0", 1),
			wantPaths: []string{"sources[0].slot"},
		},
		{
			name:      "slot 64",
			input:     strings.Replace(validSubDecl, "slot: 1", "slot: 64", 1),
			wantPaths: []string{"sources[0].slot"},
		},
		{
			name:      "interval 30s",
			input:     strings.Replace(validSubDecl, "interval: 5m", "interval: 30s", 1),
			wantPaths: []string{"sources[0].interval"},
		},
		{
			name:      "interval 25h",
			input:     strings.Replace(validSubDecl, "interval: 5m", "interval: 25h", 1),
			wantPaths: []string{"sources[0].interval"},
		},
		{
			name:      "both locators on subscription",
			input:     validSubDecl + "    wireguard_path: /etc/wireguard/wg0.conf\n",
			wantPaths: []string{"sources[0].wireguard_path"},
		},
		{
			name:      "both locators on wireguard_file",
			input:     validWGDecl + "    subscription_url: https://example.com/sub\n",
			wantPaths: []string{"sources[0].subscription_url"},
		},
		{
			name:      "wrong-kind locator on subscription",
			input:     strings.Replace(validSubDecl, "subscription_url: https://example.com/sub", "wireguard_path: /etc/wireguard/wg0.conf", 1),
			wantPaths: []string{"sources[0].wireguard_path", "sources[0].subscription_url"},
		},
		{
			name:      "wrong-kind locator on wireguard_file",
			input:     strings.Replace(validWGDecl, "wireguard_path: /etc/wireguard/wg0.conf", "subscription_url: https://example.com/sub", 1),
			wantPaths: []string{"sources[0].subscription_url", "sources[0].wireguard_path"},
		},
		{
			name:      "http URL",
			input:     strings.Replace(validSubDecl, "https://example.com/sub", "http://example.com/sub", 1),
			wantPaths: []string{"sources[0].subscription_url"},
		},
		{
			name:      "userinfo URL",
			input:     strings.Replace(validSubDecl, "https://example.com/sub", "https://user:pass@example.com/sub", 1),
			wantPaths: []string{"sources[0].subscription_url"},
		},
		{
			name:      "relative wireguard_path",
			input:     strings.Replace(validWGDecl, "/etc/wireguard/wg0.conf", "relative/wg0.conf", 1),
			wantPaths: []string{"sources[0].wireguard_path"},
		},
		{
			name:      "lowercase country",
			input:     validSubDecl + "    filter:\n      countries: [us]\n",
			wantPaths: []string{"sources[0].filter.countries[0]"},
		},
		{
			name:      "duplicate countries",
			input:     validSubDecl + "    filter:\n      countries: [US, DE, US]\n",
			wantPaths: []string{"sources[0].filter.countries[2]"},
		},
		{
			name:      "max_latency 0s",
			input:     validSubDecl + "    filter:\n      max_latency: 0s\n",
			wantPaths: []string{"sources[0].filter.max_latency"},
		},
		{
			name:      "max_latency 61s",
			input:     validSubDecl + "    filter:\n      max_latency: 61s\n",
			wantPaths: []string{"sources[0].filter.max_latency"},
		},
		{
			name:      "min_successful_probes 0",
			input:     validSubDecl + "    filter:\n      min_successful_probes: 0\n",
			wantPaths: []string{"sources[0].filter.min_successful_probes"},
		},
		{
			name:      "min_successful_probes 17",
			input:     validSubDecl + "    filter:\n      min_successful_probes: 17\n",
			wantPaths: []string{"sources[0].filter.min_successful_probes"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			decl, err := Parse([]byte(tc.input))
			if decl != nil {
				t.Fatalf("expected nil declaration on error, got %v", decl)
			}
			assertValidationProblem(t, err, tc.wantPaths...)
		})
	}
}

func TestLoadFileChecks(t *testing.T) {
	dir := t.TempDir()

	validSubYAML := []byte("schema: 1\nsources:\n  - id: sub-a\n    kind: subscription\n    slot: 1\n    interval: 5m\n    subscription_url: https://example.com/sub\n")
	wgDeclFor := func(wgPath string) []byte {
		return []byte(fmt.Sprintf("schema: 1\nsources:\n  - id: wg-a\n    kind: wireguard_file\n    slot: 1\n    interval: 5m\n    wireguard_path: %q\n", wgPath))
	}

	decl0600 := writeTempFile(t, dir, "valid.yaml", validSubYAML, 0o600)
	decl0644 := writeTempFile(t, dir, "decl-0644.yaml", validSubYAML, 0o644)
	declSymlink := filepath.Join(dir, "decl-link.yaml")
	if err := os.Symlink(decl0600, declSymlink); err != nil {
		t.Fatalf("symlink declaration: %v", err)
	}
	declDir := filepath.Join(dir, "decl-dir")
	if err := os.Mkdir(declDir, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", declDir, err)
	}

	oversizedPrefix := string(validSubYAML) + "# "
	oversizedBytes := []byte(oversizedPrefix + strings.Repeat("a", MaxDeclarationBytes+1-len(oversizedPrefix)))
	declOversized := writeTempFile(t, dir, "oversized.yaml", oversizedBytes, 0o600)

	wgMissing := filepath.Join(dir, "missing-wg.conf")
	declWGMissing := writeTempFile(t, dir, "wg-missing.yaml", wgDeclFor(wgMissing), 0o600)

	wg0644 := writeTempFile(t, dir, "wg-0644.conf", []byte("[Interface]\n"), 0o644)
	declWG0644 := writeTempFile(t, dir, "wg-0644.yaml", wgDeclFor(wg0644), 0o600)

	wgTarget := writeTempFile(t, dir, "wg-target.conf", []byte("[Interface]\n"), 0o600)
	wgSymlink := filepath.Join(dir, "wg-link.conf")
	if err := os.Symlink(wgTarget, wgSymlink); err != nil {
		t.Fatalf("symlink wireguard file: %v", err)
	}
	declWGSymlink := writeTempFile(t, dir, "wg-symlink.yaml", wgDeclFor(wgSymlink), 0o600)

	tests := []struct {
		name               string
		path               string
		wantValidationPath string
		wantErrSubstr      string
	}{
		{
			name:          "declaration 0644",
			path:          decl0644,
			wantErrSubstr: "0600",
		},
		{
			name:          "symlink declaration",
			path:          declSymlink,
			wantErrSubstr: "symlink",
		},
		{
			name:          "directory declaration",
			path:          declDir,
			wantErrSubstr: "regular file",
		},
		{
			name:          "relative declaration path",
			path:          "relative/sources.yaml",
			wantErrSubstr: "absolute",
		},
		{
			name:          "oversized declaration file",
			path:          declOversized,
			wantErrSubstr: "exceeds",
		},
		{
			name:               "wireguard locator missing",
			path:               declWGMissing,
			wantValidationPath: "sources[0].wireguard_path",
			wantErrSubstr:      "does not exist",
		},
		{
			name:               "wireguard locator 0644",
			path:               declWG0644,
			wantValidationPath: "sources[0].wireguard_path",
			wantErrSubstr:      "0600",
		},
		{
			name:               "wireguard locator symlink",
			path:               declWGSymlink,
			wantValidationPath: "sources[0].wireguard_path",
			wantErrSubstr:      "symlink",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			decl, err := Load(tc.path)
			if err == nil {
				t.Fatalf("Load(%q) succeeded unexpectedly: %v", tc.path, decl)
			}
			if decl != nil {
				t.Fatalf("expected nil declaration on error, got %v", decl)
			}
			if tc.wantValidationPath != "" {
				assertValidationProblem(t, err, tc.wantValidationPath)
			}
			if !strings.Contains(err.Error(), tc.wantErrSubstr) {
				t.Errorf("error = %q, want substring %q", err.Error(), tc.wantErrSubstr)
			}
		})
	}
}

func TestRedactionAndLocator(t *testing.T) {
	const (
		secretToken = "SECRETTOKEN"
		secretDir   = "SECRETDIR"
		secretURL   = "https://example.com/api/sub/" + secretToken
		secretWG    = "/outside/" + secretDir + "/wg.conf"
	)

	validYAML := fmt.Sprintf("schema: 1\nsources:\n  - id: sub-secret\n    kind: subscription\n    slot: 1\n    interval: 5m\n    subscription_url: %s\n  - id: wg-secret\n    kind: wireguard_file\n    slot: 2\n    interval: 5m\n    wireguard_path: %q\n", secretURL, secretWG)

	decl, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatalf("Parse should not stat wireguard_path or fail on valid declaration: %v", err)
	}
	if len(decl.Sources) != 2 {
		t.Fatalf("len(Sources) = %d, want 2", len(decl.Sources))
	}

	if got := decl.Sources[0].Locator(); got != secretURL {
		t.Errorf("Sources[0].Locator() = %q, want %q", got, secretURL)
	}
	if got := decl.Sources[1].Locator(); got != secretWG {
		t.Errorf("Sources[1].Locator() = %q, want %q", got, secretWG)
	}

	assertNoSecrets(t, "Declaration.String()", decl.String(), secretToken, secretDir)
	assertNoSecrets(t, "Declaration.GoString()", decl.GoString(), secretToken, secretDir)
	assertNoSecrets(t, `fmt.Sprintf("%v", decl)`, fmt.Sprintf("%v", decl), secretToken, secretDir)
	assertNoSecrets(t, `fmt.Sprintf("%#v", decl)`, fmt.Sprintf("%#v", decl), secretToken, secretDir)

	for _, src := range decl.Sources {
		assertNoSecrets(t, src.ID()+" Source.String()", src.String(), secretToken, secretDir)
		assertNoSecrets(t, src.ID()+" Source.GoString()", src.GoString(), secretToken, secretDir)
		assertNoSecrets(t, src.ID()+` fmt.Sprintf("%v", src)`, fmt.Sprintf("%v", src), secretToken, secretDir)
		assertNoSecrets(t, src.ID()+` fmt.Sprintf("%#v", src)`, fmt.Sprintf("%#v", src), secretToken, secretDir)
	}

	dir := t.TempDir()
	secretSubdir := filepath.Join(dir, secretDir)
	wg0644 := writeTempFile(t, secretSubdir, "wg-0644.conf", []byte("[Interface]\n"), 0o644)
	wgTarget := writeTempFile(t, secretSubdir, "wg-target.conf", []byte("[Interface]\n"), 0o600)
	wgLink := filepath.Join(secretSubdir, "wg-link.conf")
	if err := os.Symlink(wgTarget, wgLink); err != nil {
		t.Fatalf("symlink %s: %v", wgLink, err)
	}

	declMissingWG := writeTempFile(t, dir, "missing-wg.yaml", []byte(validYAML), 0o600)
	declWG0644 := writeTempFile(t, dir, "wg-0644.yaml", []byte(strings.Replace(validYAML, secretWG, wg0644, 1)), 0o600)
	declWGLink := writeTempFile(t, dir, "wg-link.yaml", []byte(strings.Replace(validYAML, secretWG, wgLink, 1)), 0o600)
	decl0644InSecretDir := writeTempFile(t, secretSubdir, "decl-0644.yaml", []byte(validYAML), 0o644)

	errCases := []struct {
		name           string
		yaml           string
		loadPath       string
		wantValidation bool
	}{
		{
			name:           "parse http url and relative wg path",
			yaml:           "schema: 1\nsources:\n  - id: sub-a\n    kind: subscription\n    slot: 1\n    interval: 5m\n    subscription_url: http://example.com/api/sub/" + secretToken + "\n  - id: wg-a\n    kind: wireguard_file\n    slot: 2\n    interval: 5m\n    wireguard_path: " + secretDir + "/wg.conf\n",
			wantValidation: true,
		},
		{
			name:           "parse userinfo url and control char wg path",
			yaml:           "schema: 1\nsources:\n  - id: sub-a\n    kind: subscription\n    slot: 1\n    interval: 5m\n    subscription_url: https://user:" + secretToken + "@example.com/api/sub/" + secretToken + "\n  - id: wg-a\n    kind: wireguard_file\n    slot: 2\n    interval: 5m\n    wireguard_path: \"/outside/" + secretDir + "\\twg.conf\"\n",
			wantValidation: true,
		},
		{
			name:           "parse malformed url",
			yaml:           "schema: 1\nsources:\n  - id: sub-a\n    kind: subscription\n    slot: 1\n    interval: 5m\n    subscription_url: https://[::1/" + secretToken + "\n",
			wantValidation: true,
		},
		{
			name:           "parse wrong-kind locators",
			yaml:           "schema: 1\nsources:\n  - id: sub-a\n    kind: subscription\n    slot: 1\n    interval: 5m\n    wireguard_path: " + secretWG + "\n  - id: wg-a\n    kind: wireguard_file\n    slot: 2\n    interval: 5m\n    subscription_url: " + secretURL + "\n",
			wantValidation: true,
		},
		{
			name:           "parse valid locators with other validation errors",
			yaml:           "schema: 2\nsources:\n  - id: sub-a\n    kind: subscription\n    slot: 0\n    interval: 30s\n    subscription_url: " + secretURL + "\n    filter:\n      countries: [us]\n      max_latency: 0s\n      min_successful_probes: 0\n  - id: wg-a\n    kind: wireguard_file\n    slot: 64\n    interval: 25h\n    wireguard_path: " + secretWG + "\n",
			wantValidation: true,
		},
		{
			name:           "load missing wg path",
			loadPath:       declMissingWG,
			wantValidation: true,
		},
		{
			name:           "load 0644 wg path in secret dir",
			loadPath:       declWG0644,
			wantValidation: true,
		},
		{
			name:           "load symlink wg path in secret dir",
			loadPath:       declWGLink,
			wantValidation: true,
		},
		{
			name:           "load 0644 declaration in secret dir",
			loadPath:       decl0644InSecretDir,
			wantValidation: false,
		},
	}

	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			if tc.loadPath != "" {
				_, err = Load(tc.loadPath)
			} else {
				_, err = Parse([]byte(tc.yaml))
			}
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if tc.wantValidation {
				verr := assertValidationProblem(t, err)
				for _, p := range verr.Problems {
					assertNoSecrets(t, "Problem.String()", p.String(), secretToken, secretDir)
				}
			}
			assertNoSecrets(t, "error text", err.Error(), secretToken, secretDir)
		})
	}
}
