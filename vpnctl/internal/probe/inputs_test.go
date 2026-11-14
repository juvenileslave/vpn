package probe

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func privateFixture(t *testing.T, name string, value any) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func fixtureRequest(t *testing.T) LadderRequest {
	t.Helper()
	budgets := Budgets{Overall: 30 * time.Second, Setup: time.Second, TCP: time.Second, TLS: time.Second,
		Auth: 3 * time.Second, Small: 5 * time.Second, Large: 10 * time.Second, Control: time.Second}
	endpoint := Endpoint{Address: netip.MustParseAddr("192.0.2.100"), Port: 18081, URL: "http://payload.example.test/fixture", SHA256: strings.Repeat("a", 64)}
	auth, small, large := endpoint, endpoint, endpoint
	auth.Bytes, small.Bytes, large.Bytes = 256, SmallBytes, LargeBytes
	return LadderRequest{Node: "exit-test", Target: Target{Address: netip.MustParseAddr("192.0.2.10"), Port: 18443,
		Family: IPv4, Timeout: budgets.Overall}, ServerName: "cover.example.test", Vantage: testPlan().Vantages[0],
		Budgets: budgets, Endpoints: Endpoints{Auth: auth, Small: small, Large: large}, ThroughputFloor: 1 << 20}
}

func fixtureProfile(t *testing.T, request LadderRequest) (map[string]any, []string) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	encoded := hex.EncodeToString(random[:])
	id := encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
	shortID := encoded[:16]
	password := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	data := map[string]any{
		"log":      map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{"tag": "local", "listen": "127.0.0.1", "port": 1080, "protocol": "socks", "settings": map[string]any{"udp": false}}},
		"outbounds": []any{map[string]any{"tag": "proxy", "protocol": "vless",
			"settings": map[string]any{"vnext": []any{map[string]any{"address": request.Target.Address.String(), "port": request.Target.Port,
				"users": []any{map[string]any{"id": id, "encryption": "none"}}}}},
			"streamSettings": map[string]any{"network": "xhttp", "security": "reality",
				"xhttpSettings": map[string]any{"mode": "stream-one", "path": "/test-path", "xPaddingBytes": "100-1000"},
				"realitySettings": map[string]any{"show": false, "serverName": request.ServerName,
					"fingerprint": "firefox", "password": password, "shortId": shortID}}},
			map[string]any{"tag": "block", "protocol": "blackhole"}},
		"routing": map[string]any{"rules": []any{map[string]any{"type": "field", "network": "tcp,udp", "outboundTag": "proxy"}}},
	}
	return data, []string{id, shortID, password}
}

func fixtureInputs(request LadderRequest, node NodeInput) Inputs {
	return Inputs{Schema: 1, LocalVantage: "inside", Vantages: testPlan().Vantages, Nodes: []NodeInput{node},
		Budgets:         BudgetInput{Overall: "30s", Setup: "1s", TCP: "1s", TLS: "1s", Auth: "3s", Small: "5s", Large: "10s", Control: "1s"},
		ThroughputFloor: request.ThroughputFloor, EvidenceWindow: "10m"}
}

func hasCode(err error, want string) bool {
	code, ok := Code(err)
	return ok && code == want
}

// Classification reads stored observations, so diagnose must not depend on a
// client bundle that may be rotated away after the ladder run was recorded.
func TestDiagnoseNeedsOnlyTheComparisonContract(t *testing.T) {
	t.Setenv("VPNCTL_TEST_ABSENT_PROFILE", "")
	request := fixtureRequest(t)
	profile, _ := fixtureProfile(t, request)
	profilePath := privateFixture(t, "client.json", profile)
	rootsPath := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(rootsPath, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	node := NodeInput{Name: request.Node, IPv4: request.Target.Address.String(), Port: request.Target.Port,
		ServerName: request.ServerName, Endpoints: request.Endpoints}
	missingProfile := node
	missingProfile.ProfileFileEnv, missingProfile.RootsFile = "VPNCTL_TEST_ABSENT_PROFILE", rootsPath
	invalidRoots := node
	invalidRoots.ProfileFile, invalidRoots.RootsFile = profilePath, rootsPath
	tests := []struct {
		name string
		node NodeInput
		code string
	}{
		{name: "missing profile environment", node: missingProfile, code: "invalid_profile_reference"},
		{name: "invalid roots file", node: invalidRoots, code: "roots_invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := privateFixture(t, "inputs.json", fixtureInputs(request, test.node))
			loaded, err := LoadInputs(path)
			if err != nil {
				t.Fatal(err)
			}
			diagnosis, err := loaded.Diagnose(request.Node, IPv4, "")
			if err != nil {
				t.Fatalf("diagnose requires the private bundle: %v", err)
			}
			if diagnosis.Target.Address != request.Target.Address || diagnosis.Endpoints != request.Endpoints {
				t.Fatalf("diagnose contract changed: %+v", diagnosis)
			}
			if _, err := loaded.Ladder(request.Node, IPv4, ""); !hasCode(err, test.code) {
				t.Fatalf("ladder accepted the private bundle: %v", err)
			}
		})
	}
}

func TestUnknownNodeAndVantageAreDistinctInputErrors(t *testing.T) {
	request := fixtureRequest(t)
	profile, _ := fixtureProfile(t, request)
	node := NodeInput{Name: request.Node, IPv4: request.Target.Address.String(), Port: request.Target.Port,
		ServerName: request.ServerName, ProfileFile: privateFixture(t, "client.json", profile), Endpoints: request.Endpoints}
	path := privateFixture(t, "inputs.json", fixtureInputs(request, node))
	loaded, err := LoadInputs(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loaded.Ladder("absent-node", IPv4, ""); !hasCode(err, "unknown_node") {
		t.Fatalf("unknown node code = %v", err)
	}
	if _, err := loaded.Diagnose(request.Node, IPv4, "absent-vantage"); !hasCode(err, "unknown_vantage") {
		t.Fatalf("unknown vantage code = %v", err)
	}
	loaded.Nodes[0].IPv6 = ""
	if _, err := loaded.Ladder(request.Node, IPv6, ""); !hasCode(err, "family_unconfigured") {
		t.Fatalf("missing IPv6 code = %v", err)
	}
}

func TestExternalInputsDoNotFallbackAddressFamily(t *testing.T) {
	request := fixtureRequest(t)
	profile, _ := fixtureProfile(t, request)
	profilePath := privateFixture(t, "client.json", profile)
	inputs := Inputs{Schema: 1, LocalVantage: "inside", Vantages: testPlan().Vantages,
		Nodes: []NodeInput{{Name: request.Node, IPv4: request.Target.Address.String(), Port: request.Target.Port,
			ServerName: request.ServerName, ProfileFile: profilePath, Endpoints: request.Endpoints}},
		Budgets:         BudgetInput{Overall: "30s", Setup: "1s", TCP: "1s", TLS: "1s", Auth: "3s", Small: "5s", Large: "10s", Control: "1s"},
		ThroughputFloor: request.ThroughputFloor, EvidenceWindow: "10m"}
	path := privateFixture(t, "inputs.json", inputs)
	loaded, err := LoadInputs(path)
	if err != nil {
		t.Fatal(err)
	}
	ipv4, err := loaded.Ladder(request.Node, IPv4, "")
	if err != nil || ipv4.Target.Address != request.Target.Address || ipv4.Target.Family != IPv4 {
		t.Fatalf("explicit IPv4 = %+v, %v", ipv4.Target, err)
	}
	if _, err := loaded.Ladder(request.Node, IPv6, ""); err == nil || !strings.Contains(err.Error(), "family_unconfigured") {
		t.Fatalf("missing IPv6 silently fell back: %v", err)
	}
	loaded.Nodes[0].IPv6 = "::ffff:192.0.2.10"
	if _, err := loaded.Ladder(request.Node, IPv6, ""); err == nil {
		t.Fatal("mapped IPv4 was accepted as IPv6")
	}
}

func TestPrivateInputsRejectPermissionsSymlinksAndCheckout(t *testing.T) {
	for _, kind := range []string{"file-mode", "directory-mode", "symlink", "checkout", "unknown-json", "trailing-json"} {
		t.Run(kind, func(t *testing.T) {
			path := privateFixture(t, "inputs.json", map[string]string{"canary": "private-value-canary"})
			switch kind {
			case "file-mode":
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			case "directory-mode":
				if err := os.Chmod(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				link := filepath.Join(filepath.Dir(path), "link.json")
				if err := os.Symlink(path, link); err != nil {
					t.Fatal(err)
				}
				path = link
			case "checkout":
				if err := os.Mkdir(filepath.Join(filepath.Dir(path), ".git"), 0o700); err != nil {
					t.Fatal(err)
				}
			case "trailing-json":
				if err := os.WriteFile(path, []byte(`{} {"private-value-canary":true}`), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := LoadInputs(path); err == nil || strings.Contains(err.Error(), "private-value-canary") || strings.Contains(err.Error(), path) {
				t.Fatalf("unsafe input accepted or disclosed: %v", err)
			}
		})
	}
}

func TestAcceptedProfileCannotAddFallbackOrRevealCredentials(t *testing.T) {
	for _, kind := range []string{"valid", "freedom", "wrong-transport", "wrong-sni", "wrong-address", "extra-log", "mux"} {
		t.Run(kind, func(t *testing.T) {
			request := fixtureRequest(t)
			profile, canaries := fixtureProfile(t, request)
			proxy := profile["outbounds"].([]any)[0].(map[string]any)
			stream := proxy["streamSettings"].(map[string]any)
			switch kind {
			case "freedom":
				profile["outbounds"].([]any)[1].(map[string]any)["protocol"] = "freedom"
			case "wrong-transport":
				stream["network"] = "tcp"
			case "wrong-sni":
				stream["realitySettings"].(map[string]any)["serverName"] = "other.example.test"
			case "wrong-address":
				proxy["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["address"] = "192.0.2.99"
			case "extra-log":
				profile["log"].(map[string]any)["access"] = "/private-value-canary"
			case "mux":
				proxy["mux"] = map[string]any{"enabled": true}
			}
			request.ProfileFile = privateFixture(t, "client.json", profile)
			_, err := loadProfile(&request)
			if kind == "valid" && err != nil {
				t.Fatal(err)
			}
			if kind != "valid" && err == nil {
				t.Fatal("non-accepted profile was accepted")
			}
			if err != nil {
				for _, canary := range canaries {
					if strings.Contains(err.Error(), canary) {
						t.Fatal("credential leaked")
					}
				}
			}
		})
	}
}

func TestSecretEndpointInputNeverAppearsInError(t *testing.T) {
	for _, url := range []string{"http://user:private-value-canary@example.test/", "http://example.test/?token=private-value-canary"} {
		request := fixtureRequest(t)
		request.Endpoints.Auth.URL = url
		if err := request.validate(); err == nil || strings.Contains(err.Error(), "private-value-canary") {
			t.Fatalf("unsafe endpoint accepted or exposed: %v", err)
		}
	}
}
