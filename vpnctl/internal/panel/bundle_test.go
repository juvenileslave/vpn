package panel

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func temporaryUUID(t *testing.T) string {
	t.Helper()
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		t.Fatal(err)
	}
	data[6] = data[6]&15 | 64
	data[8] = data[8]&63 | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", data[:4], data[4:6], data[6:8], data[8:10], data[10:])
}

func fixtureJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func policyBundle(t *testing.T) Bundle {
	t.Helper()
	bundle := Bundle{
		ID: strings.Repeat("a", 64),
		Hosts: map[string]BundleHost{
			"exit":  {SNI: "exit.example.test", IPv4: "192.0.2.10", IPv6: "2001:db8::10", Origin: "127.0.0.1:9443"},
			"relay": {SNI: "relay.example.test", IPv4: "192.0.2.20", IPv6: "2001:db8::20", Origin: "127.0.0.1:9443"},
		},
		Configs: make(map[string]json.RawMessage, 2),
	}
	private := make([]byte, 32)
	if _, err := rand.Read(private); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"exit", "relay"} {
		tags := []string{"direct-v4", "direct-v6", "transit-v4", "transit-v6"}
		if role == "relay" {
			tags = []string{"slot-0-v4", "slot-0-v6"}
		}
		inbounds := make([]any, 0, len(tags))
		id := temporaryUUID(t)
		for _, tag := range tags {
			listen := "0.0.0.0"
			if strings.HasSuffix(tag, "-v6") {
				listen = "::"
			}
			port := 18440
			if strings.HasPrefix(tag, "transit-") {
				port = 18444
			}
			inbounds = append(inbounds, map[string]any{
				"tag": tag, "listen": listen, "port": port, "protocol": "vless",
				"settings": map[string]any{"decryption": "none", "clients": []any{map[string]any{"id": id, "email": "synthetic"}}},
				"streamSettings": map[string]any{
					"network": "xhttp", "security": "reality",
					"xhttpSettings": map[string]any{"path": "/vpn", "mode": "stream-one", "xPaddingBytes": "100-1000"},
					"realitySettings": map[string]any{
						"dest": bundle.Hosts[role].Origin, "serverNames": []string{bundle.Hosts[role].SNI},
						"privateKey": base64.RawURLEncoding.EncodeToString(private), "shortIds": []string{"0123456789abcdef"},
						"xver": 0, "show": false, "maxTimeDiff": 300000,
					},
				},
			})
		}
		config := map[string]any{
			"log": map[string]string{"loglevel": "warning"}, "inbounds": inbounds,
			"outbounds": []any{map[string]string{"tag": "block", "protocol": "blackhole"}},
			"routing":   map[string]any{"rules": []any{map[string]string{"type": "field", "network": "tcp,udp", "outboundTag": "block"}}},
		}
		bundle.Configs[role] = fixtureJSON(t, config)
	}
	return bundle
}

// fixtureManifest uses an independent ASCII JSON encoder for the renderer's
// outer hash envelope. Production's Python string-escaping helper is not used.
func fixtureManifest(t *testing.T, root string, bundle Bundle) string {
	t.Helper()
	files := map[string]string{
		"exit.json":     string(bundle.Configs["exit"]) + "\n",
		"relay.json":    string(bundle.Configs["relay"]) + "\n",
		"firewall.json": "{}\n", "inputs.private.json": "{\"synthetic\":true}\n",
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	entries := make([]string, 0, len(files))
	publicFiles := make([]string, 0, len(files)-1)
	for _, name := range names {
		content := files[name]
		encodedName := fixtureJSON(t, name)
		encodedValue := fixtureJSON(t, content)
		entries = append(entries, string(encodedName)+": "+string(encodedValue))
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if name != "inputs.private.json" {
			publicFiles = append(publicFiles, name)
		}
	}
	identity := sha256.Sum256([]byte("{" + strings.Join(entries, ", ") + "}"))
	hosts := make(map[string]manifestHost, len(bundle.Hosts))
	for role, host := range bundle.Hosts {
		hosts[role] = manifestHost{SNI: host.SNI, IPv4: host.IPv4, IPv6: host.IPv6, Origin: host.Origin}
	}
	manifest := bundleManifest{
		Schema: 1, ID: hex.EncodeToString(identity[:]), State: "candidate-not-runtime-validated",
		CoreVersion: bundleCoreVersion, NodeImage: bundleNodeImage, SlotFanout: "ports", Hosts: hosts, Files: publicFiles,
	}
	path := filepath.Join(root, "manifest.json")
	if err := os.WriteFile(path, fixtureJSON(t, manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadBundlePreservesRendererBytesAndRedacts(t *testing.T) {
	original := policyBundle(t)
	path := fixtureManifest(t, t.TempDir(), original)
	loaded, err := LoadBundle(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"exit", "relay"} {
		if !bytes.Equal(loaded.Configs[role], append(original.Configs[role], '\n')) || loaded.Hosts[role] != original.Hosts[role] {
			t.Fatal("loader altered the existing renderer payload")
		}
	}
	encoded, err := json.Marshal(loaded)
	if err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{fmt.Sprintf("%v %+v %#v", loaded, loaded, loaded), string(encoded)} {
		if strings.Contains(output, "privateKey") || strings.Contains(output, "exit.example.test") {
			t.Fatal("bundle output exposed payload")
		}
	}
}

func TestLoadBundleRejectsTamperingMissingAndSymlinkFiles(t *testing.T) {
	for _, test := range []string{"bytes changed", "missing private inputs", "external symlink", "duplicate file", "unknown manifest field"} {
		t.Run(test, func(t *testing.T) {
			root := t.TempDir()
			path := fixtureManifest(t, root, policyBundle(t))
			switch test {
			case "bytes changed":
				file, err := os.OpenFile(filepath.Join(root, "exit.json"), os.O_APPEND|os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := file.WriteString(" "); err != nil {
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			case "missing private inputs":
				if err := os.Remove(filepath.Join(root, "inputs.private.json")); err != nil {
					t.Fatal(err)
				}
			case "external symlink":
				outside := filepath.Join(t.TempDir(), "outside.json")
				if err := os.Rename(filepath.Join(root, "exit.json"), outside); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, filepath.Join(root, "exit.json")); err != nil {
					t.Fatal(err)
				}
			case "duplicate file", "unknown manifest field":
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var value map[string]any
				if err := json.Unmarshal(data, &value); err != nil {
					t.Fatal(err)
				}
				if test == "duplicate file" {
					value["files"] = []string{"exit.json", "relay.json", "firewall.json", "exit.json"}
				} else {
					value["private-token"] = "must-not-appear"
				}
				if err := os.WriteFile(path, fixtureJSON(t, value), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			_, err := LoadBundle(path)
			if !errors.Is(err, ErrInvalidInput) || strings.Contains(fmt.Sprintf("%v", err), root) {
				t.Fatal("invalid immutable bundle was not safely rejected")
			}
		})
	}
}

func TestPythonHashStringEscaping(t *testing.T) {
	// Expected output is Python json.dumps(..., ensure_ascii=True), including
	// surrogate pairs, DEL and no HTML escaping.
	var output bytes.Buffer
	writer := bufio.NewWriter(&output)
	if err := writePythonJSONString(writer, []byte("<&>\n\"\\\t\x7fЖ😀")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	if output.String() != `"<&>\n\"\\\t\u007f\u0416\ud83d\ude00"` {
		t.Fatal("renderer hash string contract changed")
	}
}

func TestLoadBundleRejectsConflictingPublicationPolicy(t *testing.T) {
	for _, key := range []string{"serverNames", "dest", "mode", "privateKey"} {
		t.Run(key, func(t *testing.T) {
			bundle := policyBundle(t)
			var config map[string]any
			if err := json.Unmarshal(bundle.Configs["exit"], &config); err != nil {
				t.Fatal(err)
			}
			inbound := config["inbounds"].([]any)[0].(map[string]any)
			stream := inbound["streamSettings"].(map[string]any)
			reality := stream["realitySettings"].(map[string]any)
			switch key {
			case "serverNames":
				reality[key] = []string{"foreign.example.test"}
			case "dest":
				reality[key] = "192.0.2.99:443"
			case "mode":
				stream["xhttpSettings"].(map[string]any)[key] = "auto"
			case "privateKey":
				reality[key] = "must-not-appear"
			}
			bundle.Configs["exit"] = fixtureJSON(t, config)
			path := fixtureManifest(t, t.TempDir(), bundle)
			_, err := LoadBundle(path)
			if !errors.Is(err, ErrInvalidInput) || strings.Contains(fmt.Sprintf("%v", err), "must-not-appear") {
				t.Fatal("conflicting fixed policy was not safely rejected")
			}
		})
	}
}
