package panel

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	bundleCoreVersion = "26.11.9"
	bundleNodeImage   = "ghcr.io/remnawave/node:3.4.5@sha256:8f5a41708dfa86acc2561a520c9b40e2ff30812a16c28cf6bba6c365ca0f7d65"
	maxBundleBytes    = 64 << 20
)

var clientFilePattern = regexp.MustCompile(`^clients/(direct|relay)-(0|[1-9][0-9]*)\.json$`)

type bundleManifest struct {
	Schema      int                     `json:"schema"`
	ID          string                  `json:"bundle_id"`
	State       string                  `json:"state"`
	CoreVersion string                  `json:"core_version"`
	NodeImage   string                  `json:"node_image"`
	SlotFanout  string                  `json:"slot_fanout"`
	Hosts       map[string]manifestHost `json:"hosts"`
	Files       []string                `json:"files"`
}

type manifestHost struct {
	SNI    string `json:"reality_sni"`
	IPv4   string `json:"public_ipv4"`
	IPv6   string `json:"public_ipv6"`
	Origin string `json:"origin"`
}

// LoadBundle verifies the existing renderer's immutable version, not a second
// render or a runtime receipt. path is its manifest.json file. The fingerprint
// includes inputs.private.json, but no private payload is returned or displayed.
func LoadBundle(path string) (Bundle, error) {
	root, name, err := openFileRoot(path)
	if err != nil {
		return Bundle{}, err
	}
	defer root.Close()
	if name != "manifest.json" {
		return Bundle{}, ErrInvalidInput
	}
	manifestData, err := readRootJSON(root, name)
	if err != nil {
		return Bundle{}, err
	}
	var manifest bundleManifest
	if err := decodeStrict(manifestData, &manifest); err != nil {
		return Bundle{}, err
	}
	if err := validateManifest(manifest); err != nil {
		return Bundle{}, err
	}

	names := append([]string{}, manifest.Files...)
	names = append(names, "inputs.private.json")
	sort.Strings(names)
	hash := sha256.New()
	writer := bufio.NewWriter(hash)
	if _, err := writer.WriteString("{"); err != nil {
		return Bundle{}, ErrInvalidInput
	}
	bundle := Bundle{
		ID:      manifest.ID,
		Hosts:   make(map[string]BundleHost, len(manifest.Hosts)),
		Configs: make(map[string]json.RawMessage, 2),
	}
	for role, host := range manifest.Hosts {
		bundle.Hosts[role] = BundleHost{SNI: host.SNI, IPv4: host.IPv4, IPv6: host.IPv6, Origin: host.Origin}
	}
	total := len(manifestData)
	for index, filename := range names {
		data, err := readRootJSON(root, filename)
		if err != nil {
			return Bundle{}, err
		}
		total += len(data)
		if total > maxBundleBytes {
			return Bundle{}, ErrInvalidInput
		}
		if _, err := jsonValue(data); err != nil {
			return Bundle{}, err
		}
		if index != 0 {
			if _, err := writer.WriteString(", "); err != nil {
				return Bundle{}, ErrInvalidInput
			}
		}
		if err := writePythonJSONString(writer, []byte(filename)); err != nil {
			return Bundle{}, err
		}
		if _, err := writer.WriteString(": "); err != nil {
			return Bundle{}, ErrInvalidInput
		}
		if err := writePythonJSONString(writer, data); err != nil {
			return Bundle{}, err
		}
		if filename == "exit.json" || filename == "relay.json" {
			bundle.Configs[strings.TrimSuffix(filename, ".json")] = data
		}
	}
	if _, err := writer.WriteString("}"); err != nil {
		return Bundle{}, ErrInvalidInput
	}
	if err := writer.Flush(); err != nil {
		return Bundle{}, ErrInvalidInput
	}
	if hex.EncodeToString(hash.Sum(nil)) != manifest.ID {
		return Bundle{}, ErrInvalidInput
	}
	if err := validateBundlePolicy(bundle); err != nil {
		return Bundle{}, err
	}
	return bundle, nil
}

func validateManifest(manifest bundleManifest) error {
	validVersion := manifest.Schema == 1 && manifest.CoreVersion == bundleCoreVersion && manifest.NodeImage == bundleNodeImage
	validState := manifest.State == "candidate-not-runtime-validated" && manifest.SlotFanout == "ports"
	if !validVersion || !validState || !bundleIDPattern.MatchString(manifest.ID) {
		return ErrInvalidInput
	}
	if len(manifest.Hosts) != 2 || len(manifest.Files) < 3 {
		return ErrInvalidInput
	}
	for _, role := range []string{"exit", "relay"} {
		if _, exists := manifest.Hosts[role]; !exists {
			return ErrInvalidInput
		}
	}
	files := make(map[string]bool, len(manifest.Files))
	for _, filename := range manifest.Files {
		known := filename == "exit.json" || filename == "relay.json" || filename == "firewall.json"
		if (!known && !clientFilePattern.MatchString(filename)) || files[filename] {
			return ErrInvalidInput
		}
		files[filename] = true
	}
	if !files["exit.json"] || !files["relay.json"] || !files["firewall.json"] {
		return ErrInvalidInput
	}
	return nil
}

func openFileRoot(path string) (*os.Root, string, error) {
	if path == "" || strings.ContainsRune(path, 0) {
		return nil, "", ErrInvalidInput
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, "", ErrInvalidInput
	}
	root, err := os.OpenRoot(filepath.Dir(absolute))
	if err != nil {
		return nil, "", ErrInvalidInput
	}
	return root, filepath.Base(absolute), nil
}

func readRegularJSON(path string) ([]byte, error) {
	root, name, err := openFileRoot(path)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return readRootJSON(root, name)
}

func readRootJSON(root *os.Root, name string) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxJSONBytes {
		return nil, ErrInvalidInput
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, ErrInvalidInput
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, ErrInvalidInput
	}
	data, err := io.ReadAll(io.LimitReader(file, maxJSONBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxJSONBytes || !utf8.Valid(data) {
		return nil, ErrInvalidInput
	}
	return data, nil
}

// The renderer hashes Python json.dumps(serialized, sort_keys=True), including
// its default spaces and ensure_ascii escaping. Hash the original file bytes;
// canonicalizing them would accept tampering with an immutable version.
func writePythonJSONString(writer *bufio.Writer, data []byte) error {
	if err := writer.WriteByte('"'); err != nil {
		return ErrInvalidInput
	}
	for len(data) > 0 {
		r, size := utf8.DecodeRune(data)
		data = data[size:]
		var escaped string
		switch r {
		case '"':
			escaped = `\"`
		case '\\':
			escaped = `\\`
		case '\b':
			escaped = `\b`
		case '\f':
			escaped = `\f`
		case '\n':
			escaped = `\n`
		case '\r':
			escaped = `\r`
		case '\t':
			escaped = `\t`
		default:
			if r >= 0x20 && r < 0x7f {
				if err := writer.WriteByte(byte(r)); err != nil {
					return ErrInvalidInput
				}
				continue
			}
			if r > 0xffff {
				first, second := utf16.EncodeRune(r)
				if err := writeUnicodeEscape(writer, uint16(first)); err != nil {
					return err
				}
				if err := writeUnicodeEscape(writer, uint16(second)); err != nil {
					return err
				}
				continue
			}
			if err := writeUnicodeEscape(writer, uint16(r)); err != nil {
				return err
			}
			continue
		}
		if _, err := writer.WriteString(escaped); err != nil {
			return ErrInvalidInput
		}
	}
	if err := writer.WriteByte('"'); err != nil {
		return ErrInvalidInput
	}
	return nil
}

func writeUnicodeEscape(writer *bufio.Writer, value uint16) error {
	const digits = "0123456789abcdef"
	data := [6]byte{'\\', 'u', digits[value>>12], digits[(value>>8)&15], digits[(value>>4)&15], digits[value&15]}
	if _, err := writer.Write(data[:]); err != nil {
		return ErrInvalidInput
	}
	return nil
}

func integerField(object map[string]json.RawMessage, name string) (int64, bool) {
	raw := object[name]
	value, err := strconv.ParseInt(string(raw), 10, 64)
	if err == nil {
		return value, true
	}
	// Canonical represents exact powers of ten as decimal exponents.
	var number json.Number
	if json.Unmarshal(raw, &number) != nil {
		return 0, false
	}
	parts := strings.Split(string(number), "e")
	if len(parts) != 2 {
		return 0, false
	}
	exponent, err := strconv.Atoi(parts[1])
	if err != nil || exponent < 0 || exponent > 18 {
		return 0, false
	}
	value, err = strconv.ParseInt(parts[0]+strings.Repeat("0", exponent), 10, 64)
	return value, err == nil
}

func hasJSONValue(raw json.RawMessage, expected any) bool {
	encoded, err := json.Marshal(expected)
	if err != nil {
		return false
	}
	left, err := Canonical(raw)
	if err != nil {
		return false
	}
	right, err := Canonical(encoded)
	return err == nil && bytes.Equal(left, right)
}
