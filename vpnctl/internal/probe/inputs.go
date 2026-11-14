package probe

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// Inputs is an external, private operator document. Repository configuration
// remains credential-free; neither a panel nor DNS is contacted when loading it.
type Inputs struct {
	Schema          int         `json:"schema"`
	LocalVantage    string      `json:"local_vantage"`
	Vantages        []Vantage   `json:"vantages"`
	Nodes           []NodeInput `json:"nodes"`
	Budgets         BudgetInput `json:"budgets"`
	ThroughputFloor int64       `json:"throughput_floor_bytes_s"`
	EvidenceWindow  string      `json:"evidence_window"`
}

type NodeInput struct {
	Name              string    `json:"name"`
	IPv4              string    `json:"ipv4"`
	IPv6              string    `json:"ipv6"`
	Port              uint16    `json:"port"`
	ServerName        string    `json:"server_name"`
	ControlServerName string    `json:"control_server_name"`
	CoverIssuerSHA256 string    `json:"cover_issuer_sha256"`
	RootsFile         string    `json:"roots_file"`
	ProfileFile       string    `json:"profile_file"`
	ProfileFileEnv    string    `json:"profile_file_env"`
	Endpoints         Endpoints `json:"endpoints"`
}

type BudgetInput struct {
	Overall string `json:"overall"`
	Setup   string `json:"setup"`
	TCP     string `json:"tcp"`
	TLS     string `json:"tls"`
	Auth    string `json:"auth"`
	Small   string `json:"small"`
	Large   string `json:"large"`
	Control string `json:"control"`
}

var envPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// LoadInputs reads at most 64 KiB, requires 0600/0700 and rejects checkout files.
// Parse errors never repeat user-supplied values, filenames or raw JSON.
func LoadInputs(path string) (Inputs, error) {
	var inputs Inputs
	if err := readJSON(path, 64<<10, &inputs); err != nil {
		return Inputs{}, err
	}
	if inputs.Schema != 1 || len(inputs.Nodes) == 0 || len(inputs.Nodes) > 100 ||
		len(inputs.Vantages) == 0 || len(inputs.Vantages) > 16 {
		return Inputs{}, shortError("invalid_inputs")
	}
	seen := make(map[string]bool, len(inputs.Vantages))
	for _, vantage := range inputs.Vantages {
		if !vantage.valid() || seen[vantage.Name] {
			return Inputs{}, shortError("invalid_vantages")
		}
		seen[vantage.Name] = true
	}
	if !seen[inputs.LocalVantage] {
		return Inputs{}, shortError("local_vantage_required")
	}
	seen = make(map[string]bool, len(inputs.Nodes))
	for _, node := range inputs.Nodes {
		if !labelPattern.MatchString(node.Name) || seen[node.Name] {
			return Inputs{}, shortError("invalid_nodes")
		}
		seen[node.Name] = true
	}
	if _, err := inputs.window(); err != nil {
		return Inputs{}, err
	}
	return inputs, nil
}

// Ladder resolves exactly one declared family and actual vantage, plus the
// private client JSON and CA file the pinned core needs. An absent IPv6 address
// is an input error, never permission to try IPv4 instead.
func (i Inputs) Ladder(nodeName string, family Family, vantageName string) (LadderRequest, error) {
	request, node, err := i.resolve(nodeName, family, vantageName)
	if err != nil {
		return LadderRequest{}, err
	}
	profile := node.ProfileFile
	if node.ProfileFileEnv != "" {
		if profile != "" || !envPattern.MatchString(node.ProfileFileEnv) {
			return LadderRequest{}, shortError("invalid_profile_reference")
		}
		profile = os.Getenv(node.ProfileFileEnv)
	}
	if _, err := externalPath(profile); err != nil {
		return LadderRequest{}, shortError("invalid_profile_reference")
	}
	var roots *x509.CertPool
	if node.RootsFile != "" {
		data, err := readExternal(node.RootsFile, 64<<10, false)
		if err != nil {
			return LadderRequest{}, shortError("roots_unavailable")
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(data) {
			return LadderRequest{}, shortError("roots_invalid")
		}
	}
	request.ProfileFile, request.RootCAs = profile, roots
	return request, nil
}

// Diagnose resolves the same comparison contract without reading the private
// client JSON or CA file. Classification consumes stored observations, so a
// rotated or unavailable bundle must not block re-diagnosis of existing evidence.
func (i Inputs) Diagnose(nodeName string, family Family, vantageName string) (LadderRequest, error) {
	request, _, err := i.resolve(nodeName, family, vantageName)
	return request, err
}

func (i Inputs) resolve(nodeName string, family Family, vantageName string) (LadderRequest, NodeInput, error) {
	if vantageName == "" {
		vantageName = i.LocalVantage
	}
	var vantage Vantage
	found := false
	for _, candidate := range i.Vantages {
		if candidate.Name == vantageName {
			vantage, found = candidate, true
			break
		}
	}
	if !found {
		return LadderRequest{}, NodeInput{}, shortError("unknown_vantage")
	}
	var node NodeInput
	found = false
	for _, candidate := range i.Nodes {
		if candidate.Name == nodeName {
			node, found = candidate, true
			break
		}
	}
	if !found {
		return LadderRequest{}, NodeInput{}, shortError("unknown_node")
	}
	address := node.IPv4
	if family == IPv6 {
		address = node.IPv6
	}
	ip, err := netip.ParseAddr(address)
	if err != nil {
		return LadderRequest{}, NodeInput{}, shortError("family_unconfigured")
	}
	budgets, err := i.Budgets.parse()
	if err != nil {
		return LadderRequest{}, NodeInput{}, err
	}
	profileAddress, addressErr := netip.ParseAddr(node.IPv4)
	if addressErr != nil {
		profileAddress = ip
	}
	request := LadderRequest{
		Node: node.Name, Target: Target{Address: ip, Port: node.Port, Family: family, Timeout: budgets.Overall},
		ServerName: node.ServerName, ControlServerName: node.ControlServerName,
		CoverIssuerSHA256: node.CoverIssuerSHA256,
		ProfileAddress:    profileAddress,
		Vantage:           vantage, Budgets: budgets, Endpoints: node.Endpoints, ThroughputFloor: i.ThroughputFloor,
	}
	if err := request.validate(); err != nil {
		return LadderRequest{}, NodeInput{}, err
	}
	return request, node, nil
}

func (i Inputs) window() (time.Duration, error) {
	window, err := time.ParseDuration(i.EvidenceWindow)
	if err != nil || window <= 0 || window > 30*time.Minute {
		return 0, shortError("invalid_evidence_window")
	}
	return window, nil
}

func (b BudgetInput) parse() (Budgets, error) {
	values := []string{b.Overall, b.Setup, b.TCP, b.TLS, b.Auth, b.Small, b.Large, b.Control}
	parsed := make([]time.Duration, len(values))
	for index, value := range values {
		duration, err := time.ParseDuration(value)
		if err != nil {
			return Budgets{}, shortError("invalid_budgets")
		}
		parsed[index] = duration
	}
	budgets := Budgets{
		Overall: parsed[0], Setup: parsed[1], TCP: parsed[2], TLS: parsed[3],
		Auth: parsed[4], Small: parsed[5], Large: parsed[6], Control: parsed[7],
	}
	return budgets, budgets.validate()
}

func readJSON(path string, limit int64, value any) error {
	data, err := readExternal(path, limit, true)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return shortError("input_invalid_json")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return shortError("input_invalid_json")
	}
	return nil
}

func externalPath(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", shortError("external_absolute_path_required")
	}
	absolute := filepath.Clean(path)
	// Check both lexical and canonical ancestry; symlinked checkout directories
	// must not circumvent the no-repository-input rule.
	for _, candidate := range []string{absolute, canonicalParent(absolute)} {
		for directory := filepath.Dir(candidate); ; directory = filepath.Dir(directory) {
			if _, err := os.Lstat(filepath.Join(directory, ".git")); err == nil {
				return "", shortError("repository_input_forbidden")
			} else if !os.IsNotExist(err) {
				return "", shortError("input_unavailable")
			}
			if parent := filepath.Dir(directory); parent == directory {
				break
			}
		}
	}
	return absolute, nil
}

func canonicalParent(path string) string {
	directory, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return path
	}
	return filepath.Join(directory, filepath.Base(path))
}

func readExternal(path string, limit int64, private bool) ([]byte, error) {
	absolute, err := externalPath(path)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(absolute)
	if err != nil || !info.Mode().IsRegular() || (private && info.Mode().Perm() != 0o600) {
		return nil, shortError("input_unavailable")
	}
	if private {
		parent, err := os.Stat(filepath.Dir(absolute))
		if err != nil || !parent.IsDir() || parent.Mode().Perm() != 0o700 {
			return nil, shortError("private_directory_required")
		}
	}
	file, err := os.Open(absolute)
	if err != nil {
		return nil, shortError("input_unavailable")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || opened.Size() > limit {
		return nil, shortError("input_unavailable")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, shortError("input_unavailable")
	}
	return data, nil
}
