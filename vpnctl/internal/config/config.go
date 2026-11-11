// Package config loads and validates the vpnctl configuration file.
//
// The configuration never contains secret values: the panel API token is
// referenced only by the name of an environment variable.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is a validated vpnctl configuration.
type Config struct {
	Panel    Panel
	Nodes    []Node
	Probe    Probe
	LogLevel string
}

// Panel describes how to reach the panel API.
type Panel struct {
	URL *url.URL
	// TokenEnv is the name of the environment variable holding the API token.
	TokenEnv string
}

// Node is a VPN node.
type Node struct {
	Name    string
	Role    string
	Address string
	Port    int
}

// Probe holds probe timing settings.
type Probe struct {
	Timeout  time.Duration
	Interval time.Duration
}

// Problem is a single validation failure at a configuration path such as
// "nodes[1].port".
type Problem struct {
	Path    string
	Message string
}

func (p Problem) String() string { return p.Path + ": " + p.Message }

// ValidationError lists every validation problem found in a configuration.
type ValidationError struct {
	Problems []Problem
}

func (e *ValidationError) Error() string {
	lines := make([]string, len(e.Problems))
	for i, p := range e.Problems {
		lines[i] = p.String()
	}
	return strings.Join(lines, "\n")
}

var (
	// ErrEmpty is returned for a file without a YAML document.
	ErrEmpty = errors.New("configuration file is empty")
	// ErrMultipleDocuments is returned when a file holds more than one YAML document.
	ErrMultipleDocuments = errors.New("configuration file must contain exactly one YAML document")
)

var (
	tokenEnvPattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
	dnsLabelPattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	allDigits       = regexp.MustCompile(`^[0-9]+$`)
)

var (
	validRoles     = []string{"exit", "relay", "cp"}
	validLogLevels = []string{"debug", "info", "warn", "error"}
)

// Raw types mirror the YAML schema. Pointers distinguish missing sections
// and values from zero values; durations stay strings so that parse failures
// are reported with their configuration path.
type rawConfig struct {
	Panel    *rawPanel `yaml:"panel"`
	Nodes    []rawNode `yaml:"nodes"`
	Probe    *rawProbe `yaml:"probe"`
	LogLevel string    `yaml:"log_level"`
}

type rawPanel struct {
	URL      string `yaml:"url"`
	TokenEnv string `yaml:"token_env"`
}

type rawNode struct {
	Name    string `yaml:"name"`
	Role    string `yaml:"role"`
	Address string `yaml:"address"`
	Port    *int   `yaml:"port"`
}

type rawProbe struct {
	Timeout  string `yaml:"timeout"`
	Interval string `yaml:"interval"`
}

// Load reads, strictly decodes and validates the configuration at path.
// Validation failures are returned as *ValidationError.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	return Parse(data)
}

// Parse strictly decodes and validates configuration data.
func Parse(data []byte) (Config, error) {
	raw, err := decode(data)
	if err != nil {
		return Config{}, err
	}
	return validate(raw)
}

func decode(data []byte) (rawConfig, error) {
	var raw rawConfig
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		if errors.Is(err, io.EOF) {
			return rawConfig{}, ErrEmpty
		}
		return rawConfig{}, fmt.Errorf("parse config: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return rawConfig{}, ErrMultipleDocuments
	}
	return raw, nil
}

func validate(raw rawConfig) (Config, error) {
	var problems []Problem
	add := func(path, format string, args ...any) {
		problems = append(problems, Problem{Path: path, Message: fmt.Sprintf(format, args...)})
	}

	var cfg Config

	if raw.Panel == nil {
		add("panel", "is required")
	} else {
		cfg.Panel.URL = validatePanelURL(raw.Panel.URL, add)
		switch {
		case raw.Panel.TokenEnv == "":
			add("panel.token_env", "is required")
		case !tokenEnvPattern.MatchString(raw.Panel.TokenEnv):
			add("panel.token_env", "must be an environment variable name matching %s", tokenEnvPattern)
		default:
			cfg.Panel.TokenEnv = raw.Panel.TokenEnv
		}
	}

	if len(raw.Nodes) == 0 {
		add("nodes", "must contain at least one node")
	}
	seen := make(map[string]int)
	for i, n := range raw.Nodes {
		p := fmt.Sprintf("nodes[%d]", i)
		switch {
		case strings.TrimSpace(n.Name) == "":
			add(p+".name", "is required")
		default:
			if first, dup := seen[n.Name]; dup {
				add(p+".name", "duplicates nodes[%d].name %q", first, n.Name)
			} else {
				seen[n.Name] = i
			}
		}
		switch {
		case n.Role == "":
			add(p+".role", "is required")
		case !contains(validRoles, n.Role):
			add(p+".role", "must be one of %s, got %q", strings.Join(validRoles, ", "), n.Role)
		}
		switch {
		case n.Address == "":
			add(p+".address", "is required")
		case !validAddress(n.Address):
			add(p+".address", "must be an IPv4 address, IPv6 address or DNS name, got %q", n.Address)
		}
		switch {
		case n.Port == nil:
			add(p+".port", "is required")
		case *n.Port < 1 || *n.Port > 65535:
			add(p+".port", "must be from 1 through 65535, got %d", *n.Port)
		}
		node := Node{Name: n.Name, Role: n.Role, Address: n.Address}
		if n.Port != nil {
			node.Port = *n.Port
		}
		cfg.Nodes = append(cfg.Nodes, node)
	}

	if raw.Probe == nil {
		add("probe", "is required")
	} else {
		cfg.Probe.Timeout = positiveDuration("probe.timeout", raw.Probe.Timeout, add)
		cfg.Probe.Interval = positiveDuration("probe.interval", raw.Probe.Interval, add)
	}

	switch {
	case raw.LogLevel == "":
		add("log_level", "is required")
	case !contains(validLogLevels, raw.LogLevel):
		add("log_level", "must be one of %s, got %q", strings.Join(validLogLevels, ", "), raw.LogLevel)
	default:
		cfg.LogLevel = raw.LogLevel
	}

	if len(problems) > 0 {
		return Config{}, &ValidationError{Problems: problems}
	}
	return cfg, nil
}

func validatePanelURL(raw string, add func(path, format string, args ...any)) *url.URL {
	const path = "panel.url"
	if raw == "" {
		add(path, "is required")
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		// url.Error repeats the input, which may contain credentials.
		add(path, "is not a valid URL")
		return nil
	}
	ok := true
	if u.Scheme != "https" {
		add(path, "must use https")
		ok = false
	}
	if u.User != nil {
		add(path, "must not contain userinfo")
		ok = false
	}
	if u.Hostname() == "" {
		add(path, "must have a host")
		ok = false
	}
	if !ok {
		return nil
	}
	return u
}

func positiveDuration(path, raw string, add func(path, format string, args ...any)) time.Duration {
	if raw == "" {
		add(path, "is required")
		return 0
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		add(path, "must be a Go duration such as 5s, got %q", raw)
		return 0
	}
	if d <= 0 {
		add(path, "must be positive, got %s", raw)
		return 0
	}
	return d
}

func validAddress(s string) bool {
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.Zone() == ""
	}
	return validDNSName(s)
}

func validDNSName(s string) bool {
	if len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	for _, label := range labels {
		if !dnsLabelPattern.MatchString(label) {
			return false
		}
	}
	// A numeric last label is a malformed IP address, not a host name.
	return !allDigits.MatchString(labels[len(labels)-1])
}

func contains(values []string, s string) bool {
	for _, v := range values {
		if v == s {
			return true
		}
	}
	return false
}
