package prober

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/juvenileslave/vpn/vpnctl/internal/upstream/candidate"
)

func fakeXray(t *testing.T, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "xray")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake xray: %v", err)
	}
	return path
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	return u
}

func TestNewValidation(t *testing.T) {
	executable := fakeXray(t, "#!/bin/sh\nexit 0\n")
	notExecutable := filepath.Join(t.TempDir(), "xray")
	if err := os.WriteFile(notExecutable, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	tests := []struct {
		name string
		opts Options
	}{
		{"relative xray", Options{XrayPath: "xray", ProbeURL: "https://example.com/generate_204"}},
		{"missing xray", Options{XrayPath: filepath.Join(t.TempDir(), "absent"), ProbeURL: "https://example.com/generate_204"}},
		{"non-executable xray", Options{XrayPath: notExecutable, ProbeURL: "https://example.com/generate_204"}},
		{"missing probe url", Options{XrayPath: executable}},
		{"http probe url", Options{XrayPath: executable, ProbeURL: "http://example.com/generate_204"}},
		{"userinfo probe url", Options{XrayPath: executable, ProbeURL: "https://user:pass@example.com/generate_204"}},
		{"http geo url", Options{XrayPath: executable, ProbeURL: "https://example.com/generate_204", GeoURL: "http://example.com/geo"}},
		{"too many samples", Options{XrayPath: executable, ProbeURL: "https://example.com/generate_204", Samples: 6}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.opts); !errors.Is(err, ErrInvalidOptions) {
				t.Fatalf("New error = %v, want ErrInvalidOptions", err)
			}
		})
	}

	if _, err := New(Options{
		XrayPath: executable,
		ProbeURL: "https://example.com/generate_204",
		GeoURL:   "https://example.com/geo",
		Samples:  1,
	}); err != nil {
		t.Fatalf("valid options rejected: %v", err)
	}
}

func TestBuildConfigRestrictsRouting(t *testing.T) {
	outbound := json.RawMessage(`{"protocol":"vless","tag":"upstream-slot-3","settings":{"address":"203.0.113.9"}}`)
	raw, err := buildConfig(23456, outbound, "upstream-slot-3",
		mustURL(t, "https://probe.example/generate_204"),
		mustURL(t, "https://geo.example/country"))
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}

	var cfg struct {
		Log      map[string]string `json:"log"`
		Inbounds []struct {
			Listen   string `json:"listen"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
			Tag      string `json:"tag"`
		} `json:"inbounds"`
		Outbounds []map[string]any `json:"outbounds"`
		Routing   struct {
			DomainStrategy string `json:"domainStrategy"`
			Rules          []struct {
				Type        string   `json:"type"`
				Domain      []string `json:"domain"`
				IP          []string `json:"ip"`
				OutboundTag string   `json:"outboundTag"`
			} `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("config json: %v", err)
	}
	if cfg.Log["loglevel"] != "none" {
		t.Fatalf("loglevel = %q", cfg.Log["loglevel"])
	}
	if len(cfg.Inbounds) != 1 || cfg.Inbounds[0].Listen != "127.0.0.1" || cfg.Inbounds[0].Port != 23456 || cfg.Inbounds[0].Protocol != "http" {
		t.Fatalf("inbound = %+v", cfg.Inbounds)
	}
	if len(cfg.Outbounds) != 2 || cfg.Outbounds[0]["tag"] != "upstream-slot-3" || cfg.Outbounds[1]["protocol"] != "blackhole" {
		t.Fatalf("outbounds = %+v", cfg.Outbounds)
	}
	rules := cfg.Routing.Rules
	if len(rules) != 3 {
		t.Fatalf("rules = %+v", rules)
	}
	if rules[0].OutboundTag != "upstream-slot-3" || len(rules[0].Domain) != 2 ||
		rules[0].Domain[0] != "full:probe.example" || rules[0].Domain[1] != "full:geo.example" {
		t.Fatalf("allow rule = %+v", rules[0])
	}
	if rules[1].OutboundTag != "blocked" || !contains(rules[1].IP, "127.0.0.0/8") || !contains(rules[1].IP, "fc00::/7") {
		t.Fatalf("private block rule = %+v", rules[1])
	}
	if rules[2].OutboundTag != "blocked" || len(rules[2].Domain) != 0 || len(rules[2].IP) != 0 {
		t.Fatalf("final block rule = %+v", rules[2])
	}
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func TestBuildConfigRejectsBadInputs(t *testing.T) {
	outbound := json.RawMessage(`{"protocol":"vless","tag":"upstream-slot-1"}`)
	probe := mustURL(t, "https://probe.example/generate_204")
	if _, err := buildConfig(0, outbound, "upstream-slot-1", probe, nil); !errors.Is(err, ErrConfig) {
		t.Fatalf("port error = %v", err)
	}
	if _, err := buildConfig(1000, outbound, "bad tag", probe, nil); !errors.Is(err, ErrConfig) {
		t.Fatalf("tag error = %v", err)
	}
	if _, err := buildConfig(1000, outbound, "blocked", probe, nil); !errors.Is(err, ErrConfig) {
		t.Fatalf("reserved tag error = %v", err)
	}
	if _, err := buildConfig(1000, json.RawMessage(`[]`), "upstream-slot-1", probe, nil); !errors.Is(err, ErrConfig) {
		t.Fatalf("array outbound error = %v", err)
	}
}

func TestParseCandidate(t *testing.T) {
	valid := candidate.Candidate{Outbound: json.RawMessage(`{"protocol":"vless","tag":"upstream-slot-1"}`)}
	if _, tag, err := parseCandidate(valid); err != nil || tag != "upstream-slot-1" {
		t.Fatalf("valid candidate: tag=%q err=%v", tag, err)
	}
	for _, raw := range []string{``, `[]`, `{}`, `{"tag":""}`, `{"tag":"bad tag"}`} {
		if _, _, err := parseCandidate(candidate.Candidate{Outbound: json.RawMessage(raw)}); !errors.Is(err, ErrConfig) {
			t.Fatalf("candidate %q error = %v, want ErrConfig", raw, err)
		}
	}
}

func TestCheckVersion(t *testing.T) {
	p := &Prober{
		xrayPath:     fakeXray(t, "#!/bin/sh\necho 'Xray 26.9.0 (Xray, Penetrates Everything.)'\n"),
		startTimeout: defaultStartTimeout,
		version:      "Xray 26.9.0",
	}
	if err := p.checkVersion(context.Background()); err != nil {
		t.Fatalf("matching version: %v", err)
	}
	p.version = "Xray 25."
	if err := p.checkVersion(context.Background()); !errors.Is(err, ErrCore) {
		t.Fatalf("mismatched version error = %v, want ErrCore", err)
	}
	p.xrayPath = fakeXray(t, "#!/bin/sh\nexit 7\n")
	p.version = ""
	if err := p.checkVersion(context.Background()); !errors.Is(err, ErrCore) {
		t.Fatalf("failing version error = %v, want ErrCore", err)
	}
}

func TestProbeFailsWhenCoreExits(t *testing.T) {
	path := fakeXray(t, "#!/bin/sh\nif [ \"$1\" = \"-version\" ]; then echo 'Xray 26.9.0'; exit 0; fi\nexit 1\n")
	p, err := New(Options{XrayPath: path, ProbeURL: "https://probe.example/generate_204", Samples: 1, StartTimeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cand := candidate.Candidate{Outbound: json.RawMessage(`{"protocol":"vless","tag":"upstream-slot-1"}`)}
	before, _ := filepath.Glob(filepath.Join(os.TempDir(), "vpnctl-upstream-probe-*"))
	_, err = p.Probe(context.Background(), cand)
	if !errors.Is(err, ErrStart) {
		t.Fatalf("Probe error = %v, want ErrStart", err)
	}
	after, _ := filepath.Glob(filepath.Join(os.TempDir(), "vpnctl-upstream-probe-*"))
	if len(after) != len(before) {
		t.Fatalf("temporary probe directories leaked: before=%d after=%d", len(before), len(after))
	}
}

func TestProbeHonorsCanceledContext(t *testing.T) {
	path := fakeXray(t, "#!/bin/sh\necho 'Xray 26.9.0'\n")
	p, err := New(Options{XrayPath: path, ProbeURL: "https://probe.example/generate_204"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cand := candidate.Candidate{Outbound: json.RawMessage(`{"protocol":"vless","tag":"upstream-slot-1"}`)}
	if _, err := p.Probe(ctx, cand); !errors.Is(err, context.Canceled) {
		t.Fatalf("Probe error = %v, want context.Canceled", err)
	}
}

func TestPrivateRangesCoverLoopbackAndLinkLocal(t *testing.T) {
	ranges := strings.Join(privateRanges(), ",")
	for _, want := range []string{"127.0.0.0/8", "169.254.0.0/16", "::1/128", "fe80::/10"} {
		if !strings.Contains(ranges, want) {
			t.Fatalf("private ranges missing %s", want)
		}
	}
}
