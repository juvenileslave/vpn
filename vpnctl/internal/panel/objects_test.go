package panel

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadObjectsRejectsUnknownDuplicateAndPrivateHostDeclarations(t *testing.T) {
	valid := Objects{Schema: 1,
		Profiles: []ProfileSpec{{Name: "owned-exit", Role: "exit"}},
		Hosts:    []HostSpec{{Name: "owned-direct", Profile: "owned-exit", Inbound: "direct-v4", Family: "ipv4"}},
	}
	for _, scenario := range []string{"valid", "unknown field", "duplicate json key", "duplicate names", "private inbound", "family mismatch", "stale format", "unknown snippet reference"} {
		t.Run(scenario, func(t *testing.T) {
			var value Objects
			if err := json.Unmarshal(fixtureJSON(t, valid), &value); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "duplicate names":
				value.Hosts = append(value.Hosts, value.Hosts[0])
			case "private inbound":
				value.Hosts[0].Inbound = "transit-v4"
			case "family mismatch":
				value.Hosts[0].Family = "ipv6"
			case "stale format":
				value.Profiles[0].UUID = "not-a-uuid"
			case "unknown snippet reference":
				value.Profiles[0].Snippets = []string{"undeclared"}
			}
			data := fixtureJSON(t, value)
			if scenario == "unknown field" {
				data = append(data[:len(data)-1], []byte(`,"token":"must-not-appear"}`)...)
			}
			if scenario == "duplicate json key" {
				data = append(data[:len(data)-1], []byte(`,"schema":1}`)...)
			}
			path := filepath.Join(t.TempDir(), "objects.json")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := LoadObjects(path)
			if scenario == "valid" {
				if err != nil || len(got.Hosts) != 1 || got.Hosts[0].Name != "owned-direct" {
					t.Fatal("valid declarations not loaded")
				}
			} else if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("unsafe %s was accepted: %v", scenario, err)
			}
		})
	}
}
