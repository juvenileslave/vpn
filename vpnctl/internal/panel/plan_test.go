package panel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/juvenileslave/vpn/vpnctl/internal/remnawave"
)

type memoryReader struct {
	profiles    []remnawave.ConfigProfile
	snippets    []remnawave.Snippet
	hosts       []remnawave.Host
	computed    map[string]remnawave.ConfigProfile
	rawOverride *remnawave.ConfigProfile
	failure     error
	calls       int
}

func (r *memoryReader) ListConfigProfiles(context.Context) ([]remnawave.ConfigProfile, error) {
	r.calls++
	return r.profiles, r.failure
}
func (r *memoryReader) ListSnippets(context.Context) ([]remnawave.Snippet, error) {
	r.calls++
	return r.snippets, r.failure
}
func (r *memoryReader) ListHosts(context.Context) ([]remnawave.Host, error) {
	r.calls++
	return r.hosts, r.failure
}
func (r *memoryReader) ConfigProfile(_ context.Context, uuid string) (remnawave.ConfigProfile, error) {
	r.calls++
	if r.rawOverride != nil {
		return *r.rawOverride, nil
	}
	for _, profile := range r.profiles {
		if profile.UUID == uuid {
			return profile, nil
		}
	}
	return remnawave.ConfigProfile{}, remnawave.ErrNotFound
}
func (r *memoryReader) ComputedConfigProfile(_ context.Context, uuid string) (remnawave.ConfigProfile, error) {
	r.calls++
	profile, exists := r.computed[uuid]
	if !exists {
		return remnawave.ConfigProfile{}, remnawave.ErrNotFound
	}
	return profile, nil
}
func (r *memoryReader) Host(_ context.Context, uuid string) (remnawave.Host, error) {
	r.calls++
	for _, host := range r.hosts {
		if host.UUID == uuid {
			return host, nil
		}
	}
	return remnawave.Host{}, remnawave.ErrNotFound
}

func planFixture(t *testing.T, existing bool) (Bundle, Objects, *memoryReader) {
	t.Helper()
	bundle := policyBundle(t)
	objects := Objects{
		Schema:   1,
		Profiles: []ProfileSpec{{Name: "owned-exit", Role: "exit", Snippets: []string{"owned-outbounds"}}},
		Snippets: []SnippetSpec{{Name: "owned-outbounds", Role: "exit", Field: "outbounds"}},
		Hosts:    []HostSpec{{Name: "owned-direct", Profile: "owned-exit", Inbound: "direct-v4", Family: "ipv4"}},
	}
	reader := &memoryReader{
		profiles: []remnawave.ConfigProfile{}, snippets: []remnawave.Snippet{}, hosts: []remnawave.Host{},
		computed: make(map[string]remnawave.ConfigProfile),
	}
	if !existing {
		return bundle, objects, reader
	}
	objects.Profiles[0].UUID = temporaryUUID(t)
	objects.Hosts[0].UUID = temporaryUUID(t)
	raw, err := encodeReferences(bundle.Configs["exit"], objects.Snippets, objects.Profiles[0].Snippets)
	if err != nil {
		t.Fatal(err)
	}
	profile := remnawave.ConfigProfile{
		UUID: objects.Profiles[0].UUID, Name: objects.Profiles[0].Name, Config: fixtureJSON(t, raw),
		Inbounds: []remnawave.ConfigProfileInbound{}, Fields: map[string]json.RawMessage{"future": json.RawMessage(`{"preserve":true}`)},
	}
	for _, tag := range []string{"direct-v4", "direct-v6", "transit-v4", "transit-v6"} {
		profile.Inbounds = append(profile.Inbounds, remnawave.ConfigProfileInbound{
			UUID: temporaryUUID(t), ProfileUUID: profile.UUID, Tag: tag,
		})
	}
	reader.profiles = append(reader.profiles, profile)
	computed := profile
	computed.Config = bundle.Configs["exit"]
	reader.computed[profile.UUID] = computed
	content, err := configField(bundle.Configs["exit"], "outbounds")
	if err != nil {
		t.Fatal(err)
	}
	reader.snippets = append(reader.snippets, remnawave.Snippet{Name: "owned-outbounds", Snippet: content})
	effective, err := decodeObject(bundle.Configs["exit"])
	if err != nil {
		t.Fatal(err)
	}
	ids, err := inboundIdentities(profile)
	if err != nil {
		t.Fatal(err)
	}
	host, err := desiredHost(bundle, profileCandidate{spec: objects.Profiles[0], effective: effective, inbounds: ids}, objects.Hosts[0])
	if err != nil {
		t.Fatal(err)
	}
	host.fields["futureSetting"] = json.RawMessage(`{"preserve":"opaque"}`)
	reader.hosts = append(reader.hosts, remnawave.Host{
		UUID: objects.Hosts[0].UUID, Remark: objects.Hosts[0].Name,
		Inbound: remnawave.HostInbound{ConfigProfileUUID: profile.UUID, ConfigProfileInboundUUID: ids["direct-v4"]},
		Fields:  host.fields,
	})
	return bundle, objects, reader
}

func reportObject(t *testing.T, report Report, kind string) Object {
	t.Helper()
	for _, object := range report.Objects {
		if object.Kind == kind {
			return object
		}
	}
	t.Fatalf("missing %s report", kind)
	return Object{}
}

func TestPlanExistingCanonicalStateIsUnchangedWithoutDroppingUnknownFields(t *testing.T) {
	bundle, objects, reader := planFixture(t, true)
	report, err := Plan(context.Background(), reader, bundle, objects)
	if err != nil {
		t.Fatal(err)
	}
	if report.AtomicWrites {
		t.Fatal("read-only report claims atomic writes")
	}
	for _, kind := range []string{"profile", "snippet", "host"} {
		object := reportObject(t, report, kind)
		if object.Action != "unchanged" {
			t.Fatalf("%s action = %s", kind, object.Action)
		}
		for _, field := range object.Fields {
			if field.State != "equal" {
				t.Fatalf("%s unexpectedly reports drift", field.Path)
			}
		}
	}
	if string(reader.hosts[0].Fields["futureSetting"]) != `{"preserve":"opaque"}` ||
		string(reader.profiles[0].Fields["future"]) != `{"preserve":true}` {
		t.Fatal("planning lost unknown panel settings")
	}
}

func TestPlanNewObjectsAndActualSnippetDriftAreDistinct(t *testing.T) {
	bundle, objects, reader := planFixture(t, false)
	report, err := Plan(context.Background(), reader, bundle, objects)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"profile", "snippet", "host"} {
		if reportObject(t, report, kind).Action != "create" {
			t.Fatalf("new %s is not a create diff", kind)
		}
	}
	bundle, objects, reader = planFixture(t, true)
	reader.snippets[0].Snippet = json.RawMessage(`[{"tag":"different","protocol":"blackhole"}]`)
	computed := reader.computed[objects.Profiles[0].UUID]
	var current map[string]json.RawMessage
	if err := json.Unmarshal(computed.Config, &current); err != nil {
		t.Fatal(err)
	}
	current["outbounds"] = reader.snippets[0].Snippet
	computed.Config = fixtureJSON(t, current)
	reader.computed[computed.UUID] = computed
	report, err = Plan(context.Background(), reader, bundle, objects)
	if err != nil {
		t.Fatal(err)
	}
	if reportObject(t, report, "snippet").Action != "update" || reportObject(t, report, "profile").Action != "update" {
		t.Fatal("actual computed-config drift was not reported")
	}
	profile := reportObject(t, report, "profile")
	for _, field := range profile.Fields {
		if field.Path == "config.outbounds" && field.State == "drift" {
			return
		}
	}
	t.Fatal("effective outbounds drift missing from safe field report")
}

func TestPlanRejectsOwnershipAndConcurrentDrift(t *testing.T) {
	for _, scenario := range []string{"name collision", "stale uuid", "renamed uuid", "concurrent config", "host name collision", "duplicate hostname"} {
		t.Run(scenario, func(t *testing.T) {
			bundle, objects, reader := planFixture(t, true)
			switch scenario {
			case "name collision":
				objects.Profiles[0].UUID = ""
			case "stale uuid":
				objects.Profiles[0].UUID = temporaryUUID(t)
			case "renamed uuid":
				reader.profiles[0].Name = "another-owner"
			case "concurrent config":
				changed := reader.profiles[0]
				changed.Config = json.RawMessage(`{"changed":true}`)
				reader.rawOverride = &changed
			case "host name collision":
				objects.Hosts[0].UUID = ""
			case "duplicate hostname":
				duplicate := reader.hosts[0]
				duplicate.UUID = temporaryUUID(t)
				duplicate.Remark = "another-host"
				duplicate.Fields = make(map[string]json.RawMessage)
				for key, value := range reader.hosts[0].Fields {
					duplicate.Fields[key] = value
				}
				reader.hosts = append(reader.hosts, duplicate)
			}
			if _, err := Plan(context.Background(), reader, bundle, objects); !errors.Is(err, ErrConflict) {
				t.Fatalf("unsafe %s not rejected: %v", scenario, err)
			}
		})
	}
}

func TestPlanRejectsSharedSnippetAndLossyProfileReplacement(t *testing.T) {
	bundle, objects, reader := planFixture(t, true)
	other := reader.profiles[0]
	other.UUID = temporaryUUID(t)
	other.Name = "unmanaged"
	other.Inbounds = []remnawave.ConfigProfileInbound{}
	other.Config = json.RawMessage(`{"snippets":["owned-outbounds"],"inbounds":[]}`)
	reader.profiles = append(reader.profiles, other)
	reader.snippets[0].Snippet = json.RawMessage(`[{"tag":"other","protocol":"blackhole"}]`)
	if _, err := Plan(context.Background(), reader, bundle, objects); !errors.Is(err, ErrConflict) {
		t.Fatalf("shared snippet mutation candidate was not rejected: %v", err)
	}
	bundle, objects, reader = planFixture(t, true)
	objects.Profiles[0].Snippets = []string{}
	if _, err := Plan(context.Background(), reader, bundle, objects); !errors.Is(err, ErrLossyUpdate) {
		t.Fatalf("full PATCH clearing static clients not rejected: %v", err)
	}
}

func TestShowNeverLabelsDesiredOnlyFieldsAsPresent(t *testing.T) {
	bundle, objects, reader := planFixture(t, true)
	var desired map[string]json.RawMessage
	if err := json.Unmarshal(bundle.Configs["exit"], &desired); err != nil {
		t.Fatal(err)
	}
	desired["dns"] = json.RawMessage(`{"servers":["192.0.2.53"]}`)
	bundle.Configs["exit"] = fixtureJSON(t, desired)
	report, err := Show(context.Background(), reader, bundle, objects)
	if err != nil {
		t.Fatal(err)
	}
	profile := reportObject(t, report, "profile")
	if profile.Action != "current" {
		t.Fatal("existing profile not shown as current")
	}
	for _, field := range profile.Fields {
		if field.Path == "config.dns" {
			t.Fatal("show fabricated a desired-only DNS setting")
		}
	}
}

func TestPlanOutputAndErrorsDoNotExposePayload(t *testing.T) {
	bundle, objects, reader := planFixture(t, true)
	report, err := Plan(context.Background(), reader, bundle, objects)
	if err != nil {
		t.Fatal(err)
	}
	data := fixtureJSON(t, report)
	for _, forbidden := range []string{"privateKey", "clients", "192.0.2.10", "exit.example.test", "opaque"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatal("safe report exposed a payload field or value")
		}
	}
	cause := errors.New("secret-token response-body must-not-appear")
	reader.failure = cause
	_, err = Plan(context.Background(), reader, bundle, objects)
	if !errors.Is(err, cause) {
		t.Fatal("safe error lost typed cause")
	}
	if strings.Contains(fmt.Sprintf("%v %+v %#v", err, err, err), "secret-token") {
		t.Fatal("safe error formatting exposed transport diagnostics")
	}
}

func TestPlanInvalidDeclarationsAndCanceledContextPerformNoReads(t *testing.T) {
	bundle, objects, reader := planFixture(t, false)
	objects.Hosts[0].Inbound = "transit-v4"
	if _, err := Plan(context.Background(), reader, bundle, objects); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("private inbound accepted for public host")
	}
	if reader.calls != 0 {
		t.Fatal("invalid declarations caused I/O")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	objects.Hosts[0].Inbound = "direct-v4"
	if _, err := Plan(ctx, reader, bundle, objects); !errors.Is(err, context.Canceled) {
		t.Fatal("lost cancellation")
	}
	if reader.calls != 0 {
		t.Fatal("pre-cancelled plan caused I/O")
	}
}

func TestPlanRefusesSnippetReplacementThatDropsPanelSideSettings(t *testing.T) {
	bundle, objects, reader := planFixture(t, true)
	var content []map[string]json.RawMessage
	if err := json.Unmarshal(reader.snippets[0].Snippet, &content); err != nil {
		t.Fatal(err)
	}
	content[0]["panelExtension"] = json.RawMessage(`{"nested":{"value":"server-private-marker"}}`)
	before := fixtureJSON(t, content)
	reader.snippets[0].Snippet = before
	computed := reader.computed[objects.Profiles[0].UUID]
	var config map[string]json.RawMessage
	if err := json.Unmarshal(computed.Config, &config); err != nil {
		t.Fatal(err)
	}
	config["outbounds"] = before
	computed.Config = fixtureJSON(t, config)
	reader.computed[computed.UUID] = computed
	report, err := Plan(context.Background(), reader, bundle, objects)
	if !errors.Is(err, ErrLossyUpdate) || reportObject(t, report, "snippet").Action != "update" {
		t.Fatal("prospective snippet replacement lost unknown nested panel settings without refusal")
	}
	if strings.Contains(string(fixtureJSON(t, report)), "server-private-marker") ||
		strings.Contains(string(fixtureJSON(t, report)), "panelExtension") {
		t.Fatal("lossy refusal exposed unknown panel settings")
	}
	if _, err := Show(context.Background(), reader, bundle, objects); err != nil {
		t.Fatal("show refused current state because of a prospective lossy snippet change")
	}
	if string(reader.snippets[0].Snippet) != string(before) {
		t.Fatal("planning altered the retained unknown snippet settings")
	}
}
