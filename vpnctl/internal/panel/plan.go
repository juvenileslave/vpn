package panel

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/juvenileslave/vpn/vpnctl/internal/remnawave"
)

// Reader intentionally has no mutation or precondition emulation method.
type Reader interface {
	ListConfigProfiles(context.Context) ([]remnawave.ConfigProfile, error)
	ConfigProfile(context.Context, string) (remnawave.ConfigProfile, error)
	ComputedConfigProfile(context.Context, string) (remnawave.ConfigProfile, error)
	ListSnippets(context.Context) ([]remnawave.Snippet, error)
	ListHosts(context.Context) ([]remnawave.Host, error)
	Host(context.Context, string) (remnawave.Host, error)
}

// Field contains only a fixed field path and its comparison status, never a value.
type Field struct {
	Path  string `json:"path"`
	State string `json:"state"`
}

// Object contains only caller-declared identity and safe effective-field metadata.
type Object struct {
	Kind   string  `json:"kind"`
	Name   string  `json:"name"`
	UUID   string  `json:"uuid,omitempty"`
	Action string  `json:"action"`
	Fields []Field `json:"fields"`
}

// Report is a read-only observation, not an atomic snapshot or runtime receipt.
// AtomicWrites is always false for the pinned API, even when there is no diff.
type Report struct {
	Mode         string   `json:"mode"`
	BundleID     string   `json:"bundle_id"`
	AtomicWrites bool     `json:"atomic_writes"`
	Objects      []Object `json:"objects"`
}

var (
	identityPattern    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	bundleIDPattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	publicRelayPattern = regexp.MustCompile(`^slot-[0-9]+-v[46]$`)
)

var configPaths = []string{
	"log", "api", "inbounds", "outbounds", "routing.domainStrategy", "routing.rules",
	"routing.balancers", "observatory", "dns", "policy", "metrics", "stats",
}

var hostPaths = []string{
	"address", "port", "sni", "host", "path", "fingerprint", "inbound",
	"overrideSniFromAddress", "keepSniBlank", "shuffleHost",
}

type observation struct {
	profiles     map[string]remnawave.ConfigProfile
	profileNames map[string]string
	snippets     map[string]remnawave.Snippet
	hosts        map[string]remnawave.Host
	hostNames    map[string]string
}

type profileCandidate struct {
	spec      ProfileSpec
	desired   map[string]json.RawMessage
	effective map[string]json.RawMessage
	current   remnawave.ConfigProfile
	observed  map[string]json.RawMessage
	inbounds  map[string]string
}

type hostCandidate struct {
	spec    HostSpec
	fields  map[string]json.RawMessage
	binding string
}

// Plan compares actual panel raw/computed objects with the immutable renderer candidate.
// A non-nil report can accompany a safety refusal; it contains no request bodies.
func Plan(ctx context.Context, reader Reader, bundle Bundle, objects Objects) (Report, error) {
	return inspect(ctx, reader, bundle, objects, false)
}

// Show exposes only current declared identities and actual effective field presence.
// It never expands a snippet or reports a candidate as an existing panel object.
func Show(ctx context.Context, reader Reader, bundle Bundle, objects Objects) (Report, error) {
	return inspect(ctx, reader, bundle, objects, true)
}

func inspect(ctx context.Context, reader Reader, bundle Bundle, objects Objects, isShow bool) (Report, error) {
	mode := "plan"
	if isShow {
		mode = "show"
	}
	report := Report{Mode: mode, BundleID: bundle.ID, Objects: []Object{}}
	if reader == nil {
		return Report{}, ErrInvalidInput
	}
	if ctx == nil {
		return Report{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return Report{}, safeError("context", err)
	}
	if err := validateCandidate(bundle, objects); err != nil {
		return Report{}, err
	}
	current, err := readCollections(ctx, reader)
	if err != nil {
		return Report{}, err
	}
	profiles := make(map[string]profileCandidate, len(objects.Profiles))
	for _, spec := range objects.Profiles {
		candidate, item, err := inspectProfile(ctx, reader, current, bundle, objects, spec)
		if err != nil {
			return Report{}, err
		}
		profiles[spec.Name] = candidate
		if isShow {
			item = currentObject(item, candidate.observed)
		}
		report.Objects = append(report.Objects, item)
	}
	changedSnippets := make(map[string]bool, len(objects.Snippets))
	for _, spec := range objects.Snippets {
		desired, err := configField(bundle.Configs[spec.Role], spec.Field)
		if err != nil {
			return Report{}, err
		}
		item := Object{Kind: "snippet", Name: spec.Name, Action: "create", Fields: []Field{}}
		existing, exists := current.snippets[spec.Name]
		changed := !exists
		if exists {
			equal, err := equalJSON(existing.Snippet, desired)
			if err != nil {
				return Report{}, safeError("snippet comparison", err)
			}
			changed = !equal
			item.Action = action(changed)
		}
		changedSnippets[spec.Name] = changed
		item.Fields = []Field{{Path: spec.Field, State: comparisonState(exists, changed)}}
		if isShow {
			item.Action = "current"
			item.Fields[0].State = "present"
			if !exists {
				item.Action = "absent"
				item.Fields[0].State = "missing"
			}
		}
		report.Objects = append(report.Objects, item)
	}
	hosts := make([]hostCandidate, 0, len(objects.Hosts))
	for _, spec := range objects.Hosts {
		candidate, err := desiredHost(bundle, profiles[spec.Profile], spec)
		if err != nil {
			return Report{}, err
		}
		hosts = append(hosts, candidate)
		item, err := inspectHost(ctx, reader, current, candidate)
		if err != nil {
			return Report{}, err
		}
		if isShow {
			item.Action = "current"
			if spec.UUID == "" {
				item.Action = "absent"
			}
			for i := range item.Fields {
				item.Fields[i].State = "present"
				if spec.UUID == "" || len(current.hosts[spec.UUID].Fields[item.Fields[i].Path]) == 0 {
					item.Fields[i].State = "missing"
				}
			}
		}
		report.Objects = append(report.Objects, item)
	}
	if err := checkHostConflicts(current, hosts); err != nil {
		return report, err
	}
	if isShow {
		return report, nil
	}
	if err := checkSharedSnippets(current, profiles, changedSnippets); err != nil {
		return report, err
	}
	for _, candidate := range profiles {
		if candidate.spec.UUID == "" {
			continue
		}
		raw, err := decodeObject(candidate.current.Config)
		if err != nil {
			return report, safeError("current config", err)
		}
		equal, err := equalObjects(raw, candidate.desired)
		if err != nil {
			return report, safeError("config comparison", err)
		}
		if !equal && (hasStaticClients(raw) || hasStaticClients(candidate.desired) || losesFields(raw, candidate.desired)) {
			return report, ErrLossyUpdate
		}
	}
	return report, nil
}

func validateCandidate(bundle Bundle, objects Objects) error {
	if !bundleIDPattern.MatchString(bundle.ID) {
		return ErrInvalidInput
	}
	if err := objects.Validate(); err != nil {
		return err
	}
	for _, spec := range objects.Profiles {
		if _, err := decodeObject(bundle.Configs[spec.Role]); err != nil {
			return err
		}
	}
	for _, spec := range objects.Snippets {
		value, err := configField(bundle.Configs[spec.Role], spec.Field)
		if err != nil {
			return err
		}
		var parts []map[string]json.RawMessage
		if err := json.Unmarshal(value, &parts); err != nil || len(parts) == 0 {
			return ErrInvalidInput
		}
		for _, part := range parts {
			if len(part) == 0 {
				return ErrInvalidInput
			}
		}
	}
	return nil
}

func readCollections(ctx context.Context, reader Reader) (observation, error) {
	result := observation{
		profiles: map[string]remnawave.ConfigProfile{}, profileNames: map[string]string{},
		snippets: map[string]remnawave.Snippet{}, hosts: map[string]remnawave.Host{}, hostNames: map[string]string{},
	}
	profiles, err := reader.ListConfigProfiles(ctx)
	if err != nil {
		return result, safeError("profile collection read", err)
	}
	for _, profile := range profiles {
		_, duplicateUUID := result.profiles[profile.UUID]
		_, duplicateName := result.profileNames[profile.Name]
		if !identityPattern.MatchString(profile.UUID) || profile.Name == "" || duplicateUUID || duplicateName {
			return result, ErrConflict
		}
		if _, err := decodeObject(profile.Config); err != nil {
			return result, safeError("current config", err)
		}
		if _, err := inboundIdentities(profile); err != nil {
			return result, err
		}
		result.profiles[profile.UUID] = profile
		result.profileNames[profile.Name] = profile.UUID
	}
	snippets, err := reader.ListSnippets(ctx)
	if err != nil {
		return result, safeError("snippet collection read", err)
	}
	for _, snippet := range snippets {
		if _, duplicate := result.snippets[snippet.Name]; duplicate || snippet.Name == "" {
			return result, ErrConflict
		}
		if _, err := Canonical(snippet.Snippet); err != nil {
			return result, safeError("current snippet", err)
		}
		result.snippets[snippet.Name] = snippet
	}
	hosts, err := reader.ListHosts(ctx)
	if err != nil {
		return result, safeError("host collection read", err)
	}
	for _, host := range hosts {
		_, duplicateUUID := result.hosts[host.UUID]
		_, duplicateName := result.hostNames[host.Remark]
		if !identityPattern.MatchString(host.UUID) || host.Remark == "" || duplicateUUID || duplicateName {
			return result, ErrConflict
		}
		result.hosts[host.UUID] = host
		result.hostNames[host.Remark] = host.UUID
	}
	return result, nil
}

func inspectProfile(
	ctx context.Context,
	reader Reader,
	current observation,
	bundle Bundle,
	objects Objects,
	spec ProfileSpec,
) (profileCandidate, Object, error) {
	effective, err := decodeObject(bundle.Configs[spec.Role])
	if err != nil {
		return profileCandidate{}, Object{}, err
	}
	desired, err := encodeReferences(bundle.Configs[spec.Role], objects.Snippets, spec.Snippets)
	if err != nil {
		return profileCandidate{}, Object{}, err
	}
	candidate := profileCandidate{spec: spec, desired: desired, effective: effective, inbounds: map[string]string{}}
	item := Object{Kind: "profile", Name: spec.Name, UUID: spec.UUID, Action: "create", Fields: []Field{}}
	if spec.UUID == "" {
		if _, exists := current.profileNames[spec.Name]; exists {
			return candidate, item, ErrConflict
		}
		item.Fields = fieldMetadata(nil, effective, configPaths, "config.")
		return candidate, item, nil
	}
	listed, exists := current.profiles[spec.UUID]
	if !exists || listed.Name != spec.Name {
		return candidate, item, ErrConflict
	}
	raw, err := reader.ConfigProfile(ctx, spec.UUID)
	if err != nil {
		return candidate, item, safeError("raw profile read", err)
	}
	if raw.UUID != spec.UUID || raw.Name != spec.Name {
		return candidate, item, ErrConflict
	}
	equal, err := equalJSON(listed.Config, raw.Config)
	if err != nil {
		return candidate, item, safeError("profile read comparison", err)
	}
	if !equal {
		return candidate, item, ErrConflict
	}
	candidate.current = raw
	candidate.inbounds, err = inboundIdentities(raw)
	if err != nil {
		return candidate, item, err
	}
	computed, err := reader.ComputedConfigProfile(ctx, spec.UUID)
	if err != nil {
		return candidate, item, safeError("computed profile read", err)
	}
	if computed.UUID != spec.UUID || computed.Name != spec.Name {
		return candidate, item, ErrConflict
	}
	actual, err := decodeObject(computed.Config)
	if err != nil {
		return candidate, item, safeError("computed config", err)
	}
	candidate.observed = actual
	rawObject, err := decodeObject(raw.Config)
	if err != nil {
		return candidate, item, safeError("raw config", err)
	}
	rawEqual, err := equalObjects(rawObject, desired)
	if err != nil {
		return candidate, item, err
	}
	effectiveEqual, err := equalObjects(actual, effective)
	if err != nil {
		return candidate, item, err
	}
	item.Action = action(!rawEqual || !effectiveEqual)
	item.Fields = fieldMetadata(actual, effective, configPaths, "config.")
	// Raw reference encoding and actual expansion are separate comparisons.
	item.Fields = append(item.Fields, Field{Path: "config.raw", State: comparisonState(true, !rawEqual)})
	return candidate, item, nil
}

func encodeReferences(data []byte, snippets []SnippetSpec, selected []string) (map[string]json.RawMessage, error) {
	config, err := decodeObject(data)
	if err != nil {
		return nil, err
	}
	byName := make(map[string]SnippetSpec, len(snippets))
	for _, spec := range snippets {
		byName[spec.Name] = spec
	}
	for _, name := range selected {
		value, err := json.Marshal([]map[string]string{{"snippet": name}})
		if err != nil {
			return nil, safeError("reference encoding", err)
		}
		field := byName[name].Field
		if field == "outbounds" {
			config[field] = value
			continue
		}
		routing, err := decodeObject(config["routing"])
		if err != nil {
			return nil, err
		}
		routing[strings.TrimPrefix(field, "routing.")] = value
		encoded, err := json.Marshal(routing)
		if err != nil {
			return nil, safeError("reference encoding", err)
		}
		config["routing"] = encoded
	}
	return config, nil
}

func inboundIdentities(profile remnawave.ConfigProfile) (map[string]string, error) {
	result := make(map[string]string, len(profile.Inbounds))
	uuids := make(map[string]bool, len(profile.Inbounds))
	for _, inbound := range profile.Inbounds {
		_, duplicate := result[inbound.Tag]
		if duplicate || uuids[inbound.UUID] || !identityPattern.MatchString(inbound.UUID) {
			return nil, ErrConflict
		}
		if inbound.ProfileUUID != profile.UUID || inbound.Tag == "" {
			return nil, ErrConflict
		}
		result[inbound.Tag] = inbound.UUID
		uuids[inbound.UUID] = true
	}
	return result, nil
}

func desiredHost(bundle Bundle, profile profileCandidate, spec HostSpec) (hostCandidate, error) {
	result := hostCandidate{spec: spec, fields: map[string]json.RawMessage{}}
	host, exists := bundle.Hosts[profile.spec.Role]
	if !exists || host.SNI == "" {
		return result, ErrInvalidInput
	}
	address := host.IPv4
	if spec.Family == "ipv6" {
		address = host.IPv6
	}
	ip, err := netip.ParseAddr(address)
	if err != nil || ip.Is4() != (spec.Family == "ipv4") || ip.Is4In6() {
		return result, ErrInvalidInput
	}
	var inbounds []map[string]json.RawMessage
	if err := json.Unmarshal(profile.effective["inbounds"], &inbounds); err != nil {
		return result, ErrInvalidInput
	}
	var selected map[string]json.RawMessage
	for _, inbound := range inbounds {
		if stringField(inbound, "tag") == spec.Inbound {
			if selected != nil {
				return result, ErrInvalidInput
			}
			selected = inbound
		}
	}
	if selected == nil {
		return result, ErrInvalidInput
	}
	port, ok := integerField(selected, "port")
	if !ok || port < 1 || port > 65535 {
		return result, ErrInvalidInput
	}
	stream, err := decodeObject(selected["streamSettings"])
	if err != nil {
		return result, err
	}
	if stringField(stream, "network") != "xhttp" || stringField(stream, "security") != "reality" {
		return result, ErrInvalidInput
	}
	xhttp, err := decodeObject(stream["xhttpSettings"])
	if err != nil || stringField(xhttp, "path") == "" {
		return result, ErrInvalidInput
	}
	inboundUUID := profile.inbounds[spec.Inbound]
	if profile.spec.UUID != "" && inboundUUID == "" {
		return result, ErrConflict
	}
	values := map[string]any{
		"address": ip.String(), "port": port, "sni": host.SNI, "host": host.SNI,
		"path": stringField(xhttp, "path"), "fingerprint": "firefox",
		"overrideSniFromAddress": false, "keepSniBlank": false, "shuffleHost": false,
		"inbound": map[string]string{
			"configProfileUuid": profile.spec.UUID, "configProfileInboundUuid": inboundUUID,
		},
	}
	for key, value := range values {
		encoded, err := json.Marshal(value)
		if err != nil {
			return result, safeError("host policy", err)
		}
		result.fields[key] = encoded
	}
	identity := profile.spec.UUID
	if identity == "" {
		identity = "new:" + profile.spec.Name
	}
	result.binding = identity + ":" + inboundBase(spec.Inbound)
	return result, nil
}

func inspectHost(
	ctx context.Context,
	reader Reader,
	current observation,
	candidate hostCandidate,
) (Object, error) {
	spec := candidate.spec
	item := Object{Kind: "host", Name: spec.Name, UUID: spec.UUID, Action: "create", Fields: []Field{}}
	if spec.UUID == "" {
		if _, exists := current.hostNames[spec.Name]; exists {
			return item, ErrConflict
		}
		item.Fields = fieldMetadata(nil, candidate.fields, hostPaths, "")
		return item, nil
	}
	listed, exists := current.hosts[spec.UUID]
	if !exists || listed.Remark != spec.Name {
		return item, ErrConflict
	}
	host, err := reader.Host(ctx, spec.UUID)
	if err != nil {
		return item, safeError("host read", err)
	}
	identityChanged := host.UUID != spec.UUID || host.Remark != spec.Name
	if identityChanged || host.Inbound.ConfigProfileUUID != listed.Inbound.ConfigProfileUUID ||
		host.Inbound.ConfigProfileInboundUUID != listed.Inbound.ConfigProfileInboundUUID {
		return item, ErrConflict
	}
	equal, err := equalObjects(host.Fields, listed.Fields)
	if err != nil {
		return item, safeError("host read comparison", err)
	}
	if !equal {
		return item, ErrConflict
	}
	item.Fields = fieldMetadata(host.Fields, candidate.fields, hostPaths, "")
	item.Action = "unchanged"
	for _, field := range item.Fields {
		if field.State != "equal" {
			item.Action = "update"
		}
	}
	return item, nil
}

func checkSharedSnippets(current observation, profiles map[string]profileCandidate, changes map[string]bool) error {
	managed := make(map[string]bool, len(profiles))
	for _, profile := range profiles {
		managed[profile.spec.UUID] = profile.spec.UUID != ""
	}
	for uuid, profile := range current.profiles {
		if managed[uuid] {
			continue
		}
		var config any
		if err := json.Unmarshal(profile.Config, &config); err != nil {
			return ErrConflict
		}
		if referencesChangedSnippet(config, changes) {
			return ErrConflict
		}
	}
	return nil
}

func referencesChangedSnippet(value any, changes map[string]bool) bool {
	switch value := value.(type) {
	case map[string]any:
		if name, ok := value["snippet"].(string); ok && changes[name] {
			return true
		}
		if names, ok := value["snippets"].([]any); ok {
			for _, name := range names {
				if name, ok := name.(string); ok && changes[name] {
					return true
				}
			}
		}
		for _, nested := range value {
			if referencesChangedSnippet(nested, changes) {
				return true
			}
		}
	case []any:
		for _, nested := range value {
			if referencesChangedSnippet(nested, changes) {
				return true
			}
		}
	}
	return false
}

func checkHostConflicts(current observation, desired []hostCandidate) error {
	declared := make(map[string]bool, len(desired))
	for _, host := range desired {
		declared[host.spec.UUID] = host.spec.UUID != ""
	}
	addresses := make(map[string]string, len(current.hosts)+len(desired))
	snis := make(map[string]string, len(current.hosts)+len(desired))
	// Validate the existing collection first, including managed objects.
	for uuid, host := range current.hosts {
		binding := currentHostBinding(current, host)
		if err := addHostBinding(addresses, snis, host.Fields, binding); err != nil {
			return err
		}
		if declared[uuid] {
			continue
		}
	}
	// Rebuild with only unmanaged hosts; an explicitly owned host may change its binding.
	clear(addresses)
	clear(snis)
	for uuid, host := range current.hosts {
		if declared[uuid] {
			continue
		}
		if err := addHostBinding(addresses, snis, host.Fields, "unmanaged:"+uuid); err != nil {
			return err
		}
	}
	for _, host := range desired {
		if err := addHostBinding(addresses, snis, host.fields, host.binding); err != nil {
			return err
		}
	}
	return nil
}

func currentHostBinding(current observation, host remnawave.Host) string {
	profile := current.profiles[host.Inbound.ConfigProfileUUID]
	for _, inbound := range profile.Inbounds {
		if inbound.UUID == host.Inbound.ConfigProfileInboundUUID {
			return profile.UUID + ":" + inboundBase(inbound.Tag)
		}
	}
	return "unknown:" + host.UUID
}

func addHostBinding(addresses, snis map[string]string, fields map[string]json.RawMessage, binding string) error {
	address := strings.ToLower(stringField(fields, "address"))
	if ip, err := netip.ParseAddr(address); err == nil {
		address = ip.Unmap().String()
	}
	port, ok := integerField(fields, "port")
	if !ok || port < 1 || port > 65535 || address == "" {
		return ErrConflict
	}
	key := address + ":" + strconv.FormatInt(port, 10)
	if _, exists := addresses[key]; exists {
		return ErrConflict
	}
	addresses[key] = binding
	for _, field := range []string{"sni", "host"} {
		name := strings.ToLower(strings.TrimSuffix(stringField(fields, field), "."))
		if name == "" {
			continue
		}
		key := name + ":" + strconv.FormatInt(port, 10)
		if previous, exists := snis[key]; exists && previous != binding {
			return ErrConflict
		}
		snis[key] = binding
	}
	return nil
}

func publicInbound(role, tag, family string) bool {
	suffix := "-v4"
	if family == "ipv6" {
		suffix = "-v6"
	}
	if !strings.HasSuffix(tag, suffix) {
		return false
	}
	if role == "exit" {
		return tag == "direct"+suffix
	}
	return role == "relay" && publicRelayPattern.MatchString(tag)
}

func inboundBase(tag string) string {
	return strings.TrimSuffix(strings.TrimSuffix(tag, "-v4"), "-v6")
}

func decodeObject(data []byte) (map[string]json.RawMessage, error) {
	canonical, err := Canonical(data)
	if err != nil {
		return nil, safeError("json validation", err)
	}
	result := map[string]json.RawMessage{}
	if err := json.Unmarshal(canonical, &result); err != nil || result == nil {
		return nil, ErrInvalidInput
	}
	return result, nil
}

func configField(data []byte, path string) (json.RawMessage, error) {
	if path != "outbounds" && path != "routing.rules" && path != "routing.balancers" {
		return nil, ErrInvalidInput
	}
	config, err := decodeObject(data)
	if err != nil {
		return nil, err
	}
	value := fieldAt(config, path)
	if len(value) == 0 {
		return nil, ErrInvalidInput
	}
	return value, nil
}

func fieldAt(object map[string]json.RawMessage, path string) json.RawMessage {
	root, nested, exists := strings.Cut(path, ".")
	if !exists {
		return object[root]
	}
	child := map[string]json.RawMessage{}
	if err := json.Unmarshal(object[root], &child); err != nil {
		return nil
	}
	return child[nested]
}

func stringField(object map[string]json.RawMessage, key string) string {
	var value string
	if err := json.Unmarshal(object[key], &value); err != nil {
		return ""
	}
	return value
}

func equalJSON(left, right []byte) (bool, error) {
	a, err := Canonical(left)
	if err != nil {
		return false, err
	}
	b, err := Canonical(right)
	if err != nil {
		return false, err
	}
	return bytes.Equal(a, b), nil
}

func equalObjects(left, right map[string]json.RawMessage) (bool, error) {
	a, err := json.Marshal(left)
	if err != nil {
		return false, safeError("object comparison", err)
	}
	b, err := json.Marshal(right)
	if err != nil {
		return false, safeError("object comparison", err)
	}
	return equalJSON(a, b)
}

func fieldMetadata(actual, desired map[string]json.RawMessage, paths []string, prefix string) []Field {
	result := make([]Field, 0, len(paths))
	for _, path := range paths {
		left, right := fieldAt(actual, path), fieldAt(desired, path)
		if len(left) == 0 && len(right) == 0 {
			continue
		}
		state := "missing"
		if len(left) != 0 {
			state = "drift"
			if equal, err := equalJSON(left, right); err == nil && equal {
				state = "equal"
			}
		}
		result = append(result, Field{Path: prefix + path, State: state})
	}
	return result
}

func currentObject(item Object, observed map[string]json.RawMessage) Object {
	item.Action = "absent"
	item.Fields = []Field{}
	if item.UUID == "" {
		return item
	}
	item.Action = "current"
	for _, path := range configPaths {
		if len(fieldAt(observed, path)) != 0 {
			item.Fields = append(item.Fields, Field{Path: "config." + path, State: "present"})
		}
	}
	return item
}

func hasStaticClients(config map[string]json.RawMessage) bool {
	var inbounds []map[string]json.RawMessage
	if err := json.Unmarshal(config["inbounds"], &inbounds); err != nil {
		return false
	}
	for _, inbound := range inbounds {
		settings := map[string]json.RawMessage{}
		if err := json.Unmarshal(inbound["settings"], &settings); err != nil {
			continue
		}
		var clients []json.RawMessage
		if err := json.Unmarshal(settings["clients"], &clients); err == nil && len(clients) != 0 {
			return true
		}
	}
	return false
}

func losesFields(current, desired map[string]json.RawMessage) bool {
	for key, value := range current {
		replacement, exists := desired[key]
		if !exists {
			return true
		}
		var oldObject, newObject map[string]json.RawMessage
		if json.Unmarshal(value, &oldObject) == nil && oldObject != nil {
			if json.Unmarshal(replacement, &newObject) != nil || losesFields(oldObject, newObject) {
				return true
			}
		}
		var oldArray, newArray []json.RawMessage
		if json.Unmarshal(value, &oldArray) == nil && oldArray != nil {
			if json.Unmarshal(replacement, &newArray) != nil {
				return true
			}
			// Reference replacement is intentional and checked against actual computed-config.
			if len(newArray) == 1 {
				var reference map[string]json.RawMessage
				if json.Unmarshal(newArray[0], &reference) == nil && len(reference["snippet"]) != 0 {
					continue
				}
			}
			for i, old := range oldArray {
				if i >= len(newArray) {
					return true
				}
				var before, after map[string]json.RawMessage
				if json.Unmarshal(old, &before) == nil && before != nil {
					if json.Unmarshal(newArray[i], &after) != nil || losesFields(before, after) {
						return true
					}
				}
			}
		}
	}
	return false
}

func action(changed bool) string {
	if changed {
		return "update"
	}
	return "unchanged"
}

func comparisonState(exists, changed bool) string {
	if !exists {
		return "missing"
	}
	if changed {
		return "drift"
	}
	return "equal"
}

// SortedObjects provides stable presentation without changing bundle or panel ordering.
func (r Report) SortedObjects() []Object {
	result := append([]Object{}, r.Objects...)
	sort.Slice(result, func(i, j int) bool {
		if result[i].Kind != result[j].Kind {
			return result[i].Kind < result[j].Kind
		}
		return result[i].Name < result[j].Name
	})
	return result
}
