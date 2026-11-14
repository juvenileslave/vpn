package remnawave

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
	"unicode/utf8"
)

// ConfigProfile retains the complete response fields for in-memory planning.
// Config and Fields may contain credentials: never output them directly.
// Formatting and JSON encoding the model itself always redact its contents.
type ConfigProfile struct {
	UUID     string
	Name     string
	Config   json.RawMessage
	Inbounds []ConfigProfileInbound
	Fields   map[string]json.RawMessage
}

func (p ConfigProfile) String() string               { return "remnawave.ConfigProfile{redacted}" }
func (p ConfigProfile) GoString() string             { return p.String() }
func (p ConfigProfile) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }

// ConfigProfileInbound identifies an inbound and retains its complete fields.
type ConfigProfileInbound struct {
	UUID        string
	ProfileUUID string
	Tag         string
	Fields      map[string]json.RawMessage
}

func (i ConfigProfileInbound) String() string               { return "remnawave.ConfigProfileInbound{redacted}" }
func (i ConfigProfileInbound) GoString() string             { return i.String() }
func (i ConfigProfileInbound) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }

// Snippet has only a name and content in API 3.4.10, with no incarnation marker.
// Snippet and Fields are secret-bearing in-memory data, not output models.
type Snippet struct {
	Name    string
	Snippet json.RawMessage
	Fields  map[string]json.RawMessage
}

func (s Snippet) String() string               { return "remnawave.Snippet{redacted}" }
func (s Snippet) GoString() string             { return s.String() }
func (s Snippet) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }

// Host retains all response fields, including unknown settings, for planning.
type Host struct {
	UUID    string
	Remark  string
	Inbound HostInbound
	Fields  map[string]json.RawMessage
}

func (h Host) String() string               { return "remnawave.Host{redacted}" }
func (h Host) GoString() string             { return h.String() }
func (h Host) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }

// HostInbound contains profile references. Empty strings represent API nulls;
// Fields retains those nulls and any unknown nested settings without loss.
type HostInbound struct {
	ConfigProfileUUID        string
	ConfigProfileInboundUUID string
	Fields                   map[string]json.RawMessage
}

func (i HostInbound) String() string               { return "remnawave.HostInbound{redacted}" }
func (i HostInbound) GoString() string             { return i.String() }
func (i HostInbound) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }

// planningEnvelope validates the whole JSON tree, including opaque config and
// future fields, before decoding. Legacy user/node decoding stays unchanged.
func planningEnvelope(data []byte) (json.RawMessage, error) {
	if !utf8.Valid(data) {
		return nil, malformed("envelope: invalid utf8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := uniqueJSONValue(dec, 0); err != nil {
		return nil, malformed("envelope: invalid or duplicate-key json")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, malformed("envelope: unexpected data after json value")
	}
	fields, err := objectFields(data)
	if err != nil {
		return nil, err
	}
	return requiredField(fields, "response", false)
}

func uniqueJSONValue(dec *json.Decoder, depth int) error {
	if depth > 128 {
		return ErrMalformedResponse
	}
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for dec.More() {
			token, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok {
				return ErrMalformedResponse
			}
			if _, exists := seen[key]; exists {
				return ErrMalformedResponse
			}
			seen[key] = struct{}{}
			if err := uniqueJSONValue(dec, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := uniqueJSONValue(dec, depth+1); err != nil {
				return err
			}
		}
	default:
		return ErrMalformedResponse
	}
	closing, err := dec.Token()
	if err != nil {
		return err
	}
	if delim == '{' && closing != json.Delim('}') {
		return ErrMalformedResponse
	}
	if delim == '[' && closing != json.Delim(']') {
		return ErrMalformedResponse
	}
	return nil
}

func objectFields(raw []byte) (map[string]json.RawMessage, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '{' {
		return nil, malformed("response: expected object")
	}
	fields := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, malformed("response: invalid object")
	}
	return fields, nil
}

func arrayValues(raw []byte) ([]json.RawMessage, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '[' {
		return nil, malformed("response: expected array")
	}
	values := []json.RawMessage{}
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil, malformed("response: invalid array")
	}
	return values, nil
}

func isNull(raw []byte) bool { return bytes.Equal(bytes.TrimSpace(raw), []byte("null")) }

// key is always a source-code constant, never a key supplied by the panel.
func requiredField(fields map[string]json.RawMessage, key string, nullable bool) (json.RawMessage, error) {
	raw, ok := fields[key]
	if !ok || (!nullable && isNull(raw)) {
		return nil, malformed("response: missing or null %s", key)
	}
	return raw, nil
}

func fieldValue[T any](fields map[string]json.RawMessage, key string, nullable bool) (T, error) {
	var value T
	raw, err := requiredField(fields, key, nullable)
	if err != nil {
		return value, err
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return value, malformed("response: invalid %s", key)
	}
	return value, nil
}

func identityString(fields map[string]json.RawMessage, key string) (string, error) {
	value, err := fieldValue[string](fields, key, false)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(value) == "" {
		return "", malformed("response: empty %s", key)
	}
	return value, nil
}

func uuidField(fields map[string]json.RawMessage, key string, nullable bool) (string, error) {
	value, err := fieldValue[string](fields, key, nullable)
	if err != nil {
		return "", err
	}
	if nullable && isNull(fields[key]) {
		return "", nil
	}
	if !validUUID(value) {
		return "", malformed("response: invalid %s", key)
	}
	return value, nil
}

func validUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i := range len(value) {
		switch i {
		case 8, 13, 18, 23:
			if value[i] != '-' {
				return false
			}
		default:
			b := value[i]
			isDigit := b >= '0' && b <= '9'
			isLower := b >= 'a' && b <= 'f'
			isUpper := b >= 'A' && b <= 'F'
			if !isDigit && !isLower && !isUpper {
				return false
			}
		}
	}
	if value == "00000000-0000-0000-0000-000000000000" ||
		strings.EqualFold(value, "ffffffff-ffff-ffff-ffff-ffffffffffff") {
		return true
	}
	return value[14] >= '1' && value[14] <= '8' && strings.ContainsRune("89abAB", rune(value[19]))
}

func sameUUID(a, b string) bool { return strings.EqualFold(a, b) }

func collection(data []byte, key string) ([]json.RawMessage, error) {
	raw, err := planningEnvelope(data)
	if err != nil {
		return nil, err
	}
	fields, err := objectFields(raw)
	if err != nil {
		return nil, err
	}
	total, err := fieldValue[int64](fields, "total", false)
	if err != nil {
		return nil, err
	}
	raw, err = requiredField(fields, key, false)
	if err != nil {
		return nil, err
	}
	items, err := arrayValues(raw)
	if err != nil {
		return nil, err
	}
	if total < 0 || total != int64(len(items)) {
		return nil, malformed("response: inconsistent collection total")
	}
	return items, nil
}

func decodeConfigProfiles(data []byte) ([]ConfigProfile, error) {
	items, err := collection(data, "configProfiles")
	if err != nil {
		return nil, err
	}
	profiles := make([]ConfigProfile, 0, len(items))
	uuids := make(map[string]struct{}, len(items))
	names := make(map[string]struct{}, len(items))
	inbounds := map[string]struct{}{}
	for _, raw := range items {
		profile, err := decodeConfigProfile(raw)
		if err != nil {
			return nil, err
		}
		if err := uniqueIdentity(uuids, strings.ToLower(profile.UUID)); err != nil {
			return nil, err
		}
		if err := uniqueIdentity(names, profile.Name); err != nil {
			return nil, err
		}
		for _, inbound := range profile.Inbounds {
			if err := uniqueIdentity(inbounds, strings.ToLower(inbound.UUID)); err != nil {
				return nil, err
			}
		}
		profiles = append(profiles, profile)
	}
	return profiles, nil
}

func uniqueIdentity(seen map[string]struct{}, identity string) error {
	if _, exists := seen[identity]; exists {
		return malformed("response: duplicate identity")
	}
	seen[identity] = struct{}{}
	return nil
}

func decodeConfigProfile(raw []byte) (ConfigProfile, error) {
	fields, err := objectFields(raw)
	if err != nil {
		return ConfigProfile{}, err
	}
	uuid, err := uuidField(fields, "uuid", false)
	if err != nil {
		return ConfigProfile{}, err
	}
	name, err := identityString(fields, "name")
	if err != nil {
		return ConfigProfile{}, err
	}
	if _, err := fieldValue[int64](fields, "viewPosition", false); err != nil {
		return ConfigProfile{}, err
	}
	if err := stringArray(fields, "tags", nil); err != nil {
		return ConfigProfile{}, err
	}
	config, err := requiredField(fields, "config", false)
	if err != nil {
		return ConfigProfile{}, err
	}
	if len(bytes.TrimSpace(config)) == 0 || bytes.TrimSpace(config)[0] != '{' {
		return ConfigProfile{}, malformed("profile: config must be an object")
	}
	for _, key := range []string{"createdAt", "updatedAt"} {
		if _, err := fieldValue[time.Time](fields, key, false); err != nil {
			return ConfigProfile{}, err
		}
	}
	inboundRaw, err := requiredField(fields, "inbounds", false)
	if err != nil {
		return ConfigProfile{}, err
	}
	items, err := arrayValues(inboundRaw)
	if err != nil {
		return ConfigProfile{}, err
	}
	inbounds := make([]ConfigProfileInbound, 0, len(items))
	uuids := make(map[string]struct{}, len(items))
	tags := make(map[string]struct{}, len(items))
	for _, raw := range items {
		inbound, err := decodeProfileInbound(raw, uuid)
		if err != nil {
			return ConfigProfile{}, err
		}
		if err := uniqueIdentity(uuids, strings.ToLower(inbound.UUID)); err != nil {
			return ConfigProfile{}, err
		}
		if err := uniqueIdentity(tags, inbound.Tag); err != nil {
			return ConfigProfile{}, err
		}
		inbounds = append(inbounds, inbound)
	}
	if err := validateProfileNodes(fields); err != nil {
		return ConfigProfile{}, err
	}
	return ConfigProfile{UUID: uuid, Name: name, Config: config, Inbounds: inbounds, Fields: fields}, nil
}

func decodeProfileInbound(raw []byte, profileUUID string) (ConfigProfileInbound, error) {
	fields, err := objectFields(raw)
	if err != nil {
		return ConfigProfileInbound{}, err
	}
	uuid, err := uuidField(fields, "uuid", false)
	if err != nil {
		return ConfigProfileInbound{}, err
	}
	owner, err := uuidField(fields, "profileUuid", false)
	if err != nil {
		return ConfigProfileInbound{}, err
	}
	if !sameUUID(owner, profileUUID) {
		return ConfigProfileInbound{}, malformed("inbound: profile identity mismatch")
	}
	tag, err := identityString(fields, "tag")
	if err != nil {
		return ConfigProfileInbound{}, err
	}
	if _, err := fieldValue[string](fields, "type", false); err != nil {
		return ConfigProfileInbound{}, err
	}
	for _, key := range []string{"network", "security"} {
		if _, err := fieldValue[string](fields, key, true); err != nil {
			return ConfigProfileInbound{}, err
		}
	}
	if _, err := fieldValue[float64](fields, "port", true); err != nil {
		return ConfigProfileInbound{}, err
	}
	if _, err := requiredField(fields, "rawInbound", true); err != nil {
		return ConfigProfileInbound{}, err
	}
	return ConfigProfileInbound{UUID: uuid, ProfileUUID: owner, Tag: tag, Fields: fields}, nil
}

func validateProfileNodes(fields map[string]json.RawMessage) error {
	raw, err := requiredField(fields, "nodes", false)
	if err != nil {
		return err
	}
	nodes, err := arrayValues(raw)
	if err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(nodes))
	for _, raw := range nodes {
		fields, err := objectFields(raw)
		if err != nil {
			return err
		}
		uuid, err := uuidField(fields, "uuid", false)
		if err != nil {
			return err
		}
		if err := uniqueIdentity(seen, strings.ToLower(uuid)); err != nil {
			return err
		}
		for _, key := range []string{"name", "countryCode"} {
			if _, err := fieldValue[string](fields, key, false); err != nil {
				return err
			}
		}
	}
	return nil
}

func decodeSnippets(data []byte) ([]Snippet, error) {
	items, err := collection(data, "snippets")
	if err != nil {
		return nil, err
	}
	snippets := make([]Snippet, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, raw := range items {
		fields, err := objectFields(raw)
		if err != nil {
			return nil, err
		}
		name, err := identityString(fields, "name")
		if err != nil {
			return nil, err
		}
		if err := uniqueIdentity(seen, name); err != nil {
			return nil, err
		}
		content, err := requiredField(fields, "snippet", false)
		if err != nil {
			return nil, err
		}
		parts, err := arrayValues(content)
		if err != nil {
			return nil, err
		}
		if len(parts) == 0 {
			return nil, malformed("snippet: empty content")
		}
		for _, part := range parts {
			object, err := objectFields(part)
			if err != nil {
				return nil, err
			}
			if len(object) == 0 {
				return nil, malformed("snippet: empty content object")
			}
		}
		snippets = append(snippets, Snippet{Name: name, Snippet: content, Fields: fields})
	}
	return snippets, nil
}

func decodeHosts(data []byte) ([]Host, error) {
	raw, err := planningEnvelope(data)
	if err != nil {
		return nil, err
	}
	items, err := arrayValues(raw)
	if err != nil {
		return nil, err
	}
	hosts := make([]Host, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, raw := range items {
		host, err := decodeHost(raw)
		if err != nil {
			return nil, err
		}
		if err := uniqueIdentity(seen, strings.ToLower(host.UUID)); err != nil {
			return nil, err
		}
		hosts = append(hosts, host)
	}
	return hosts, nil
}

func decodeHost(raw []byte) (Host, error) {
	fields, err := objectFields(raw)
	if err != nil {
		return Host{}, err
	}
	uuid, err := uuidField(fields, "uuid", false)
	if err != nil {
		return Host{}, err
	}
	remark, err := identityString(fields, "remark")
	if err != nil {
		return Host{}, err
	}
	if err := validateHostFields(fields); err != nil {
		return Host{}, err
	}
	inboundRaw, err := requiredField(fields, "inbound", false)
	if err != nil {
		return Host{}, err
	}
	inboundFields, err := objectFields(inboundRaw)
	if err != nil {
		return Host{}, err
	}
	profileUUID, err := uuidField(inboundFields, "configProfileUuid", true)
	if err != nil {
		return Host{}, err
	}
	inboundUUID, err := uuidField(inboundFields, "configProfileInboundUuid", true)
	if err != nil {
		return Host{}, err
	}
	inbound := HostInbound{
		ConfigProfileUUID:        profileUUID,
		ConfigProfileInboundUUID: inboundUUID,
		Fields:                   inboundFields,
	}
	return Host{UUID: uuid, Remark: remark, Inbound: inbound, Fields: fields}, nil
}

func validateHostFields(fields map[string]json.RawMessage) error {
	for _, key := range []string{"viewPosition", "port"} {
		if _, err := fieldValue[int64](fields, key, false); err != nil {
			return err
		}
	}
	if _, err := fieldValue[string](fields, "address", false); err != nil {
		return err
	}
	for _, key := range []string{"path", "sni", "host", "fingerprint", "serverDescription",
		"pinnedPeerCertSha256", "verifyPeerCertByName"} {
		if _, err := fieldValue[string](fields, key, true); err != nil {
			return err
		}
	}
	for _, key := range []string{"isDisabled", "shuffleHost", "mihomoX25519"} {
		if _, err := fieldValue[bool](fields, key, false); err != nil {
			return err
		}
	}
	for _, key := range []string{"isHidden", "overrideSniFromAddress", "keepSniBlank"} {
		if _, exists := fields[key]; exists {
			if _, err := fieldValue[bool](fields, key, false); err != nil {
				return err
			}
		}
	}
	for _, key := range []string{"xhttpExtraParams", "muxParams", "sockoptParams", "finalMask"} {
		if _, err := requiredField(fields, key, true); err != nil {
			return err
		}
	}
	if err := enumField(fields, "alpn", true, []string{
		"h3", "h2", "http/1.1", "h2,http/1.1", "h3,h2,http/1.1", "h3,h2",
	}); err != nil {
		return err
	}
	if _, exists := fields["securityLayer"]; exists {
		if err := enumField(fields, "securityLayer", false, []string{"DEFAULT", "TLS", "NONE"}); err != nil {
			return err
		}
	}
	if err := enumField(fields, "mihomoIpVersion", true, []string{
		"dual", "ipv4", "ipv6", "ipv4-prefer", "ipv6-prefer",
	}); err != nil {
		return err
	}
	route, err := fieldValue[int64](fields, "vlessRouteId", true)
	if err != nil {
		return err
	}
	if route < 0 || route > 65535 {
		return malformed("response: invalid vlessRouteId")
	}
	if _, err := uuidField(fields, "xrayJsonTemplateUuid", true); err != nil {
		return err
	}
	if err := uuidArray(fields, "nodes"); err != nil {
		return err
	}
	if _, exists := fields["tags"]; exists {
		if err := stringArray(fields, "tags", nil); err != nil {
			return err
		}
	}
	if err := stringArray(fields, "includeInSrrRules", nil); err != nil {
		return err
	}
	if err := stringArray(fields, "excludeFromSubscriptionTypes", []string{
		"XRAY_JSON", "XRAY_BASE64", "MIHOMO", "STASH", "CLASH", "SINGBOX",
	}); err != nil {
		return err
	}
	mapperRaw, err := requiredField(fields, "mapper", false)
	if err != nil {
		return err
	}
	mapper, err := objectFields(mapperRaw)
	if err != nil {
		return err
	}
	for _, key := range []string{"xrayJson", "mihomo", "base64", "singbox"} {
		if raw, exists := mapper[key]; exists {
			operations, err := arrayValues(raw)
			if err != nil {
				return err
			}
			for _, operation := range operations {
				if _, err := objectFields(operation); err != nil {
					return err
				}
			}
		}
	}
	squadsRaw, err := requiredField(fields, "internalSquads", false)
	if err != nil {
		return err
	}
	squads, err := objectFields(squadsRaw)
	if err != nil {
		return err
	}
	if err := enumField(squads, "mode", false, []string{"EXCLUDE", "ALLOW_ONLY"}); err != nil {
		return err
	}
	return uuidArray(squads, "squads")
}

func enumField(fields map[string]json.RawMessage, key string, nullable bool, allowed []string) error {
	value, err := fieldValue[string](fields, key, nullable)
	if err != nil {
		return err
	}
	if nullable && isNull(fields[key]) {
		return nil
	}
	if !allowedValue(value, allowed) {
		return malformed("response: invalid %s", key)
	}
	return nil
}

func allowedValue(value string, allowed []string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func stringArray(fields map[string]json.RawMessage, key string, allowed []string) error {
	raw, err := requiredField(fields, key, false)
	if err != nil {
		return err
	}
	items, err := arrayValues(raw)
	if err != nil {
		return err
	}
	for _, item := range items {
		var value string
		if isNull(item) || json.Unmarshal(item, &value) != nil {
			return malformed("response: invalid string array")
		}
		if allowed != nil && !allowedValue(value, allowed) {
			return malformed("response: invalid %s", key)
		}
	}
	return nil
}

func uuidArray(fields map[string]json.RawMessage, key string) error {
	raw, err := requiredField(fields, key, false)
	if err != nil {
		return err
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '[' {
		return malformed("response: invalid uuid array")
	}
	values := []string{}
	if err := json.Unmarshal(raw, &values); err != nil {
		return malformed("response: invalid uuid array")
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validUUID(value) {
			return malformed("response: invalid uuid array")
		}
		if err := uniqueIdentity(seen, strings.ToLower(value)); err != nil {
			return err
		}
	}
	return nil
}
