package remnawave

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func planningUUID(t *testing.T) string {
	t.Helper()
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		t.Fatal("generating temporary uuid")
	}
	data[6] = data[6]&0x0f | 0x40
	data[8] = data[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", data[:4], data[4:6], data[6:8], data[8:10], data[10:])
}

func planningJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal("encoding synthetic fixture")
	}
	return string(data)
}

func planningProfile(uuid, inboundUUID, secret string) map[string]any {
	return map[string]any{
		"uuid": uuid, "name": "temporary-profile", "viewPosition": 0, "tags": []string{},
		"config": map[string]any{
			"inbounds": []any{map[string]any{
				"tag": "direct-v4", "settings": map[string]any{"clients": []any{map[string]any{"id": secret}}},
			}},
			"futureRoot": secret,
		},
		"inbounds": []any{map[string]any{
			"uuid": inboundUUID, "profileUuid": uuid, "tag": "direct-v4", "type": "vless",
			"network": "xhttp", "security": "tls", "port": 443,
			"rawInbound": map[string]any{"privateKey": secret}, "futureInbound": secret,
		}},
		"nodes": []any{}, "createdAt": "2026-11-01T00:00:00.000Z", "updatedAt": "2026-11-01T00:00:00.000Z",
		"futureProfile": map[string]any{"private": secret},
	}
}

func planningHost(uuid, profileUUID, inboundUUID, secret string) map[string]any {
	return map[string]any{
		"uuid": uuid, "remark": "temporary-host", "viewPosition": 0, "address": "192.0.2.1", "port": 443,
		"path": "/temporary", "sni": "temporary.example.test", "host": "temporary.example.test",
		"alpn": "h2", "fingerprint": "firefox", "isDisabled": false, "securityLayer": "TLS",
		"xhttpExtraParams": map[string]any{"private": secret}, "muxParams": nil, "sockoptParams": nil,
		"finalMask": nil,
		"inbound": map[string]any{
			"configProfileUuid": profileUUID, "configProfileInboundUuid": inboundUUID, "futureReference": secret,
		},
		"serverDescription": nil, "tags": []string{}, "isHidden": false, "overrideSniFromAddress": false,
		"keepSniBlank": false, "vlessRouteId": nil, "pinnedPeerCertSha256": nil, "verifyPeerCertByName": nil,
		"shuffleHost": false, "mihomoX25519": false, "mihomoIpVersion": nil,
		"nodes": []string{}, "xrayJsonTemplateUuid": nil, "excludeFromSubscriptionTypes": []string{},
		"mapper": map[string]any{}, "includeInSrrRules": []string{},
		"internalSquads": map[string]any{"mode": "EXCLUDE", "squads": []string{}},
		"futureHost":     map[string]any{"private": secret},
	}
}

type planningReadCase struct {
	name string
	path string
	body string
	read func(*Client, context.Context) (any, error)
}

func planningReads(t *testing.T, secret string) []planningReadCase {
	t.Helper()
	profileUUID := planningUUID(t)
	inboundUUID := planningUUID(t)
	hostUUID := planningUUID(t)
	profile := planningProfile(profileUUID, inboundUUID, secret)
	host := planningHost(hostUUID, profileUUID, inboundUUID, secret)
	snippet := map[string]any{
		"name": "temporary-snippet", "snippet": []any{map[string]any{"privateKey": secret}}, "futureSnippet": secret,
	}
	return []planningReadCase{
		{
			name: "list profiles", path: "/api/config-profiles",
			body: planningJSON(t, map[string]any{"response": map[string]any{"total": 1, "configProfiles": []any{profile}}}),
			read: func(c *Client, ctx context.Context) (any, error) { return c.ListConfigProfiles(ctx) },
		},
		{
			name: "profile", path: "/api/config-profiles/" + profileUUID,
			body: planningJSON(t, map[string]any{"response": profile}),
			read: func(c *Client, ctx context.Context) (any, error) { return c.ConfigProfile(ctx, profileUUID) },
		},
		{
			name: "computed profile", path: "/api/config-profiles/" + profileUUID + "/computed-config",
			body: planningJSON(t, map[string]any{"response": profile}),
			read: func(c *Client, ctx context.Context) (any, error) { return c.ComputedConfigProfile(ctx, profileUUID) },
		},
		{
			name: "snippets", path: "/api/snippets",
			body: planningJSON(t, map[string]any{"response": map[string]any{"total": 1, "snippets": []any{snippet}}}),
			read: func(c *Client, ctx context.Context) (any, error) { return c.ListSnippets(ctx) },
		},
		{
			name: "list hosts", path: "/api/hosts", body: planningJSON(t, map[string]any{"response": []any{host}}),
			read: func(c *Client, ctx context.Context) (any, error) { return c.ListHosts(ctx) },
		},
		{
			name: "host", path: "/api/hosts/" + hostUUID, body: planningJSON(t, map[string]any{"response": host}),
			read: func(c *Client, ctx context.Context) (any, error) { return c.Host(ctx, hostUUID) },
		},
	}
}

// Every planning request must be exactly a bodyless, queryless GET. The TLS
// client trusts only httptest's local certificate; it never skips verification.
func planningServer(t *testing.T, token, path string, h http.HandlerFunc, opts ...Option) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		valid := r.Method == http.MethodGet && r.URL.Path == "/private-panel"+path && r.URL.RawQuery == ""
		validHeaders := r.Header.Get("Authorization") == "Bearer "+token &&
			r.Header.Get("Accept") == "application/json" && r.Header.Get("Content-Type") == ""
		body, err := io.ReadAll(r.Body)
		if !valid || !validHeaders || err != nil || len(body) != 0 || r.ContentLength != 0 {
			t.Error("planning request violates readonly method/path/query/header/body contract")
			writeJSON(w, http.StatusBadRequest, `{"errorCode":"A063"}`)
			return
		}
		if r.Header.Get("If-Match") != "" {
			t.Error("readonly request invents a write precondition")
		}
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL + "/private-panel/")
	if err != nil {
		t.Fatal("parsing temporary server url")
	}
	c, err := New(u, token, srv.Client(), opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, srv
}

func assertPlanningRedacted(t *testing.T, value any, markers ...string) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal("encoding redacted model")
	}
	outputs := []string{
		fmt.Sprintf("%v", value), fmt.Sprintf("%+v", value), fmt.Sprintf("%#v", value), string(encoded),
	}
	for _, output := range outputs {
		for _, marker := range markers {
			if strings.Contains(output, marker) {
				t.Error("planning output exposes a secret or identity")
			}
		}
	}
}

func TestPlanningReadsPinnedEnvelopesAndRedaction(t *testing.T) {
	token := rand.Text()
	secret := rand.Text()
	for _, tc := range planningReads(t, secret) {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int32
			c, _ := planningServer(t, token, tc.path, func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				writeJSON(w, http.StatusOK, tc.body)
			})
			value, err := tc.read(c, context.Background())
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if hits.Load() != 1 {
				t.Fatal("read must make exactly one request")
			}
			assertPlanningRedacted(t, value, token, secret, "temporary-profile", "temporary-host", "temporary-snippet")
			switch value := value.(type) {
			case ConfigProfile:
				assertProfileMemory(t, value, secret)
			case []ConfigProfile:
				if len(value) != 1 {
					t.Fatal("profile collection length")
				}
				assertProfileMemory(t, value[0], secret)
			case []Snippet:
				if len(value) != 1 || value[0].Name != "temporary-snippet" ||
					!strings.Contains(string(value[0].Snippet), secret) ||
					!strings.Contains(string(value[0].Fields["futureSnippet"]), secret) {
					t.Fatal("snippet content or unknown fields were lost")
				}
				assertPlanningRedacted(t, &value[0], token, secret, value[0].Name)
			case Host:
				assertHostMemory(t, value, secret)
			case []Host:
				if len(value) != 1 {
					t.Fatal("host collection length")
				}
				assertHostMemory(t, value[0], secret)
			default:
				t.Fatal("unexpected read model")
			}
		})
	}
}

func assertProfileMemory(t *testing.T, profile ConfigProfile, secret string) {
	t.Helper()
	if !validUUID(profile.UUID) || profile.Name != "temporary-profile" || len(profile.Inbounds) != 1 {
		t.Fatal("profile identity was lost")
	}
	inbound := profile.Inbounds[0]
	if !validUUID(inbound.UUID) || inbound.ProfileUUID != profile.UUID || inbound.Tag != "direct-v4" {
		t.Fatal("inbound identity was lost")
	}
	if !strings.Contains(string(profile.Config), secret) ||
		!strings.Contains(string(profile.Fields["futureProfile"]), secret) ||
		!strings.Contains(string(inbound.Fields["futureInbound"]), secret) {
		t.Fatal("raw config, static clients or unknown profile/inbound fields were lost")
	}
	assertPlanningRedacted(t, &profile, secret, profile.UUID, profile.Name)
	assertPlanningRedacted(t, []ConfigProfileInbound{inbound}, secret, inbound.UUID, inbound.Tag)
	assertPlanningRedacted(t, map[string]any{"profile": profile, "inbound": &inbound}, secret, profile.Name)
}

func assertHostMemory(t *testing.T, host Host, secret string) {
	t.Helper()
	if !validUUID(host.UUID) || host.Remark != "temporary-host" ||
		!validUUID(host.Inbound.ConfigProfileUUID) || !validUUID(host.Inbound.ConfigProfileInboundUUID) {
		t.Fatal("host identity was lost")
	}
	if !strings.Contains(string(host.Fields["futureHost"]), secret) ||
		!strings.Contains(string(host.Inbound.Fields["futureReference"]), secret) {
		t.Fatal("unknown host or inbound fields were lost")
	}
	assertPlanningRedacted(t, &host, secret, host.UUID, host.Remark)
	assertPlanningRedacted(t, []HostInbound{host.Inbound}, secret, host.Inbound.ConfigProfileUUID)
	assertPlanningRedacted(t, map[string]any{"host": host, "inbound": &host.Inbound}, secret, host.Remark)
}

func TestPlanningReadsRejectMalformedJSON(t *testing.T) {
	token := rand.Text()
	secret := rand.Text()
	for _, tc := range planningReads(t, secret) {
		t.Run(tc.name, func(t *testing.T) {
			var body atomic.Value
			body.Store("")
			c, _ := planningServer(t, token, tc.path, func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, http.StatusOK, body.Load().(string))
			})
			cases := map[string]string{
				"empty": "", "invalid": secret, "truncated": tc.body[:len(tc.body)-1],
				"trailing value": tc.body + `{}`, "trailing garbage": tc.body + secret,
				"null envelope": `null`, "array envelope": `[]`, "missing response": `{}`,
				"case altered response": strings.Replace(tc.body, `"response"`, `"Response"`, 1),
				"null response":         `{"response":null}`, "scalar response": `{"response":true}`,
				"duplicate response": strings.TrimSuffix(tc.body, "}") + `,"response":[]}`,
				"escaped duplicate":  strings.TrimSuffix(tc.body, "}") + `,"respon\u0073e":[]}`,
				"unknown duplicate": strings.TrimSuffix(tc.body, "}") +
					`,"future":{"private":1,"private":2}}`,
			}
			for name, malformedBody := range cases {
				t.Run(name, func(t *testing.T) {
					body.Store(malformedBody)
					_, err := tc.read(c, context.Background())
					if !errors.Is(err, ErrMalformedResponse) {
						t.Fatalf("read error = %v, want malformed response", err)
					}
					assertPlanningRedacted(t, err, token, secret)
				})
			}
		})
	}
}

func TestPlanningReadsRejectInvalidArgumentsBeforeIO(t *testing.T) {
	var hits atomic.Int32
	c, _ := planningServer(t, rand.Text(), "/unused", func(w http.ResponseWriter, r *http.Request) { hits.Add(1) })
	for _, value := range []string{
		"", "not-a-uuid", "../hosts", "00000000-0000-4000-8000-00000000000g",
		"00000000-0000-0000-8000-000000000001", "00000000-0000-4000-7000-000000000001",
		planningUUID(t) + "?token=" + rand.Text(),
	} {
		for _, read := range []func(context.Context, string) (any, error){
			func(ctx context.Context, uuid string) (any, error) { return c.ConfigProfile(ctx, uuid) },
			func(ctx context.Context, uuid string) (any, error) { return c.ComputedConfigProfile(ctx, uuid) },
			func(ctx context.Context, uuid string) (any, error) { return c.Host(ctx, uuid) },
		} {
			if _, err := read(context.Background(), value); !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("invalid uuid: %v", err)
			}
		}
	}
	for _, tc := range planningReads(t, rand.Text()) {
		if _, err := tc.read(c, nil); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("nil context: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := tc.read(c, ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("pre-cancelled context: %v", err)
		}
	}
	if hits.Load() != 0 {
		t.Fatal("invalid arguments caused network io")
	}
}

func TestPlanningReadsHTTPFailuresAndLimits(t *testing.T) {
	for _, tc := range planningReads(t, rand.Text()) {
		t.Run(tc.name, func(t *testing.T) {
			token := rand.Text()
			secret := rand.Text()
			var status atomic.Int32
			status.Store(http.StatusOK)
			c, _ := planningServer(t, token, tc.path, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Retry-After", "7")
				w.Header().Set("Location", "https://example.test/%zz?token="+token)
				writeJSON(w, int(status.Load()), `{"errorCode":"A063","message":"`+secret+`"}`)
			})
			for _, failure := range []struct {
				status   int
				sentinel error
			}{
				{301, ErrRedirect}, {303, ErrRedirect}, {307, ErrRedirect}, {308, ErrRedirect},
				{400, ErrBadRequest}, {401, ErrUnauthorized}, {403, ErrForbidden}, {404, ErrNotFound},
				{409, ErrUnexpectedStatus}, {429, ErrRateLimited}, {500, ErrServer}, {503, ErrServer},
			} {
				status.Store(int32(failure.status))
				_, err := tc.read(c, context.Background())
				var apiErr *APIError
				if !errors.Is(err, failure.sentinel) || !errors.As(err, &apiErr) || apiErr.StatusCode != failure.status {
					t.Fatalf("status %d: %v", failure.status, err)
				}
				if failure.status == 429 && apiErr.RetryAfter != 7*time.Second {
					t.Fatal("retry-after was lost")
				}
				assertPlanningRedacted(t, err, token, secret, "example.test", "%zz")
			}
			for _, chunked := range []bool{false, true} {
				large := tc.body + strings.Repeat(" ", 4096)
				c, _ := planningServer(t, token, tc.path, func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					if !chunked {
						w.Header().Set("Content-Length", strconv.Itoa(len(large)))
					}
					for offset := 0; offset < len(large); offset += 256 {
						if _, err := io.WriteString(w, large[offset:min(offset+256, len(large))]); err != nil {
							return
						}
						if chunked {
							w.(http.Flusher).Flush()
						}
					}
				}, WithMaxResponseBytes(1024))
				if _, err := tc.read(c, context.Background()); !errors.Is(err, ErrResponseTooLarge) {
					t.Fatalf("body limit: %v", err)
				}
			}
			c, _ = planningServer(t, token, tc.path, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; private="+secret)
				_, _ = io.WriteString(w, secret)
			})
			_, err := tc.read(c, context.Background())
			if !errors.Is(err, ErrMalformedResponse) {
				t.Fatalf("content type: %v", err)
			}
			assertPlanningRedacted(t, err, token, secret)
		})
	}
}

func TestPlanningReadsCancellationDeadlineAndClientTimeout(t *testing.T) {
	for _, tc := range planningReads(t, rand.Text()) {
		t.Run(tc.name, func(t *testing.T) {
			for _, afterHeaders := range []bool{false, true} {
				started := make(chan struct{}, 3)
				c, _ := planningServer(t, rand.Text(), tc.path, func(w http.ResponseWriter, r *http.Request) {
					if afterHeaders {
						w.Header().Set("Content-Type", "application/json")
						_, _ = io.WriteString(w, `{"response":`)
						w.(http.Flusher).Flush()
					}
					started <- struct{}{}
					<-r.Context().Done()
				})
				ctx, cancel := context.WithCancel(context.Background())
				go func() { <-started; cancel() }()
				if _, err := tc.read(c, ctx); !errors.Is(err, context.Canceled) {
					t.Fatalf("cancel: %v", err)
				}
				ctx, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
				_, err := tc.read(c, ctx)
				stop()
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("deadline: %v", err)
				}
				c.http.Timeout = 100 * time.Millisecond
				_, err = tc.read(c, context.Background())
				var timeout net.Error
				if !errors.As(err, &timeout) || !timeout.Timeout() {
					t.Fatalf("client timeout: %v", err)
				}
			}
		})
	}
}

func TestPlanningCollectionShapesTotalsAndDuplicateIdentities(t *testing.T) {
	profileUUID, inboundUUID, hostUUID := planningUUID(t), planningUUID(t), planningUUID(t)
	profile := planningProfile(profileUUID, inboundUUID, rand.Text())
	host := planningHost(hostUUID, profileUUID, inboundUUID, rand.Text())
	snippet := map[string]any{"name": "temporary-snippet", "snippet": []any{map[string]any{"key": "value"}}}
	cases := []struct {
		name, body string
		decode     func([]byte) error
	}{
		{"profiles", planningJSON(t, map[string]any{
			"response": map[string]any{"total": 2, "configProfiles": []any{profile, profile}},
		}), func(data []byte) error { _, err := decodeConfigProfiles(data); return err }},
		{"snippets", planningJSON(t, map[string]any{
			"response": map[string]any{"total": 2, "snippets": []any{snippet, snippet}},
		}), func(data []byte) error { _, err := decodeSnippets(data); return err }},
		{"hosts", planningJSON(t, map[string]any{"response": []any{host, host}}),
			func(data []byte) error { _, err := decodeHosts(data); return err }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.decode([]byte(tc.body)); !errors.Is(err, ErrMalformedResponse) {
				t.Fatalf("duplicate identity: %v", err)
			}
		})
	}
	for _, key := range []string{"configProfiles", "snippets"} {
		decode := func(data []byte) error { _, err := decodeConfigProfiles(data); return err }
		if key == "snippets" {
			decode = func(data []byte) error { _, err := decodeSnippets(data); return err }
		}
		for _, body := range []string{
			`{"response":{"total":1,"` + key + `":[]}}`, `{"response":{"total":-1,"` + key + `":[]}}`,
			`{"response":{"total":1.5,"` + key + `":[]}}`, `{"response":{"total":"0","` + key + `":[]}}`,
			`{"response":{"` + key + `":[]}}`, `{"response":{"total":0,"` + key + `":null}}`,
			`{"response":{"total":0,"` + key + `":{}}}`, `{"response":{"total":0}}`,
		} {
			if err := decode([]byte(body)); !errors.Is(err, ErrMalformedResponse) {
				t.Fatalf("invalid collection: %v", err)
			}
		}
	}
	profiles, err := decodeConfigProfiles([]byte(`{"response":{"total":0,"configProfiles":[]}}`))
	if err != nil || profiles == nil || len(profiles) != 0 {
		t.Fatal("empty profile collection must be non-nil")
	}
	snippets, err := decodeSnippets([]byte(`{"response":{"total":0,"snippets":[]}}`))
	if err != nil || snippets == nil || len(snippets) != 0 {
		t.Fatal("empty snippet collection must be non-nil")
	}
	hosts, err := decodeHosts([]byte(`{"response":[]}`))
	if err != nil || hosts == nil || len(hosts) != 0 {
		t.Fatal("empty host collection must be non-nil")
	}
}

func TestPlanningMandatoryFieldsAndNestedValidation(t *testing.T) {
	profileUUID, inboundUUID, hostUUID := planningUUID(t), planningUUID(t), planningUUID(t)
	secret := rand.Text()
	profile := planningProfile(profileUUID, inboundUUID, secret)
	host := planningHost(hostUUID, profileUUID, inboundUUID, secret)
	for _, tc := range []struct {
		name     string
		fields   map[string]any
		decode   func([]byte) error
		optional map[string]bool
	}{
		{"profile", profile, func(data []byte) error { _, err := decodeConfigProfile(data); return err },
			map[string]bool{"futureProfile": true}},
		{"host", host, func(data []byte) error { _, err := decodeHost(data); return err },
			map[string]bool{"futureHost": true, "securityLayer": true, "tags": true, "isHidden": true,
				"overrideSniFromAddress": true, "keepSniBlank": true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for key, original := range tc.fields {
				if tc.optional[key] {
					continue
				}
				delete(tc.fields, key)
				if err := tc.decode([]byte(planningJSON(t, tc.fields))); !errors.Is(err, ErrMalformedResponse) {
					t.Errorf("missing mandatory %s: %v", key, err)
				}
				tc.fields[key] = original
			}
		})
	}
	inbound := profile["inbounds"].([]any)[0].(map[string]any)
	for key, original := range inbound {
		if key == "futureInbound" {
			continue
		}
		delete(inbound, key)
		if _, err := decodeConfigProfile([]byte(planningJSON(t, profile))); !errors.Is(err, ErrMalformedResponse) {
			t.Errorf("missing mandatory inbound %s: %v", key, err)
		}
		inbound[key] = original
	}
	for _, change := range []struct {
		fields map[string]any
		key    string
		value  any
	}{
		{profile, "uuid", secret}, {profile, "name", ""}, {profile, "config", []any{}},
		{profile, "createdAt", secret}, {profile, "updatedAt", nil}, {profile, "tags", []any{nil}},
		{profile, "nodes", []any{map[string]any{"uuid": secret}}},
		{inbound, "profileUuid", planningUUID(t)}, {inbound, "uuid", secret}, {inbound, "network", true},
		{inbound, "port", "443"}, {inbound, "security", []any{}}, {inbound, "tag", ""},
	} {
		original := change.fields[change.key]
		change.fields[change.key] = change.value
		_, err := decodeConfigProfile([]byte(planningJSON(t, profile)))
		change.fields[change.key] = original
		if !errors.Is(err, ErrMalformedResponse) {
			t.Errorf("invalid profile/inbound %s: %v", change.key, err)
		}
		assertPlanningRedacted(t, err, secret)
	}
	profile["inbounds"] = []any{inbound, inbound}
	if _, err := decodeConfigProfile([]byte(planningJSON(t, profile))); !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("duplicate inbound: %v", err)
	}
	hostInbound := host["inbound"].(map[string]any)
	for _, key := range []string{"configProfileUuid", "configProfileInboundUuid"} {
		original := hostInbound[key]
		delete(hostInbound, key)
		if _, err := decodeHost([]byte(planningJSON(t, host))); !errors.Is(err, ErrMalformedResponse) {
			t.Errorf("missing host reference %s: %v", key, err)
		}
		hostInbound[key] = secret
		if _, err := decodeHost([]byte(planningJSON(t, host))); !errors.Is(err, ErrMalformedResponse) {
			t.Errorf("invalid host reference %s: %v", key, err)
		}
		hostInbound[key] = original
	}
	for _, key := range []string{"configProfileUuid", "configProfileInboundUuid"} {
		hostInbound[key] = nil
	}
	decodedHost, err := decodeHost([]byte(planningJSON(t, host)))
	if err != nil || decodedHost.Inbound.ConfigProfileUUID != "" || decodedHost.Inbound.ConfigProfileInboundUUID != "" {
		t.Fatal("nullable host references were not preserved")
	}
	for _, change := range []struct {
		key   string
		value any
	}{
		{"uuid", secret}, {"remark", ""}, {"address", true}, {"port", 443.5}, {"isDisabled", nil},
		{"alpn", secret}, {"securityLayer", secret}, {"mihomoIpVersion", secret}, {"tags", []any{nil}},
		{"vlessRouteId", -1}, {"vlessRouteId", 65536}, {"xrayJsonTemplateUuid", secret},
		{"nodes", []string{secret}}, {"mapper", []any{}},
		{"internalSquads", map[string]any{"mode": secret, "squads": []string{}}},
	} {
		original := host[change.key]
		host[change.key] = change.value
		_, err := decodeHost([]byte(planningJSON(t, host)))
		host[change.key] = original
		if !errors.Is(err, ErrMalformedResponse) {
			t.Errorf("invalid host %s: %v", change.key, err)
		}
		assertPlanningRedacted(t, err, secret)
	}
	for _, content := range []any{nil, map[string]any{}, []any{}, []any{nil}, []any{map[string]any{}}, []any{"secret"}} {
		body := planningJSON(t, map[string]any{"response": map[string]any{
			"total": 1, "snippets": []any{map[string]any{"name": "temporary-snippet", "snippet": content}},
		}})
		if _, err := decodeSnippets([]byte(body)); !errors.Is(err, ErrMalformedResponse) {
			t.Fatalf("invalid snippet content: %v", err)
		}
	}
}

func TestPlanningSingleReadsRejectIdentityMismatch(t *testing.T) {
	for _, tc := range planningReads(t, rand.Text()) {
		if tc.name != "profile" && tc.name != "computed profile" && tc.name != "host" {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			var envelope map[string]any
			if err := json.Unmarshal([]byte(tc.body), &envelope); err != nil {
				t.Fatal("decoding synthetic fixture")
			}
			envelope["response"].(map[string]any)["uuid"] = planningUUID(t)
			body := planningJSON(t, envelope)
			c, _ := planningServer(t, rand.Text(), tc.path, func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, http.StatusOK, body)
			})
			if _, err := tc.read(c, context.Background()); !errors.Is(err, ErrMalformedResponse) {
				t.Fatalf("identity mismatch: %v", err)
			}
		})
	}
}

type planningFailTransport struct{ cause error }

func (f planningFailTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, f.cause }

type planningFailBody struct{ cause error }

func (b planningFailBody) Read([]byte) (int, error) { return 0, b.cause }
func (b planningFailBody) Close() error             { return nil }

type planningBodyTransport struct{ body io.ReadCloser }

func (b planningBodyTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}},
		Body: b.body, ContentLength: -1,
	}, nil
}

func TestPlanningTransportAndBodyErrorsRedactPreservingCause(t *testing.T) {
	token, secret := rand.Text(), rand.Text()
	cause := errors.New("https://private.example.test/?token=" + token + " body=" + secret)
	u, err := url.Parse("https://private.example.test")
	if err != nil {
		t.Fatal("parsing synthetic url")
	}
	for _, transport := range []http.RoundTripper{
		planningFailTransport{cause: cause}, planningBodyTransport{body: planningFailBody{cause: cause}},
	} {
		c, err := New(u, token, &http.Client{Transport: transport})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		for _, tc := range planningReads(t, secret) {
			_, err := tc.read(c, context.Background())
			if !errors.Is(err, cause) {
				t.Fatalf("transport/body cause lost: %v", err)
			}
			assertPlanningRedacted(t, err, token, secret, "private.example.test")
		}
	}
}
