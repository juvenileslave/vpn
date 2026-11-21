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

func ptr[T any](v T) *T { return &v }

type writeCase struct {
	name       string
	method     string
	path       string
	hasBody    bool
	wantBody   string
	status     int
	respBody   string
	call       func(*Client, context.Context) (any, error)
	verify     func(*testing.T, any)
	inputValue any
}

func writeServer(t *testing.T, token, wantMethod, wantPath string, hasBody bool, h func(http.ResponseWriter, *http.Request, []byte), opts ...Option) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error("reading request body")
			writeJSON(w, http.StatusBadRequest, `{"errorCode":"A063"}`)
			return
		}
		if r.Method != wantMethod || r.URL.Path != "/private-panel"+wantPath || r.URL.RawQuery != "" {
			t.Errorf("request %s %s?%s, want %s /private-panel%s", r.Method, r.URL.Path, r.URL.RawQuery, wantMethod, wantPath)
			writeJSON(w, http.StatusBadRequest, `{"errorCode":"A063"}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("missing or wrong authorization header")
			writeJSON(w, http.StatusUnauthorized, `{"errorCode":"E401"}`)
			return
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Error("missing or wrong accept header")
			writeJSON(w, http.StatusBadRequest, `{"errorCode":"A063"}`)
			return
		}
		if r.Header.Get("If-Match") != "" {
			t.Error("write request must not invent If-Match")
			writeJSON(w, http.StatusBadRequest, `{"errorCode":"A063"}`)
			return
		}
		if hasBody {
			if r.Header.Get("Content-Type") != "application/json" || len(body) == 0 {
				t.Error("body-bearing write request must set application/json and non-empty body")
				writeJSON(w, http.StatusBadRequest, `{"errorCode":"A063"}`)
				return
			}
		} else {
			if r.Header.Get("Content-Type") != "" || len(body) != 0 || r.ContentLength != 0 {
				t.Error("bodyless write request must omit Content-Type and body")
				writeJSON(w, http.StatusBadRequest, `{"errorCode":"A063"}`)
				return
			}
		}
		h(w, r, body)
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

func writeCases(t *testing.T, secret string) []writeCase {
	t.Helper()
	profileUUID := planningUUID(t)
	inboundUUID := planningUUID(t)
	hostUUID := planningUUID(t)

	profile := planningProfile(profileUUID, inboundUUID, secret)
	profileEnvelope := planningJSON(t, map[string]any{"response": profile})
	snippetObj := map[string]any{
		"name": "routing/direct-v4", "snippet": []any{map[string]any{"privateKey": secret}}, "futureSnippet": secret,
	}
	otherSnippet := map[string]any{
		"name": "other-snippet", "snippet": []any{map[string]any{"tag": "other"}},
	}
	snippetEnvelope := planningJSON(t, map[string]any{
		"response": map[string]any{"total": 2, "snippets": []any{otherSnippet, snippetObj}},
	})
	host := planningHost(hostUUID, profileUUID, inboundUUID, secret)
	hostEnvelope := planningJSON(t, map[string]any{"response": host})

	cfgRaw := json.RawMessage(`{ "inbounds" : [ { "tag" : "direct-v4", "secret" : "` + secret + `" } ] }`)
	cfgCompact := `{"inbounds":[{"tag":"direct-v4","secret":"` + secret + `"}]}`
	snipRaw := json.RawMessage(`[ { "privateKey" : "` + secret + `" } ]`)
	snipCompact := `[{"privateKey":"` + secret + `"}]`

	createProfileIn := CreateConfigProfileInput{Name: "temporary-profile", Config: cfgRaw}
	updateProfileAll := UpdateConfigProfileInput{UUID: profileUUID, Name: ptr("temporary-profile"), Config: cfgRaw}
	updateProfileNameOnly := UpdateConfigProfileInput{UUID: profileUUID, Name: ptr("temporary-profile")}
	updateProfileCfgOnly := UpdateConfigProfileInput{UUID: profileUUID, Config: cfgRaw}
	writeSnippetIn := WriteSnippetInput{Name: "routing/direct-v4", Snippet: snipRaw}
	createHostMin := WriteHost{
		HostName: "temporary-host",
		Address:  "192.0.2.1",
		Port:     443,
		Inbound:  InboundRef{ConfigProfileUUID: profileUUID, ConfigProfileInboundUUID: inboundUUID},
	}
	createHostOpts := WriteHost{
		HostName:               "temporary-host",
		Address:                "192.0.2.1",
		Port:                   443,
		Path:                   ptr(""),
		SNI:                    ptr("edge.example.test"),
		Host:                   ptr("edge.example.test"),
		Fingerprint:            ptr("firefox"),
		Inbound:                InboundRef{ConfigProfileUUID: profileUUID, ConfigProfileInboundUUID: inboundUUID},
		OverrideSNIFromAddress: ptr(false),
		KeepSNIBlank:           ptr(true),
		ShuffleHost:            ptr(false),
	}
	updateHostPartial := UpdateHostInput{
		UUID: hostUUID,
		Port: ptr(8443),
	}
	updateHostOpts := UpdateHostInput{
		UUID:                   hostUUID,
		HostName:               ptr("temporary-host"),
		Address:                ptr("192.0.2.2"),
		Port:                   ptr(8443),
		Path:                   ptr(""),
		Inbound:                &InboundRef{ConfigProfileUUID: profileUUID, ConfigProfileInboundUUID: inboundUUID},
		OverrideSNIFromAddress: ptr(false),
		KeepSNIBlank:           ptr(false),
		ShuffleHost:            ptr(true),
	}

	return []writeCase{
		{
			name:       "create config profile",
			method:     http.MethodPost,
			path:       "/api/config-profiles",
			hasBody:    true,
			wantBody:   `{"name":"temporary-profile","config":` + cfgCompact + `}`,
			status:     http.StatusCreated,
			respBody:   profileEnvelope,
			inputValue: createProfileIn,
			call:       func(c *Client, ctx context.Context) (any, error) { return c.CreateConfigProfile(ctx, createProfileIn) },
			verify: func(t *testing.T, v any) {
				assertProfileMemory(t, v.(ConfigProfile), secret)
			},
		},
		{
			name:       "update config profile full",
			method:     http.MethodPatch,
			path:       "/api/config-profiles",
			hasBody:    true,
			wantBody:   `{"uuid":"` + profileUUID + `","name":"temporary-profile","config":` + cfgCompact + `}`,
			status:     http.StatusOK,
			respBody:   profileEnvelope,
			inputValue: updateProfileAll,
			call:       func(c *Client, ctx context.Context) (any, error) { return c.UpdateConfigProfile(ctx, updateProfileAll) },
			verify: func(t *testing.T, v any) {
				assertProfileMemory(t, v.(ConfigProfile), secret)
			},
		},
		{
			name:       "update config profile name only",
			method:     http.MethodPatch,
			path:       "/api/config-profiles",
			hasBody:    true,
			wantBody:   `{"uuid":"` + profileUUID + `","name":"temporary-profile"}`,
			status:     http.StatusOK,
			respBody:   profileEnvelope,
			inputValue: updateProfileNameOnly,
			call: func(c *Client, ctx context.Context) (any, error) {
				return c.UpdateConfigProfile(ctx, updateProfileNameOnly)
			},
			verify: func(t *testing.T, v any) {
				assertProfileMemory(t, v.(ConfigProfile), secret)
			},
		},
		{
			name:       "update config profile config only",
			method:     http.MethodPatch,
			path:       "/api/config-profiles",
			hasBody:    true,
			wantBody:   `{"uuid":"` + profileUUID + `","config":` + cfgCompact + `}`,
			status:     http.StatusOK,
			respBody:   profileEnvelope,
			inputValue: updateProfileCfgOnly,
			call: func(c *Client, ctx context.Context) (any, error) {
				return c.UpdateConfigProfile(ctx, updateProfileCfgOnly)
			},
			verify: func(t *testing.T, v any) {
				assertProfileMemory(t, v.(ConfigProfile), secret)
			},
		},
		{
			name:     "delete config profile",
			method:   http.MethodDelete,
			path:     "/api/config-profiles/" + profileUUID,
			hasBody:  false,
			status:   http.StatusNoContent,
			respBody: "",
			call:     func(c *Client, ctx context.Context) (any, error) { return nil, c.DeleteConfigProfile(ctx, profileUUID) },
		},
		{
			name:       "create snippet",
			method:     http.MethodPost,
			path:       "/api/snippets",
			hasBody:    true,
			wantBody:   `{"name":"routing/direct-v4","snippet":` + snipCompact + `}`,
			status:     http.StatusCreated,
			respBody:   snippetEnvelope,
			inputValue: writeSnippetIn,
			call:       func(c *Client, ctx context.Context) (any, error) { return c.CreateSnippet(ctx, writeSnippetIn) },
			verify: func(t *testing.T, v any) {
				items := v.([]Snippet)
				if len(items) != 2 || items[1].Name != "routing/direct-v4" || !strings.Contains(string(items[1].Snippet), secret) {
					t.Fatal("snippet collection or content was lost")
				}
			},
		},
		{
			name:       "update snippet",
			method:     http.MethodPatch,
			path:       "/api/snippets",
			hasBody:    true,
			wantBody:   `{"name":"routing/direct-v4","snippet":` + snipCompact + `}`,
			status:     http.StatusOK,
			respBody:   snippetEnvelope,
			inputValue: writeSnippetIn,
			call:       func(c *Client, ctx context.Context) (any, error) { return c.UpdateSnippet(ctx, writeSnippetIn) },
			verify: func(t *testing.T, v any) {
				items := v.([]Snippet)
				if len(items) != 2 || items[1].Name != "routing/direct-v4" {
					t.Fatal("updated snippet collection was lost")
				}
			},
		},
		{
			name:     "delete snippet",
			method:   http.MethodDelete,
			path:     "/api/snippets",
			hasBody:  true,
			wantBody: `{"name":"routing/direct-v4"}`,
			status:   http.StatusNoContent,
			respBody: "",
			call: func(c *Client, ctx context.Context) (any, error) {
				return nil, c.DeleteSnippet(ctx, "routing/direct-v4")
			},
		},
		{
			name:     "sync snippet",
			method:   http.MethodPost,
			path:     "/api/snippets/actions/sync",
			hasBody:  true,
			wantBody: `{"name":"routing/direct-v4"}`,
			status:   http.StatusAccepted,
			respBody: "",
			call: func(c *Client, ctx context.Context) (any, error) {
				return nil, c.SyncSnippet(ctx, "routing/direct-v4")
			},
		},
		{
			name:       "create host minimal",
			method:     http.MethodPost,
			path:       "/api/hosts",
			hasBody:    true,
			wantBody:   `{"remark":"temporary-host","address":"192.0.2.1","port":443,"inbound":{"configProfileUuid":"` + profileUUID + `","configProfileInboundUuid":"` + inboundUUID + `"}}`,
			status:     http.StatusCreated,
			respBody:   hostEnvelope,
			inputValue: createHostMin,
			call: func(c *Client, ctx context.Context) (any, error) {
				return c.CreateHost(ctx, createHostMin)
			},
			verify: func(t *testing.T, v any) {
				assertHostMemory(t, v.(Host), secret)
			},
		},
		{
			name:       "create host with optional fields",
			method:     http.MethodPost,
			path:       "/api/hosts",
			hasBody:    true,
			wantBody:   `{"remark":"temporary-host","address":"192.0.2.1","port":443,"path":"","sni":"edge.example.test","host":"edge.example.test","fingerprint":"firefox","inbound":{"configProfileUuid":"` + profileUUID + `","configProfileInboundUuid":"` + inboundUUID + `"},"overrideSniFromAddress":false,"keepSniBlank":true,"shuffleHost":false}`,
			status:     http.StatusCreated,
			respBody:   hostEnvelope,
			inputValue: createHostOpts,
			call: func(c *Client, ctx context.Context) (any, error) {
				return c.CreateHost(ctx, createHostOpts)
			},
			verify: func(t *testing.T, v any) {
				assertHostMemory(t, v.(Host), secret)
			},
		},
		{
			name:       "update host partial",
			method:     http.MethodPatch,
			path:       "/api/hosts",
			hasBody:    true,
			wantBody:   `{"uuid":"` + hostUUID + `","port":8443}`,
			status:     http.StatusOK,
			respBody:   hostEnvelope,
			inputValue: updateHostPartial,
			call:       func(c *Client, ctx context.Context) (any, error) { return c.UpdateHost(ctx, updateHostPartial) },
			verify: func(t *testing.T, v any) {
				assertHostMemory(t, v.(Host), secret)
			},
		},
		{
			name:       "update host explicit zero optionals and inbound",
			method:     http.MethodPatch,
			path:       "/api/hosts",
			hasBody:    true,
			wantBody:   `{"uuid":"` + hostUUID + `","remark":"temporary-host","address":"192.0.2.2","port":8443,"path":"","inbound":{"configProfileUuid":"` + profileUUID + `","configProfileInboundUuid":"` + inboundUUID + `"},"overrideSniFromAddress":false,"keepSniBlank":false,"shuffleHost":true}`,
			status:     http.StatusOK,
			respBody:   hostEnvelope,
			inputValue: updateHostOpts,
			call:       func(c *Client, ctx context.Context) (any, error) { return c.UpdateHost(ctx, updateHostOpts) },
			verify: func(t *testing.T, v any) {
				assertHostMemory(t, v.(Host), secret)
			},
		},
		{
			name:     "delete host",
			method:   http.MethodDelete,
			path:     "/api/hosts/" + hostUUID,
			hasBody:  false,
			status:   http.StatusNoContent,
			respBody: "",
			call:     func(c *Client, ctx context.Context) (any, error) { return nil, c.DeleteHost(ctx, hostUUID) },
		},
	}
}

func TestWriteMethodsRequestsEnvelopesAndRedaction(t *testing.T) {
	token := rand.Text()
	secret := rand.Text()
	for _, tc := range writeCases(t, secret) {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int32
			c, _ := writeServer(t, token, tc.method, tc.path, tc.hasBody, func(w http.ResponseWriter, r *http.Request, body []byte) {
				hits.Add(1)
				if tc.hasBody && string(body) != tc.wantBody {
					t.Errorf("request body = %s, want %s", string(body), tc.wantBody)
				}
				if tc.respBody == "" {
					w.WriteHeader(tc.status)
					return
				}
				writeJSON(w, tc.status, tc.respBody)
			})
			if tc.inputValue != nil {
				formatted := fmt.Sprintf("%v %+v %#v", tc.inputValue, tc.inputValue, tc.inputValue)
				for _, marker := range []string{secret, "temporary-profile", "temporary-host", "routing/direct-v4", "192.0.2.1"} {
					if strings.Contains(formatted, marker) {
						t.Errorf("input formatting leaks %q", marker)
					}
				}
				switch v := tc.inputValue.(type) {
				case CreateConfigProfileInput:
					assertSecretInputJSONRedacted(t, v, &v, secret, "temporary-profile")
				case UpdateConfigProfileInput:
					assertSecretInputJSONRedacted(t, v, &v, secret, "temporary-profile", v.UUID)
				case WriteSnippetInput:
					assertSecretInputJSONRedacted(t, v, &v, secret, "routing/direct-v4")
				}
			}
			got, err := tc.call(c, context.Background())
			if err != nil {
				t.Fatalf("write failed: %v", err)
			}
			if hits.Load() != 1 {
				t.Fatalf("hits = %d, want 1", hits.Load())
			}
			if got != nil {
				assertPlanningRedacted(t, got, token, secret, "temporary-profile", "temporary-host", "routing/direct-v4")
			}
			if tc.verify != nil {
				tc.verify(t, got)
			}
		})
	}
}

func assertSecretInputJSONRedacted(t *testing.T, val, ptrVal any, markers ...string) {
	t.Helper()
	for _, candidate := range []any{val, ptrVal} {
		encoded, err := json.Marshal(candidate)
		if err != nil {
			t.Fatalf("encoding redacted input: %v", err)
		}
		if string(encoded) != `{"redacted":true}` {
			t.Errorf("input JSON = %s, want {\"redacted\":true}", string(encoded))
		}
		for _, marker := range markers {
			if marker != "" && strings.Contains(string(encoded), marker) {
				t.Errorf("input JSON leaks %q", marker)
			}
		}
	}
}

func TestWriteValidationRejectsBeforeIO(t *testing.T) {
	var hits atomic.Int32
	token := rand.Text()
	c, _ := writeServer(t, token, http.MethodPost, "/unused", true, func(w http.ResponseWriter, r *http.Request, body []byte) {
		hits.Add(1)
	})
	validID := planningUUID(t)
	validCfg := json.RawMessage(`{"inbounds":[]}`)
	validSnip := json.RawMessage(`[{"tag":"direct"}]`)
	validRef := InboundRef{ConfigProfileUUID: validID, ConfigProfileInboundUUID: planningUUID(t)}

	for _, tc := range writeCases(t, rand.Text()) {
		if _, err := tc.call(c, nil); !errors.Is(err, ErrInvalidArgument) || errors.Is(err, ErrAmbiguousWrite) {
			t.Errorf("%s nil context: %v", tc.name, err)
		}
	}

	for _, badUUID := range []string{
		"", "not-a-uuid", "../hosts", "00000000-0000-4000-8000-00000000000g",
		"00000000-0000-0000-8000-000000000001", validID + "?x=1",
	} {
		if _, err := c.UpdateConfigProfile(context.Background(), UpdateConfigProfileInput{UUID: badUUID, Name: ptr("valid-name")}); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("UpdateConfigProfile bad uuid %q: %v", badUUID, err)
		}
		if err := c.DeleteConfigProfile(context.Background(), badUUID); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("DeleteConfigProfile bad uuid %q: %v", badUUID, err)
		}
		if _, err := c.UpdateHost(context.Background(), UpdateHostInput{UUID: badUUID, Port: ptr(443)}); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("UpdateHost bad uuid %q: %v", badUUID, err)
		}
		if err := c.DeleteHost(context.Background(), badUUID); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("DeleteHost bad uuid %q: %v", badUUID, err)
		}
		if _, err := c.CreateHost(context.Background(), WriteHost{
			HostName: "ok", Address: "192.0.2.1", Port: 443,
			Inbound: InboundRef{ConfigProfileUUID: badUUID, ConfigProfileInboundUUID: validID},
		}); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("CreateHost bad profile uuid %q: %v", badUUID, err)
		}
		if _, err := c.CreateHost(context.Background(), WriteHost{
			HostName: "ok", Address: "192.0.2.1", Port: 443,
			Inbound: InboundRef{ConfigProfileUUID: validID, ConfigProfileInboundUUID: badUUID},
		}); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("CreateHost bad inbound uuid %q: %v", badUUID, err)
		}
	}

	for _, badName := range []string{"", "a", "   ", strings.Repeat("a", 31), "bad/name", "bad@name", "bad\nname"} {
		if _, err := c.CreateConfigProfile(context.Background(), CreateConfigProfileInput{Name: badName, Config: validCfg}); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("CreateConfigProfile bad name %q: %v", badName, err)
		}
		if _, err := c.UpdateConfigProfile(context.Background(), UpdateConfigProfileInput{UUID: validID, Name: ptr(badName)}); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("UpdateConfigProfile bad name %q: %v", badName, err)
		}
	}

	for _, badCfg := range []json.RawMessage{
		nil, json.RawMessage(""), json.RawMessage("   "), json.RawMessage("null"),
		json.RawMessage("[]"), json.RawMessage("{}"), json.RawMessage(`{"a":1,"a":2}`),
		json.RawMessage(`{"a":1}{}`), json.RawMessage(`{"a":`), json.RawMessage{0xff},
	} {
		if _, err := c.CreateConfigProfile(context.Background(), CreateConfigProfileInput{Name: "valid-name", Config: badCfg}); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("CreateConfigProfile bad config %q: %v", string(badCfg), err)
		}
		if badCfg != nil {
			if _, err := c.UpdateConfigProfile(context.Background(), UpdateConfigProfileInput{UUID: validID, Config: badCfg}); !errors.Is(err, ErrInvalidArgument) {
				t.Errorf("UpdateConfigProfile bad config %q: %v", string(badCfg), err)
			}
		}
	}
	if _, err := c.UpdateConfigProfile(context.Background(), UpdateConfigProfileInput{UUID: validID}); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("UpdateConfigProfile empty patch: %v", err)
	}

	for _, badSnipName := range []string{
		"", "a", "  ", strings.Repeat("a", 256), "/leading", "trailing/",
		"a//b", "a/  /b", "../escape", "bad@name", "bad\nname",
	} {
		if _, err := c.CreateSnippet(context.Background(), WriteSnippetInput{Name: badSnipName, Snippet: validSnip}); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("CreateSnippet bad name %q: %v", badSnipName, err)
		}
		if _, err := c.UpdateSnippet(context.Background(), WriteSnippetInput{Name: badSnipName, Snippet: validSnip}); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("UpdateSnippet bad name %q: %v", badSnipName, err)
		}
		if err := c.DeleteSnippet(context.Background(), badSnipName); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("DeleteSnippet bad name %q: %v", badSnipName, err)
		}
		if err := c.SyncSnippet(context.Background(), badSnipName); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("SyncSnippet bad name %q: %v", badSnipName, err)
		}
	}

	for _, badSnip := range []json.RawMessage{
		nil, json.RawMessage(""), json.RawMessage("null"), json.RawMessage("{}"),
		json.RawMessage("[]"), json.RawMessage("[null]"), json.RawMessage("[{}]"),
		json.RawMessage(`["scalar"]`), json.RawMessage(`[{"a":1,"a":2}]`),
		json.RawMessage(`[{"a":1}][]`), json.RawMessage{0xff},
	} {
		if _, err := c.CreateSnippet(context.Background(), WriteSnippetInput{Name: "valid-snippet", Snippet: badSnip}); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("CreateSnippet bad snippet %q: %v", string(badSnip), err)
		}
		if _, err := c.UpdateSnippet(context.Background(), WriteSnippetInput{Name: "valid-snippet", Snippet: badSnip}); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("UpdateSnippet bad snippet %q: %v", string(badSnip), err)
		}
	}

	for _, badHost := range []WriteHost{
		{HostName: "", Address: "192.0.2.1", Port: 443, Inbound: validRef},
		{HostName: "   ", Address: "192.0.2.1", Port: 443, Inbound: validRef},
		{HostName: strings.Repeat("x", 101), Address: "192.0.2.1", Port: 443, Inbound: validRef},
		{HostName: "bad\nremark", Address: "192.0.2.1", Port: 443, Inbound: validRef},
		{HostName: "ok", Address: "", Port: 443, Inbound: validRef},
		{HostName: "ok", Address: "192.0.2.1 bad", Port: 443, Inbound: validRef},
		{HostName: "ok", Address: "192.0.2.1", Port: 0, Inbound: validRef},
		{HostName: "ok", Address: "192.0.2.1", Port: -1, Inbound: validRef},
		{HostName: "ok", Address: "192.0.2.1", Port: 65536, Inbound: validRef},
		{HostName: "ok", Address: "192.0.2.1", Port: 443, Path: ptr("/bad\npath"), Inbound: validRef},
		{HostName: "ok", Address: "192.0.2.1", Port: 443, SNI: ptr(string([]byte{0xff})), Inbound: validRef},
	} {
		if _, err := c.CreateHost(context.Background(), badHost); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("CreateHost invalid input: %v", err)
		}
	}
	for _, badUpdate := range []UpdateHostInput{
		{UUID: validID},
		{UUID: validID, HostName: ptr("")},
		{UUID: validID, Address: ptr("bad addr")},
		{UUID: validID, Port: ptr(0)},
		{UUID: validID, Port: ptr(70000)},
		{UUID: validID, Inbound: &InboundRef{ConfigProfileUUID: validID}},
		{UUID: validID, Fingerprint: ptr("bad\x00fp")},
	} {
		if _, err := c.UpdateHost(context.Background(), badUpdate); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("UpdateHost invalid input: %v", err)
		}
	}

	u, _ := url.Parse("https://panel.example.test")
	if _, err := New(u, token, &http.Client{}, WithMaxRequestBytes(0)); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("WithMaxRequestBytes(0): %v", err)
	}
	capped, _ := writeServer(t, token, http.MethodPost, "/api/config-profiles", true, func(w http.ResponseWriter, r *http.Request, body []byte) {
		hits.Add(1)
	}, WithMaxRequestBytes(64))
	bigCfg := json.RawMessage(`{"pad":"` + strings.Repeat("x", 128) + `"}`)
	if _, err := capped.CreateConfigProfile(context.Background(), CreateConfigProfileInput{Name: "valid-name", Config: bigCfg}); !errors.Is(err, ErrRequestTooLarge) || errors.Is(err, ErrAmbiguousWrite) {
		t.Errorf("oversized request: %v", err)
	}

	if hits.Load() != 0 {
		t.Fatalf("invalid inputs caused %d network requests", hits.Load())
	}
}

func TestWriteMalformedResponsesAndIdentityMismatch(t *testing.T) {
	token := rand.Text()
	secret := rand.Text()

	for _, tc := range writeCases(t, secret) {
		t.Run(tc.name, func(t *testing.T) {
			if tc.respBody == "" {
				// 202/204 must treat wrong 2xx status as ambiguous (no replay) and reject non-empty body.
				var hits atomic.Int32
				c, _ := writeServer(t, token, tc.method, tc.path, tc.hasBody, func(w http.ResponseWriter, r *http.Request, body []byte) {
					hits.Add(1)
					writeJSON(w, http.StatusOK, `{"response":{}}`)
				})
				_, err := tc.call(c, context.Background())
				var unknown *WriteOutcomeUnknownError
				if !errors.Is(err, ErrAmbiguousWrite) || !errors.As(err, &unknown) || !errors.Is(err, ErrUnexpectedStatus) {
					t.Fatalf("unexpected 2xx: %v", err)
				}
				if hits.Load() != 1 {
					t.Fatalf("unexpected 2xx hits = %d, want 1", hits.Load())
				}
				assertPlanningRedacted(t, err, token, secret)
				if tc.status == http.StatusAccepted {
					c, _ = writeServer(t, token, tc.method, tc.path, tc.hasBody, func(w http.ResponseWriter, r *http.Request, body []byte) {
						w.WriteHeader(http.StatusAccepted)
						_, _ = io.WriteString(w, secret)
					})
					_, err := tc.call(c, context.Background())
					if !errors.Is(err, ErrMalformedResponse) || errors.Is(err, ErrAmbiguousWrite) {
						t.Fatalf("non-empty 202 body: %v", err)
					}
					assertPlanningRedacted(t, err, token, secret)
				} else {
					u, _ := url.Parse("https://panel.example.test")
					rt := writeStatusTransport{status: http.StatusNoContent, body: secret}
					customClient, err := New(u, token, &http.Client{Transport: rt})
					if err != nil {
						t.Fatal(err)
					}
					_, err = tc.call(customClient, context.Background())
					if !errors.Is(err, ErrMalformedResponse) || errors.Is(err, ErrAmbiguousWrite) {
						t.Fatalf("non-empty 204 body: %v", err)
					}
					assertPlanningRedacted(t, err, token, secret)
				}
				return
			}

			// Wrong 2xx status on a mutating request is ambiguous and must not replay.
			wrongStatus := http.StatusOK
			if tc.status == http.StatusOK {
				wrongStatus = http.StatusCreated
			}
			var hits atomic.Int32
			c, _ := writeServer(t, token, tc.method, tc.path, tc.hasBody, func(w http.ResponseWriter, r *http.Request, body []byte) {
				hits.Add(1)
				writeJSON(w, wrongStatus, tc.respBody)
			})
			_, err := tc.call(c, context.Background())
			var unknown *WriteOutcomeUnknownError
			if !errors.Is(err, ErrAmbiguousWrite) || !errors.As(err, &unknown) || !errors.Is(err, ErrUnexpectedStatus) {
				t.Fatalf("wrong 2xx status: %v", err)
			}
			if hits.Load() != 1 {
				t.Fatalf("wrong 2xx status hits = %d, want 1", hits.Load())
			}
			assertPlanningRedacted(t, err, token, secret)

			// Wrong content type.
			c, _ = writeServer(t, token, tc.method, tc.path, tc.hasBody, func(w http.ResponseWriter, r *http.Request, body []byte) {
				w.Header().Set("Content-Type", "text/html; detail="+secret)
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, secret)
			})
			_, err = tc.call(c, context.Background())
			if !errors.Is(err, ErrMalformedResponse) || errors.Is(err, ErrAmbiguousWrite) {
				t.Fatalf("wrong content type: %v", err)
			}
			assertPlanningRedacted(t, err, token, secret)

			// Malformed JSON and duplicate keys.
			var body atomic.Value
			body.Store("")
			c, _ = writeServer(t, token, tc.method, tc.path, tc.hasBody, func(w http.ResponseWriter, r *http.Request, reqBody []byte) {
				writeJSON(w, tc.status, body.Load().(string))
			})
			for name, malformedBody := range map[string]string{
				"empty":              "",
				"invalid":            secret,
				"truncated":          tc.respBody[:len(tc.respBody)-1],
				"trailing":           tc.respBody + `{}`,
				"null response":      `{"response":null}`,
				"duplicate key":      strings.TrimSuffix(tc.respBody, "}") + `,"response":{}}`,
				"escaped duplicate":  strings.TrimSuffix(tc.respBody, "}") + `,"respon\u0073e":{}}`,
				"nested dup unknown": strings.TrimSuffix(tc.respBody, "}") + `,"extra":{"k":1,"k":2}}`,
			} {
				t.Run(name, func(t *testing.T) {
					body.Store(malformedBody)
					_, err := tc.call(c, context.Background())
					if !errors.Is(err, ErrMalformedResponse) || errors.Is(err, ErrAmbiguousWrite) {
						t.Fatalf("%s: %v", name, err)
					}
					assertPlanningRedacted(t, err, token, secret)
				})
			}
		})
	}

	// Identity mismatch checks.
	profileUUID, inboundUUID, hostUUID := planningUUID(t), planningUUID(t), planningUUID(t)
	otherUUID := planningUUID(t)

	t.Run("create profile name mismatch", func(t *testing.T) {
		p := planningProfile(profileUUID, inboundUUID, secret)
		p["name"] = "other-profile"
		c, _ := writeServer(t, token, http.MethodPost, "/api/config-profiles", true, func(w http.ResponseWriter, r *http.Request, body []byte) {
			writeJSON(w, http.StatusCreated, planningJSON(t, map[string]any{"response": p}))
		})
		if _, err := c.CreateConfigProfile(context.Background(), CreateConfigProfileInput{
			Name: "temporary-profile", Config: json.RawMessage(`{"inbounds":[]}`),
		}); !errors.Is(err, ErrMalformedResponse) || errors.Is(err, ErrAmbiguousWrite) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("update profile uuid mismatch", func(t *testing.T) {
		p := planningProfile(otherUUID, inboundUUID, secret)
		c, _ := writeServer(t, token, http.MethodPatch, "/api/config-profiles", true, func(w http.ResponseWriter, r *http.Request, body []byte) {
			writeJSON(w, http.StatusOK, planningJSON(t, map[string]any{"response": p}))
		})
		if _, err := c.UpdateConfigProfile(context.Background(), UpdateConfigProfileInput{
			UUID: profileUUID, Name: ptr("temporary-profile"),
		}); !errors.Is(err, ErrMalformedResponse) || errors.Is(err, ErrAmbiguousWrite) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("update profile name mismatch", func(t *testing.T) {
		p := planningProfile(profileUUID, inboundUUID, secret)
		p["name"] = "wrong-name"
		c, _ := writeServer(t, token, http.MethodPatch, "/api/config-profiles", true, func(w http.ResponseWriter, r *http.Request, body []byte) {
			writeJSON(w, http.StatusOK, planningJSON(t, map[string]any{"response": p}))
		})
		if _, err := c.UpdateConfigProfile(context.Background(), UpdateConfigProfileInput{
			UUID: profileUUID, Name: ptr("temporary-profile"),
		}); !errors.Is(err, ErrMalformedResponse) || errors.Is(err, ErrAmbiguousWrite) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("snippet missing requested name or bad total or duplicate", func(t *testing.T) {
		other := map[string]any{"name": "other", "snippet": []any{map[string]any{"k": "v"}}}
		req := map[string]any{"name": "wanted", "snippet": []any{map[string]any{"k": "v"}}}
		for _, resp := range []string{
			planningJSON(t, map[string]any{"response": map[string]any{"total": 1, "snippets": []any{other}}}),
			planningJSON(t, map[string]any{"response": map[string]any{"total": 2, "snippets": []any{req}}}),
			planningJSON(t, map[string]any{"response": map[string]any{"total": 2, "snippets": []any{req, req}}}),
		} {
			c, _ := writeServer(t, token, http.MethodPost, "/api/snippets", true, func(w http.ResponseWriter, r *http.Request, body []byte) {
				writeJSON(w, http.StatusCreated, resp)
			})
			if _, err := c.CreateSnippet(context.Background(), WriteSnippetInput{
				Name: "wanted", Snippet: json.RawMessage(`[{"k":"v"}]`),
			}); !errors.Is(err, ErrMalformedResponse) || errors.Is(err, ErrAmbiguousWrite) {
				t.Fatalf("err = %v", err)
			}
		}
	})

	t.Run("create and update host identity mismatch", func(t *testing.T) {
		hWrongRemark := planningHost(hostUUID, profileUUID, inboundUUID, secret)
		hWrongRemark["remark"] = "other-host"
		c, _ := writeServer(t, token, http.MethodPost, "/api/hosts", true, func(w http.ResponseWriter, r *http.Request, body []byte) {
			writeJSON(w, http.StatusCreated, planningJSON(t, map[string]any{"response": hWrongRemark}))
		})
		if _, err := c.CreateHost(context.Background(), WriteHost{
			HostName: "temporary-host", Address: "192.0.2.1", Port: 443,
			Inbound: InboundRef{ConfigProfileUUID: profileUUID, ConfigProfileInboundUUID: inboundUUID},
		}); !errors.Is(err, ErrMalformedResponse) {
			t.Fatalf("create host remark mismatch: %v", err)
		}

		hWrongInbound := planningHost(hostUUID, otherUUID, inboundUUID, secret)
		c, _ = writeServer(t, token, http.MethodPost, "/api/hosts", true, func(w http.ResponseWriter, r *http.Request, body []byte) {
			writeJSON(w, http.StatusCreated, planningJSON(t, map[string]any{"response": hWrongInbound}))
		})
		if _, err := c.CreateHost(context.Background(), WriteHost{
			HostName: "temporary-host", Address: "192.0.2.1", Port: 443,
			Inbound: InboundRef{ConfigProfileUUID: profileUUID, ConfigProfileInboundUUID: inboundUUID},
		}); !errors.Is(err, ErrMalformedResponse) {
			t.Fatalf("create host inbound mismatch: %v", err)
		}

		hWrongUUID := planningHost(otherUUID, profileUUID, inboundUUID, secret)
		c, _ = writeServer(t, token, http.MethodPatch, "/api/hosts", true, func(w http.ResponseWriter, r *http.Request, body []byte) {
			writeJSON(w, http.StatusOK, planningJSON(t, map[string]any{"response": hWrongUUID}))
		})
		if _, err := c.UpdateHost(context.Background(), UpdateHostInput{
			UUID: hostUUID, Port: ptr(8443),
		}); !errors.Is(err, ErrMalformedResponse) {
			t.Fatalf("update host uuid mismatch: %v", err)
		}
	})
}

func TestWriteHTTPFailuresAndResponseLimits(t *testing.T) {
	var redirectTargetHits atomic.Int32
	redirectTarget := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectTargetHits.Add(1)
		writeJSON(w, http.StatusOK, `{"response":{}}`)
	}))
	defer redirectTarget.Close()

	for _, tc := range writeCases(t, rand.Text()) {
		t.Run(tc.name, func(t *testing.T) {
			token := rand.Text()
			secret := rand.Text()
			var status atomic.Int32
			var hits atomic.Int32
			c, _ := writeServer(t, token, tc.method, tc.path, tc.hasBody, func(w http.ResponseWriter, r *http.Request, body []byte) {
				hits.Add(1)
				s := int(status.Load())
				if s >= 300 && s <= 399 {
					w.Header().Set("Location", redirectTarget.URL+"/%zz?token="+token+"&secret="+secret)
					w.WriteHeader(s)
					return
				}
				if s == http.StatusTooManyRequests {
					w.Header().Set("Retry-After", "9")
				}
				writeJSON(w, s, `{"errorCode":"A063","message":"`+secret+`"}`)
			})

			for _, failure := range []struct {
				status    int
				sentinel  error
				ambiguous bool
			}{
				{301, ErrRedirect, false},
				{302, ErrRedirect, false},
				{307, ErrRedirect, false},
				{308, ErrRedirect, false},
				{400, ErrBadRequest, false},
				{401, ErrUnauthorized, false},
				{403, ErrForbidden, false},
				{404, ErrNotFound, false},
				{409, ErrUnexpectedStatus, false},
				{429, ErrRateLimited, false},
				{500, ErrServer, true},
				{503, ErrServer, true},
			} {
				hits.Store(0)
				status.Store(int32(failure.status))
				_, err := tc.call(c, context.Background())
				if hits.Load() != 1 {
					t.Fatalf("status %d: hits = %d, want 1 (no retries)", failure.status, hits.Load())
				}
				var apiErr *APIError
				if !errors.Is(err, failure.sentinel) || !errors.As(err, &apiErr) || apiErr.StatusCode != failure.status {
					t.Fatalf("status %d: err = %v", failure.status, err)
				}
				if failure.status == 429 && apiErr.RetryAfter != 9*time.Second {
					t.Fatalf("429 RetryAfter = %v, want 9s", apiErr.RetryAfter)
				}
				if errors.Is(err, ErrAmbiguousWrite) != failure.ambiguous {
					t.Fatalf("status %d: ErrAmbiguousWrite = %t, want %t (%v)", failure.status, errors.Is(err, ErrAmbiguousWrite), failure.ambiguous, err)
				}
				var unknown *WriteOutcomeUnknownError
				if errors.As(err, &unknown) != failure.ambiguous {
					t.Fatalf("status %d: WriteOutcomeUnknownError = %t, want %t", failure.status, errors.As(err, &unknown), failure.ambiguous)
				}
				assertPlanningRedacted(t, err, token, secret, redirectTarget.URL, "%zz")
			}

			if tc.respBody != "" {
				for _, chunked := range []bool{false, true} {
					large := tc.respBody + strings.Repeat(" ", 4096)
					c, _ := writeServer(t, token, tc.method, tc.path, tc.hasBody, func(w http.ResponseWriter, r *http.Request, body []byte) {
						w.Header().Set("Content-Type", "application/json")
						if !chunked {
							w.Header().Set("Content-Length", strconv.Itoa(len(large)))
						}
						w.WriteHeader(tc.status)
						for offset := 0; offset < len(large); offset += 256 {
							if _, err := io.WriteString(w, large[offset:min(offset+256, len(large))]); err != nil {
								return
							}
							if chunked {
								w.(http.Flusher).Flush()
							}
						}
					}, WithMaxResponseBytes(1024))
					if _, err := tc.call(c, context.Background()); !errors.Is(err, ErrResponseTooLarge) || errors.Is(err, ErrAmbiguousWrite) {
						t.Fatalf("oversized response chunked=%t: %v", chunked, err)
					}
				}
			}
		})
	}

	if redirectTargetHits.Load() != 0 {
		t.Fatalf("redirect target received %d requests", redirectTargetHits.Load())
	}
}

func TestWriteCancellationTimeoutsAndTransportFailures(t *testing.T) {
	token := rand.Text()
	secret := rand.Text()

	// Pre-canceled and pre-expired contexts must fail before I/O and are NOT ambiguous.
	t.Run("pre-cancelled and pre-expired are not ambiguous", func(t *testing.T) {
		var hits atomic.Int32
		c, _ := writeServer(t, token, http.MethodPost, "/unused", true, func(w http.ResponseWriter, r *http.Request, body []byte) {
			hits.Add(1)
		})
		for _, tc := range writeCases(t, secret) {
			canceled, stop := context.WithCancel(context.Background())
			stop()
			_, err := tc.call(c, canceled)
			if !errors.Is(err, context.Canceled) || errors.Is(err, ErrAmbiguousWrite) {
				t.Fatalf("%s pre-canceled: %v", tc.name, err)
			}
			expired, stop2 := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			stop2()
			_, err = tc.call(c, expired)
			if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrAmbiguousWrite) {
				t.Fatalf("%s pre-expired: %v", tc.name, err)
			}
		}
		if hits.Load() != 0 {
			t.Fatalf("pre-cancelled requests reached server %d times", hits.Load())
		}
	})

	// In-flight cancellation, deadline and client timeout are ambiguous.
	for _, tc := range writeCases(t, secret) {
		t.Run("in-flight "+tc.name, func(t *testing.T) {
			phases := []bool{false}
			if tc.respBody != "" {
				phases = append(phases, true)
			}
			for _, afterHeaders := range phases {
				started := make(chan struct{}, 3)
				var hits atomic.Int32
				c, _ := writeServer(t, token, tc.method, tc.path, tc.hasBody, func(w http.ResponseWriter, r *http.Request, body []byte) {
					hits.Add(1)
					if afterHeaders {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(tc.status)
						_, _ = io.WriteString(w, `{"response":`)
						w.(http.Flusher).Flush()
					}
					started <- struct{}{}
					<-r.Context().Done()
				})

				ctx, cancel := context.WithCancel(context.Background())
				go func() { <-started; cancel() }()
				_, err := tc.call(c, ctx)
				if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrAmbiguousWrite) {
					t.Fatalf("cancel afterHeaders=%t: %v", afterHeaders, err)
				}
				assertPlanningRedacted(t, err, token, secret)

				ctx, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
				_, err = tc.call(c, ctx)
				stop()
				if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrAmbiguousWrite) {
					t.Fatalf("deadline afterHeaders=%t: %v", afterHeaders, err)
				}
				assertPlanningRedacted(t, err, token, secret)

				c.http.Timeout = 100 * time.Millisecond
				_, err = tc.call(c, context.Background())
				var timeout net.Error
				if !errors.As(err, &timeout) || !timeout.Timeout() || !errors.Is(err, ErrAmbiguousWrite) {
					t.Fatalf("client timeout afterHeaders=%t: %v", afterHeaders, err)
				}
				assertPlanningRedacted(t, err, token, secret)

				if hits.Load() != 3 {
					t.Fatalf("expected 3 hits (no retries), got %d", hits.Load())
				}
			}
		})
	}

	// Transport and post-2xx body-read errors are ambiguous and secret-safe.
	t.Run("transport and read-after-2xx errors redact and mark ambiguous", func(t *testing.T) {
		cause := errors.New("https://private.example.test/?token=" + token + " body=" + secret)
		u, err := url.Parse("https://private.example.test")
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range writeCases(t, secret) {
			for _, transport := range []http.RoundTripper{
				planningFailTransport{cause: cause},
				writeFailBodyTransport{status: tc.status, cause: cause},
			} {
				c, err := New(u, token, &http.Client{Transport: transport})
				if err != nil {
					t.Fatalf("New: %v", err)
				}
				_, err = tc.call(c, context.Background())
				if !errors.Is(err, cause) || !errors.Is(err, ErrAmbiguousWrite) {
					t.Fatalf("%s: err = %v, want cause + ErrAmbiguousWrite", tc.name, err)
				}
				assertPlanningRedacted(t, err, token, secret, "private.example.test")
			}
		}
	})
}

type writeStatusTransport struct {
	status int
	body   string
}

func (t writeStatusTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode:    t.status,
		Header:        http.Header{},
		Body:          io.NopCloser(strings.NewReader(t.body)),
		ContentLength: int64(len(t.body)),
	}, nil
}

type writeFailBodyTransport struct {
	status int
	cause  error
}

func (t writeFailBodyTransport) RoundTrip(*http.Request) (*http.Response, error) {
	header := http.Header{}
	if t.status != http.StatusNoContent && t.status != http.StatusAccepted {
		header.Set("Content-Type", "application/json")
	}
	return &http.Response{
		StatusCode:    t.status,
		Header:        header,
		Body:          planningFailBody{cause: t.cause},
		ContentLength: -1,
	}, nil
}
