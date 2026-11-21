package fetch

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/juvenileslave/vpn/vpnctl/internal/upstream/candidate"
	"github.com/juvenileslave/vpn/vpnctl/internal/upstream/source"
)

const (
	testVLESS = "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp&security=tls#a"
	testSS    = "ss://YWVzLTI1Ni1nY206c2VjcmV0@example.com:8388#b"
	testWG    = `[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.0.0.2/24

[Peer]
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
Endpoint = 192.0.2.1:51820
AllowedIPs = 0.0.0.0/0
`
)

func loadDeclaration(t *testing.T, body string) *source.Declaration {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sources.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write declaration: %v", err)
	}
	decl, err := source.Load(path)
	if err != nil {
		t.Fatalf("source.Load: %v", err)
	}
	return decl
}

func subscriptionDeclaration(t *testing.T, rawURL string) *source.Declaration {
	t.Helper()
	return loadDeclaration(t, "schema: 1\nsources:\n  - id: sub-a\n    kind: subscription\n    slot: 1\n    interval: 5m\n    subscription_url: "+rawURL+"\n")
}

func TestFetchSubscriptionBase64(t *testing.T) {
	body := strings.Join([]string{testVLESS, testSS, "vmess://AAAA"}, "\n")
	encoded := base64.StdEncoding.EncodeToString([]byte(body))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(encoded))
	}))
	defer server.Close()

	decl := subscriptionDeclaration(t, server.URL+"/sub/SECRETTOKEN")
	f, err := New(Options{Client: server.Client()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cands, rejects, err := f.Fetch(context.Background(), decl.Sources[0], "upstream-slot-1")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(cands) != 2 || len(rejects) != 1 {
		t.Fatalf("candidates = %d, rejects = %d", len(cands), len(rejects))
	}
	if rejects[0].Scheme != "vmess" {
		t.Fatalf("reject = %+v", rejects[0])
	}
	for _, c := range cands {
		if !strings.Contains(string(c.Outbound), `"upstream-slot-1"`) {
			t.Fatalf("candidate tag missing: %s", c.Outbound)
		}
	}
	if cands[0].Scheme != candidate.SchemeVLESS || cands[1].Scheme != candidate.SchemeShadowsocks {
		t.Fatalf("schemes = %s %s", cands[0].Scheme, cands[1].Scheme)
	}
}

func TestFetchSubscriptionPlainText(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("# comment\n\n" + testVLESS + "\n"))
	}))
	defer server.Close()

	decl := subscriptionDeclaration(t, server.URL+"/sub")
	f, err := New(Options{Client: server.Client()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cands, rejects, err := f.Fetch(context.Background(), decl.Sources[0], "upstream-slot-1")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(cands) != 1 || len(rejects) != 0 {
		t.Fatalf("candidates = %d, rejects = %d", len(cands), len(rejects))
	}
}

func TestFetchSubscriptionRejectsBadResponses(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		want    error
	}{
		{
			name: "status",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			want: ErrResponse,
		},
		{
			name: "oversized",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(strings.Repeat("a", (1<<20)+1)))
			},
			want: ErrResponse,
		},
		{
			name: "redirect to http",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "http://127.0.0.1:1/sub", http.StatusFound)
			},
			want: ErrResponse,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewTLSServer(tt.handler)
			defer server.Close()
			decl := subscriptionDeclaration(t, server.URL+"/sub/SECRETTOKEN")
			f, err := New(Options{Client: server.Client()})
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			_, _, err = f.Fetch(context.Background(), decl.Sources[0], "upstream-slot-1")
			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
			if strings.Contains(err.Error(), "SECRETTOKEN") || strings.Contains(err.Error(), server.URL) {
				t.Fatalf("error leaked locator: %v", err)
			}
		})
	}
}

func TestFetchSubscriptionCanceledContext(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer server.Close()
	decl := subscriptionDeclaration(t, server.URL+"/sub")
	f, err := New(Options{Client: server.Client()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := f.Fetch(ctx, decl.Sources[0], "upstream-slot-1"); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestFetchWireguardFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wg.conf")
	if err := os.WriteFile(path, []byte(testWG), 0o600); err != nil {
		t.Fatalf("write wg: %v", err)
	}
	decl := loadDeclaration(t, "schema: 1\nsources:\n  - id: wg-a\n    kind: wireguard_file\n    slot: 2\n    interval: 5m\n    wireguard_path: "+path+"\n")
	f, err := New(Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cands, rejects, err := f.Fetch(context.Background(), decl.Sources[0], "upstream-slot-2")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(cands) != 1 || len(rejects) != 0 || cands[0].Scheme != candidate.SchemeWireguard {
		t.Fatalf("candidates = %+v rejects = %+v", cands, rejects)
	}
}

func TestFetchWireguardFileRejectsInsecureAndSymlink(t *testing.T) {
	dir := t.TempDir()
	insecure := filepath.Join(dir, "insecure.conf")
	if err := os.WriteFile(insecure, []byte(testWG), 0o600); err != nil {
		t.Fatalf("write wg: %v", err)
	}
	decl := loadDeclaration(t, "schema: 1\nsources:\n  - id: wg-a\n    kind: wireguard_file\n    slot: 2\n    interval: 5m\n    wireguard_path: "+insecure+"\n")
	if err := os.Chmod(insecure, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	link := filepath.Join(dir, "link.conf")
	if err := os.Symlink(insecure, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	f, err := New(Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, _, err := f.Fetch(context.Background(), decl.Sources[0], "upstream-slot-2"); !errors.Is(err, ErrWireguardFile) {
		t.Fatalf("insecure file error = %v, want ErrWireguardFile", err)
	}

	info, err := os.Lstat(link)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("link missing: %v", err)
	}
	// The declaration loader rejects symlinks; the fetcher is still expected to
	// reject one if a file is replaced after declaration validation.
	if _, err := f.fetchWireguard(link, "upstream-slot-2"); !errors.Is(err, ErrWireguardFile) {
		t.Fatalf("symlink error = %v, want ErrWireguardFile", err)
	}
}

func TestFetchInvalidInputs(t *testing.T) {
	if _, err := New(Options{}); err != nil {
		t.Fatalf("New: %v", err)
	}
	f, _ := New(Options{})
	if _, _, err := f.Fetch(context.Background(), source.Source{}, "upstream-slot-1"); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("zero source error = %v, want ErrInvalidOptions", err)
	}
	if _, _, err := f.Fetch(nil, source.Source{}, "upstream-slot-1"); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("nil context error = %v, want ErrInvalidOptions", err)
	}
}
