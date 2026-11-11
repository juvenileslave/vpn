package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

const testTimeout = 5 * time.Second

var loopback4 = netip.MustParseAddr("127.0.0.1")

// rawServer accepts TCP connections and runs handle for each one. Cleanup
// closes the listener and every connection and waits for all goroutines.
type rawServer struct {
	ln    net.Listener
	addr  netip.AddrPort
	peers chan netip.AddrPort
	done  chan struct{}

	mu    sync.Mutex
	conns []net.Conn
	wg    sync.WaitGroup
}

func newRawServer(t *testing.T, network, address string, handle func(net.Conn, <-chan struct{})) *rawServer {
	t.Helper()
	ln, err := net.Listen(network, address)
	if err != nil {
		t.Fatal(err)
	}
	return startRawServer(t, ln, handle)
}

func startRawServer(t *testing.T, ln net.Listener, handle func(net.Conn, <-chan struct{})) *rawServer {
	t.Helper()
	s := &rawServer{
		ln:    ln,
		addr:  addrPort(ln.Addr()),
		peers: make(chan netip.AddrPort, 16),
		done:  make(chan struct{}),
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conns = append(s.conns, c)
			s.mu.Unlock()
			select {
			case s.peers <- addrPort(c.RemoteAddr()):
			default:
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer c.Close()
				if handle != nil {
					handle(c, s.done)
				}
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		close(s.done)
		s.mu.Lock()
		for _, c := range s.conns {
			_ = c.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
	})
	return s
}

func (s *rawServer) peer(t *testing.T) netip.AddrPort {
	t.Helper()
	select {
	case p := <-s.peers:
		return p
	case <-time.After(testTimeout):
		t.Fatal("server saw no connection")
		return netip.AddrPort{}
	}
}

func target(addr netip.AddrPort, family Family) Target {
	return Target{Address: addr.Addr(), Port: addr.Port(), Family: family, Timeout: testTimeout}
}

// silent keeps the connection open without sending anything.
func silent(_ net.Conn, done <-chan struct{}) { <-done }

func reply(data string) func(net.Conn, <-chan struct{}) {
	return func(c net.Conn, done <-chan struct{}) {
		_, _ = c.Write([]byte(data))
	}
}

// replyAfterRequest reads the request header, sends data and, if hold is
// set, keeps the connection open.
func replyAfterRequest(data string, hold bool) func(net.Conn, <-chan struct{}) {
	return func(c net.Conn, done <-chan struct{}) {
		buf := make([]byte, 4096)
		var req []byte
		for !strings.Contains(string(req), "\r\n\r\n") {
			n, err := c.Read(buf)
			if err != nil {
				return
			}
			req = append(req, buf[:n]...)
		}
		_, _ = c.Write([]byte(data))
		if hold {
			<-done
		}
	}
}

type pki struct {
	ca   *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "probe test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &pki{ca: ca, key: key, pool: pool}
}

func (p *pki) leaf(t *testing.T, notAfter time.Time, names ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-2 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func newTLSServer(t *testing.T, cert tls.Certificate) *rawServer {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tl := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})
	return startRawServer(t, tl, func(c net.Conn, _ <-chan struct{}) {
		_ = c.(*tls.Conn).Handshake()
	})
}

func expect(t *testing.T, res Result, stages ...string) {
	t.Helper()
	var got []string
	for _, o := range res.Observations {
		got = append(got, string(o.Stage)+":"+string(o.Outcome))
		if o.End.Before(o.Start) {
			t.Errorf("%s: end %v before start %v", o.Stage, o.End, o.Start)
		}
	}
	if strings.Join(got, " ") != strings.Join(stages, " ") {
		t.Fatalf("observations = %v, want %v (last error: %q)", got, stages, res.Last().Error)
	}
}

func TestTCPConnectReportsSocketAddresses(t *testing.T) {
	srv := newRawServer(t, "tcp4", "127.0.0.1:0", nil)
	res := TCP(context.Background(), TCPRequest{target(srv.addr, IPv4)})
	expect(t, res, "tcp:success")
	o := res.Last()
	if !res.OK() || o.RemoteAddr != srv.addr {
		t.Fatalf("remote = %v, want %v", o.RemoteAddr, srv.addr)
	}
	if peer := srv.peer(t); o.LocalAddr != peer {
		t.Fatalf("local = %v, server saw peer %v", o.LocalAddr, peer)
	}
	if !o.LocalAddr.Addr().Is4() {
		t.Fatalf("local %v is not IPv4", o.LocalAddr)
	}
}

func TestTCPRefused(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := addrPort(ln.Addr())
	_ = ln.Close()
	res := TCP(context.Background(), TCPRequest{target(addr, IPv4)})
	expect(t, res, "tcp:refused")
	if o := res.Last(); o.LocalAddr.IsValid() || o.RemoteAddr.IsValid() {
		t.Fatalf("addresses reported without a connection: %+v", o)
	}
}

func TestTCPCanceledContext(t *testing.T) {
	srv := newRawServer(t, "tcp4", "127.0.0.1:0", nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	expect(t, TCP(ctx, TCPRequest{target(srv.addr, IPv4)}), "tcp:canceled")
}

func TestTCPSourceIPIsBound(t *testing.T) {
	srv := newRawServer(t, "tcp4", "127.0.0.1:0", nil)
	tg := target(srv.addr, IPv4)
	tg.SourceIP = loopback4
	res := TCP(context.Background(), TCPRequest{tg})
	expect(t, res, "tcp:success")
	if peer := srv.peer(t); peer.Addr() != tg.SourceIP || res.Last().LocalAddr != peer {
		t.Fatalf("server saw %v, probe reported %v, want source %v", peer, res.Last().LocalAddr, tg.SourceIP)
	}
}

// Binding a second loopback address proves the source is not just the
// kernel's default choice. 127.0.0.2 is routable on Linux loopback but is
// not assigned by default on macOS or BSD.
func TestTCPSourceIPAliasIsBound(t *testing.T) {
	alias := netip.MustParseAddr("127.0.0.2")
	probeLn, err := net.Listen("tcp4", "127.0.0.2:0")
	if err != nil {
		t.Skipf("loopback alias %v unavailable: net.Listen(\"tcp4\", \"127.0.0.2:0\") failed: %v", alias, err)
	}
	_ = probeLn.Close()

	srv := newRawServer(t, "tcp4", "127.0.0.1:0", nil)
	tg := target(srv.addr, IPv4)
	tg.SourceIP = alias
	res := TCP(context.Background(), TCPRequest{tg})
	expect(t, res, "tcp:success")
	if peer := srv.peer(t); peer.Addr() != alias || res.Last().LocalAddr != peer {
		t.Fatalf("server saw %v, probe reported %v, want source %v", peer, res.Last().LocalAddr, alias)
	}
}

func TestTCPSourceIPUnavailable(t *testing.T) {
	srv := newRawServer(t, "tcp4", "127.0.0.1:0", nil)
	tg := target(srv.addr, IPv4)
	tg.SourceIP = netip.MustParseAddr("192.0.2.1") // TEST-NET-1, not assigned locally
	expect(t, TCP(context.Background(), TCPRequest{tg}), "tcp:source_unavailable")
}

func ipv6Loopback(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: net.Listen(\"tcp6\", \"[::1]:0\") failed: %v", err)
	}
	return ln
}

func TestFamilySelectionIPv6(t *testing.T) {
	srv := startRawServer(t, ipv6Loopback(t), nil)
	res := TCP(context.Background(), TCPRequest{target(srv.addr, IPv6)})
	expect(t, res, "tcp:success")
	o := res.Last()
	if peer := srv.peer(t); o.LocalAddr != peer || !o.LocalAddr.Addr().Is6() || o.RemoteAddr != srv.addr {
		t.Fatalf("local %v remote %v, server saw %v", o.LocalAddr, o.RemoteAddr, peer)
	}
}

// A listener accepting both families must still be reached over IPv4 when
// IPv4 is requested.
func TestFamilySelectionIPv4OnAnyFamilyListener(t *testing.T) {
	srv := newRawServer(t, "tcp", ":0", nil)
	tg := target(netip.AddrPortFrom(loopback4, srv.addr.Port()), IPv4)
	res := TCP(context.Background(), TCPRequest{tg})
	expect(t, res, "tcp:success")
	if peer := srv.peer(t); peer.Addr().Unmap() != loopback4 || !res.Last().LocalAddr.Addr().Is4() {
		t.Fatalf("server saw %v, probe local %v", peer, res.Last().LocalAddr)
	}
}

func TestInvalidRequestsDoNotDial(t *testing.T) {
	v4 := Target{Address: loopback4, Port: 1, Family: IPv4, Timeout: time.Second}
	with := func(f func(*Target)) Target { tg := v4; f(&tg); return tg }
	cases := map[string]func() Result{
		"ipv6 address for ipv4": func() Result {
			return TCP(context.Background(), TCPRequest{with(func(t *Target) { t.Address = netip.MustParseAddr("::1") })})
		},
		"ipv4 address for ipv6": func() Result {
			return TCP(context.Background(), TCPRequest{with(func(t *Target) { t.Family = IPv6 })})
		},
		"mapped address for ipv6": func() Result {
			return TCP(context.Background(), TCPRequest{with(func(t *Target) {
				t.Family, t.Address = IPv6, netip.MustParseAddr("::ffff:127.0.0.1")
			})})
		},
		"source of other family": func() Result {
			return TCP(context.Background(), TCPRequest{with(func(t *Target) { t.SourceIP = netip.MustParseAddr("::1") })})
		},
		"unknown family": func() Result {
			return TCP(context.Background(), TCPRequest{with(func(t *Target) { t.Family = "any" })})
		},
		"zero port":    func() Result { return TCP(context.Background(), TCPRequest{with(func(t *Target) { t.Port = 0 })}) },
		"zero timeout": func() Result { return TCP(context.Background(), TCPRequest{with(func(t *Target) { t.Timeout = 0 })}) },
		"tls without server name": func() Result {
			return TLS(context.Background(), TLSRequest{Target: v4})
		},
		"ftp url": func() Result {
			return HTTP(context.Background(), HTTPRequest{Target: v4, URL: "ftp://probe.test/", MaxBytes: 1})
		},
		"userinfo": func() Result {
			return HTTP(context.Background(), HTTPRequest{Target: v4, URL: "http://u:p@probe.test/", MaxBytes: 1})
		},
		"no byte limit": func() Result {
			return HTTP(context.Background(), HTTPRequest{Target: v4, URL: "http://probe.test/"})
		},
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			expect(t, run(), "request:invalid_request")
		})
	}
}

func TestTLSTrusted(t *testing.T) {
	p := newPKI(t)
	srv := newTLSServer(t, p.leaf(t, time.Now().Add(time.Hour), "probe.test"))
	res := TLS(context.Background(), TLSRequest{Target: target(srv.addr, IPv4), ServerName: "probe.test", RootCAs: p.pool})
	expect(t, res, "tcp:success", "tls:success")
	o := res.Last()
	if o.TLSVersion != tls.VersionTLS13 || o.RemoteAddr != srv.addr || o.LocalAddr != srv.peer(t) {
		t.Fatalf("unexpected observation %+v", o)
	}
}

func TestTLSVerificationFailures(t *testing.T) {
	p := newPKI(t)
	valid := newTLSServer(t, p.leaf(t, time.Now().Add(time.Hour), "probe.test"))
	expired := newTLSServer(t, p.leaf(t, time.Now().Add(-time.Hour), "probe.test"))
	cases := []struct {
		name       string
		srv        *rawServer
		serverName string
		roots      *x509.CertPool
		want       string
	}{
		{"untrusted CA", valid, "probe.test", newPKI(t).pool, "tls:certificate_untrusted"},
		{"hostname mismatch", valid, "other.test", p.pool, "tls:hostname_mismatch"},
		{"expired", expired, "probe.test", p.pool, "tls:certificate_invalid"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := TLS(context.Background(), TLSRequest{Target: target(c.srv.addr, IPv4), ServerName: c.serverName, RootCAs: c.roots})
			expect(t, res, "tcp:success", c.want)
		})
	}

	// With system roots the platform verifier decides: Go's verifier
	// reports an unknown authority, macOS may report an untyped rejection.
	t.Run("system roots", func(t *testing.T) {
		res := TLS(context.Background(), TLSRequest{Target: target(valid.addr, IPv4), ServerName: "probe.test"})
		if o := res.Last(); len(res.Observations) != 2 || o.Stage != StageTLS ||
			(o.Outcome != OutcomeCertificateUntrusted && o.Outcome != OutcomeCertificateInvalid) {
			t.Fatalf("observations = %+v, want tls certificate rejection", res.Observations)
		}
	})
}

func TestClassifyTLSPlatformVerifierError(t *testing.T) {
	ctx := context.Background()
	// Shape of the macOS verifier result for an unlisted Security.framework
	// code, as wrapped by crypto/tls.
	platform := &tls.CertificateVerificationError{Err: errors.New("x509: “probe.test” certificate is not trusted")}
	if got := classifyTLS(ctx, fmt.Errorf("handshake: %w", platform)); got != OutcomeCertificateInvalid {
		t.Fatalf("platform verifier rejection = %s, want %s", got, OutcomeCertificateInvalid)
	}
	if got := classifyTLS(ctx, errors.New("tls: first record does not look like a TLS handshake")); got != OutcomeHandshakeFailed {
		t.Fatalf("non-certificate failure = %s, want %s", got, OutcomeHandshakeFailed)
	}
}

func TestTLSHandshakeFailedOnNonTLSPeer(t *testing.T) {
	srv := newRawServer(t, "tcp4", "127.0.0.1:0", reply("SSH-2.0-not-tls\r\n"))
	res := TLS(context.Background(), TLSRequest{Target: target(srv.addr, IPv4), ServerName: "probe.test"})
	expect(t, res, "tcp:success", "tls:handshake_failed")
}

func TestTLSTimeoutAndCancellation(t *testing.T) {
	srv := newRawServer(t, "tcp4", "127.0.0.1:0", silent)

	tg := target(srv.addr, IPv4)
	tg.Timeout = 200 * time.Millisecond
	res := TLS(context.Background(), TLSRequest{Target: tg, ServerName: "probe.test"})
	expect(t, res, "tcp:success", "tls:timeout")
	if d := res.Last().Duration(); d < 100*time.Millisecond || d > 3*time.Second {
		t.Fatalf("timeout after %v", d)
	}

	ctx, cancel := context.WithCancel(context.Background())
	timer := time.AfterFunc(100*time.Millisecond, cancel)
	defer timer.Stop()
	res = TLS(ctx, TLSRequest{Target: target(srv.addr, IPv4), ServerName: "probe.test"})
	expect(t, res, "tcp:success", "tls:canceled")
}

func TestHTTPBodyWithinAndBeyondLimit(t *testing.T) {
	var gotHost, gotPath string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotHost, gotPath = r.Host, r.URL.Path
		mu.Unlock()
		size := 1000
		if r.URL.Path == "/big" {
			size = 10000
		}
		_, _ = w.Write([]byte(strings.Repeat("x", size)))
	}))
	t.Cleanup(srv.Close)
	addr := addrPort(srv.Listener.Addr())
	// An ambient proxy must not be used.
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")

	res := HTTP(context.Background(), HTTPRequest{Target: target(addr, IPv4), URL: "http://probe.test/small", MaxBytes: 4096})
	expect(t, res, "tcp:success", "http:success")
	o := res.Last()
	if o.StatusCode != 200 || o.BytesRead != 1000 || o.LimitReached || o.HeaderReceived.IsZero() {
		t.Fatalf("unexpected observation %+v", o)
	}
	mu.Lock()
	if gotHost != "probe.test" || gotPath != "/small" {
		t.Fatalf("server saw host %q path %q", gotHost, gotPath)
	}
	mu.Unlock()

	res = HTTP(context.Background(), HTTPRequest{Target: target(addr, IPv4), URL: "http://probe.test/big", MaxBytes: 4096})
	expect(t, res, "tcp:success", "http:success")
	if o := res.Last(); o.BytesRead != 4096 || !o.LimitReached {
		t.Fatalf("unexpected observation %+v", o)
	}
}

func TestHTTPSTrustedStreamsExactLimit(t *testing.T) {
	p := newPKI(t)
	const size = 1 << 20
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(size))
		chunk := make([]byte, 32<<10)
		for range size / len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{p.leaf(t, time.Now().Add(time.Hour), "probe.test")}}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	res := HTTP(context.Background(), HTTPRequest{
		Target: target(addrPort(srv.Listener.Addr()), IPv4), URL: "https://probe.test/1m", RootCAs: p.pool, MaxBytes: size,
	})
	expect(t, res, "tcp:success", "tls:success", "http:success")
	if o := res.Last(); o.BytesRead != size || o.LimitReached || o.StatusCode != 200 {
		t.Fatalf("unexpected observation %+v", o)
	}
}

func TestHTTPSUntrustedStopsBeforeRequest(t *testing.T) {
	p := newPKI(t)
	srv := newTLSServer(t, p.leaf(t, time.Now().Add(time.Hour), "probe.test"))
	res := HTTP(context.Background(), HTTPRequest{Target: target(srv.addr, IPv4), URL: "https://probe.test/", RootCAs: newPKI(t).pool, MaxBytes: 1})
	expect(t, res, "tcp:success", "tls:certificate_untrusted")
}

func TestHTTPEarlyHintsThenFinalResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", "</style.css>; rel=preload; as=style")
		w.WriteHeader(http.StatusEarlyHints)
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Set("Content-Length", "2")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	res := HTTP(context.Background(), HTTPRequest{Target: target(addrPort(srv.Listener.Addr()), IPv4), URL: "http://probe.test/", MaxBytes: 1024})
	expect(t, res, "tcp:success", "http:success")
	if o := res.Last(); o.StatusCode != 200 || o.InterimResponses != 2 || o.BytesRead != 2 || o.LimitReached {
		t.Fatalf("unexpected observation %+v", o)
	}
}

func TestHTTPNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	res := HTTP(context.Background(), HTTPRequest{Target: target(addrPort(srv.Listener.Addr()), IPv4), URL: "http://probe.test/", MaxBytes: 1024})
	expect(t, res, "tcp:success", "http:http_status")
	if o := res.Last(); o.StatusCode != 503 || o.BytesRead != 0 {
		t.Fatalf("unexpected observation %+v", o)
	}
}

func TestHTTPRawResponses(t *testing.T) {
	cases := []struct {
		name      string
		response  string
		want      string
		bytesRead int64
	}{
		{"content-length early EOF", "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n" + strings.Repeat("x", 100), "http:early_eof", 100},
		{"chunked early EOF", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n64\r\n" + strings.Repeat("x", 50), "http:early_eof", 50},
		{"close before response", "", "http:early_eof", 0},
		{"close inside header", "HTTP/1.1 200 OK\r\nContent-Le", "http:http_protocol_error", 0},
		{"close-delimited body", "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n" + strings.Repeat("x", 300), "http:success", 300},
		{"header too large", "HTTP/1.1 200 OK\r\nX-Pad: " + strings.Repeat("a", 2048) + "\r\n\r\n", "http:http_protocol_error", 0},
		{"not HTTP", "SSH-2.0-not-http\r\n\r\n", "http:http_protocol_error", 0},
		{"interim then early EOF", "HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc", "http:early_eof", 3},
		{"interim headers share limit", strings.Repeat("HTTP/1.1 103 Early Hints\r\nX-Pad: "+strings.Repeat("a", 200)+"\r\n\r\n", 6), "http:http_protocol_error", 0},
		{"unrequested protocol switch", "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n", "http:http_protocol_error", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := newRawServer(t, "tcp4", "127.0.0.1:0", replyAfterRequest(c.response, false))
			res := HTTP(context.Background(), HTTPRequest{
				Target: target(srv.addr, IPv4), URL: "http://probe.test/", MaxBytes: 4096, MaxHeaderBytes: 1024,
			})
			expect(t, res, "tcp:success", c.want)
			if o := res.Last(); o.BytesRead != c.bytesRead {
				t.Fatalf("bytes read = %d, want %d", o.BytesRead, c.bytesRead)
			}
		})
	}
}

func TestHTTPStalledBodyTimesOut(t *testing.T) {
	srv := newRawServer(t, "tcp4", "127.0.0.1:0",
		replyAfterRequest("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n"+strings.Repeat("x", 10), true))
	tg := target(srv.addr, IPv4)
	tg.Timeout = 300 * time.Millisecond
	res := HTTP(context.Background(), HTTPRequest{Target: tg, URL: "http://probe.test/", MaxBytes: 4096})
	expect(t, res, "tcp:success", "http:timeout")
	if o := res.Last(); o.BytesRead != 10 || o.StatusCode != 200 {
		t.Fatalf("unexpected observation %+v", o)
	}
}

func TestHTTPCanceledDuringBody(t *testing.T) {
	srv := newRawServer(t, "tcp4", "127.0.0.1:0",
		replyAfterRequest("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n", true))
	ctx, cancel := context.WithCancel(context.Background())
	timer := time.AfterFunc(100*time.Millisecond, cancel)
	defer timer.Stop()
	res := HTTP(ctx, HTTPRequest{Target: target(srv.addr, IPv4), URL: "http://probe.test/", MaxBytes: 4096})
	expect(t, res, "tcp:success", "http:canceled")
}
