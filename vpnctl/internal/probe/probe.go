// Package probe performs bounded TCP connect, certificate-verified TLS
// handshake and HTTP transfer probes against one explicit IP address.
//
// Every probe dials exactly once, through the address family chosen in the
// request, with no DNS lookup, proxy, retry, redirect or connection reuse.
// Results describe only what was observed on the socket: a successful TLS
// handshake is not a REALITY/VLESS check, and a timeout is not proof of any
// particular blocking mechanism.
package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"
)

// Family selects the IP address family used for a probe.
type Family string

const (
	IPv4 Family = "ipv4"
	IPv6 Family = "ipv6"
)

// Stage names one step of a probe.
type Stage string

const (
	// StageRequest is reported when the request is rejected before any
	// network activity.
	StageRequest Stage = "request"
	StageTCP     Stage = "tcp"
	StageTLS     Stage = "tls"
	StageHTTP    Stage = "http"
)

// Outcome classifies what was observed at a stage.
type Outcome string

const (
	OutcomeSuccess        Outcome = "success"
	OutcomeInvalidRequest Outcome = "invalid_request"
	// OutcomeTimeout means the request timeout or the context deadline
	// expired during the stage.
	OutcomeTimeout Outcome = "timeout"
	// OutcomeCanceled means the caller's context was canceled.
	OutcomeCanceled Outcome = "canceled"
	// OutcomeRefused means the peer (or a device on the path) answered the
	// connection attempt with a reset.
	OutcomeRefused Outcome = "refused"
	// OutcomeSourceUnavailable means the requested source IP could not be
	// bound locally; nothing was sent.
	OutcomeSourceUnavailable Outcome = "source_unavailable"
	OutcomeNetworkError      Outcome = "network_error"
	// OutcomeCertificateUntrusted means the chain does not lead to a
	// trusted root.
	OutcomeCertificateUntrusted Outcome = "certificate_untrusted"
	// OutcomeHostnameMismatch means the certificate is not valid for the
	// requested server name.
	OutcomeHostnameMismatch Outcome = "hostname_mismatch"
	// OutcomeCertificateInvalid covers other verification failures such as
	// an expired certificate.
	OutcomeCertificateInvalid Outcome = "certificate_invalid"
	// OutcomeHandshakeFailed covers every other TLS handshake failure:
	// alerts, resets, non-TLS replies, early close.
	OutcomeHandshakeFailed Outcome = "handshake_failed"
	// OutcomeHTTPStatus means a response arrived with a non-2xx status.
	OutcomeHTTPStatus Outcome = "http_status"
	// OutcomeHTTPProtocol means the response could not be parsed or its
	// header exceeded MaxHeaderBytes.
	OutcomeHTTPProtocol Outcome = "http_protocol_error"
	// OutcomeEarlyEOF means the connection ended before the body declared
	// by Content-Length or chunked encoding was complete.
	OutcomeEarlyEOF Outcome = "early_eof"
)

// Target is the common part of every probe request.
type Target struct {
	// Address is an IP literal of the selected Family. Host names are not
	// resolved: DNS answers are a separate observation.
	Address netip.Addr
	Port    uint16
	Family  Family
	// Timeout bounds the whole probe, all stages included. It is required;
	// an earlier context deadline takes precedence.
	Timeout time.Duration
	// SourceIP, when valid, is bound as the local address. It must belong
	// to the selected Family. Binding a source address does not prove which
	// interface or tunnel the kernel used.
	SourceIP netip.Addr
}

// TCPRequest describes a TCP connect probe.
type TCPRequest struct {
	Target
}

// TLSRequest describes a TCP connect followed by a TLS handshake.
type TLSRequest struct {
	Target
	// ServerName is sent as SNI and verified against the certificate.
	ServerName string
	// RootCAs overrides the system roots when non-nil. Verification is
	// never disabled.
	RootCAs *x509.CertPool
}

// HTTPRequest describes one HTTP/1.1 GET over a fresh connection.
type HTTPRequest struct {
	Target
	// URL is an absolute http or https URL. Its host is used for the Host
	// header and, for https, as SNI unless ServerName is set; the
	// connection always goes to Target.Address.
	URL        string
	ServerName string
	RootCAs    *x509.CertPool
	// MaxBytes is the maximum number of body bytes to read. It is required.
	MaxBytes int64
	// MaxHeaderBytes bounds the response status line and header; zero means
	// DefaultMaxHeaderBytes.
	MaxHeaderBytes int64
}

// DefaultMaxHeaderBytes is the response header limit used when
// HTTPRequest.MaxHeaderBytes is zero.
const DefaultMaxHeaderBytes = 64 << 10

// Observation records one stage.
type Observation struct {
	Stage   Stage     `json:"stage"`
	Outcome Outcome   `json:"outcome"`
	Start   time.Time `json:"start"`
	End     time.Time `json:"end"`
	// LocalAddr and RemoteAddr are the socket addresses reported by the
	// kernel; they are zero when no connection was established.
	LocalAddr  netip.AddrPort `json:"local_addr"`
	RemoteAddr netip.AddrPort `json:"remote_addr"`
	Error      string         `json:"error,omitempty"`

	// TLSVersion is the negotiated version after a successful handshake.
	TLSVersion uint16 `json:"tls_version,omitempty"`

	// StatusCode is set once an HTTP response header was received.
	StatusCode int `json:"status_code,omitempty"`
	// HeaderReceived is when the response header was parsed.
	HeaderReceived time.Time `json:"header_received,omitzero"`
	// BytesRead counts response body bytes consumed, at most MaxBytes.
	BytesRead int64 `json:"bytes_read,omitempty"`
	// LimitReached reports that MaxBytes were read and the body had more.
	LimitReached bool `json:"limit_reached,omitempty"`
}

// Duration is the elapsed time of the stage.
func (o Observation) Duration() time.Duration { return o.End.Sub(o.Start) }

// Result lists the stages attempted, in order. Probing stops at the first
// stage whose outcome is not success.
type Result struct {
	Observations []Observation `json:"observations"`
}

// Last returns the final observation.
func (r Result) Last() Observation {
	if len(r.Observations) == 0 {
		return Observation{}
	}
	return r.Observations[len(r.Observations)-1]
}

// OK reports whether every attempted stage succeeded.
func (r Result) OK() bool {
	return len(r.Observations) > 0 && r.Last().Outcome == OutcomeSuccess
}

func (r *Result) add(o Observation) { r.Observations = append(r.Observations, o) }

func invalid(err error) Result {
	now := time.Now()
	return Result{Observations: []Observation{{
		Stage: StageRequest, Outcome: OutcomeInvalidRequest,
		Start: now, End: now, Error: err.Error(),
	}}}
}

func (t Target) validate() error {
	var want func(netip.Addr) bool
	switch t.Family {
	case IPv4:
		want = netip.Addr.Is4
	case IPv6:
		want = func(a netip.Addr) bool { return a.Is6() && !a.Is4In6() }
	default:
		return fmt.Errorf("family must be %q or %q", IPv4, IPv6)
	}
	if !t.Address.IsValid() || !want(t.Address) {
		return fmt.Errorf("address %v is not an %s address", t.Address, t.Family)
	}
	if t.Address.Zone() != "" {
		return errors.New("address must not have a zone")
	}
	if t.Port == 0 {
		return errors.New("port must be 1-65535")
	}
	if t.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	if t.SourceIP.IsValid() && (!want(t.SourceIP) || t.SourceIP.Zone() != "") {
		return fmt.Errorf("source IP %v is not an %s address", t.SourceIP, t.Family)
	}
	return nil
}

func (t Target) network() string {
	if t.Family == IPv6 {
		return "tcp6"
	}
	return "tcp4"
}

// dial performs the TCP stage. On success the caller owns conn and must
// close it.
func dial(ctx context.Context, t Target) (net.Conn, Observation) {
	d := net.Dialer{KeepAlive: -1}
	if t.SourceIP.IsValid() {
		d.LocalAddr = &net.TCPAddr{IP: t.SourceIP.AsSlice()}
	}
	obs := Observation{Stage: StageTCP, Start: time.Now()}
	conn, err := d.DialContext(ctx, t.network(),
		net.JoinHostPort(t.Address.String(), strconv.Itoa(int(t.Port))))
	obs.End = time.Now()
	if err != nil {
		obs.Outcome, obs.Error = classifyNet(ctx, err), err.Error()
		return nil, obs
	}
	obs.Outcome = OutcomeSuccess
	obs.LocalAddr = addrPort(conn.LocalAddr())
	obs.RemoteAddr = addrPort(conn.RemoteAddr())
	return conn, obs
}

func addrPort(a net.Addr) netip.AddrPort {
	tcp, ok := a.(*net.TCPAddr)
	if !ok {
		return netip.AddrPort{}
	}
	ap := tcp.AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// watch makes conn I/O fail as soon as ctx ends and applies its deadline.
// The returned stop function must be called before conn is closed.
func watch(ctx context.Context, conn net.Conn) (stop func() bool) {
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	return context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Unix(1, 0))
	})
}

func classifyNet(ctx context.Context, err error) Outcome {
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		return OutcomeCanceled
	case errors.Is(ctx.Err(), context.DeadlineExceeded), isTimeout(err):
		return OutcomeTimeout
	case errors.Is(err, syscall.ECONNREFUSED):
		return OutcomeRefused
	case errors.Is(err, syscall.EADDRNOTAVAIL):
		return OutcomeSourceUnavailable
	}
	return OutcomeNetworkError
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func classifyTLS(ctx context.Context, err error) Outcome {
	var (
		unknown  x509.UnknownAuthorityError
		hostname x509.HostnameError
		invalid  x509.CertificateInvalidError
	)
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		return OutcomeCanceled
	case errors.Is(ctx.Err(), context.DeadlineExceeded), isTimeout(err):
		return OutcomeTimeout
	case errors.As(err, &unknown):
		return OutcomeCertificateUntrusted
	case errors.As(err, &hostname):
		return OutcomeHostnameMismatch
	case errors.As(err, &invalid):
		return OutcomeCertificateInvalid
	}
	return OutcomeHandshakeFailed
}

// handshake performs the TLS stage over an established connection.
func handshake(ctx context.Context, conn net.Conn, serverName string, roots *x509.CertPool, base Observation) (*tls.Conn, Observation) {
	obs := Observation{
		Stage: StageTLS, Start: time.Now(),
		LocalAddr: base.LocalAddr, RemoteAddr: base.RemoteAddr,
	}
	tc := tls.Client(conn, &tls.Config{
		ServerName: serverName,
		RootCAs:    roots,
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
	})
	err := tc.HandshakeContext(ctx)
	obs.End = time.Now()
	if err != nil {
		obs.Outcome, obs.Error = classifyTLS(ctx, err), err.Error()
		return nil, obs
	}
	obs.Outcome = OutcomeSuccess
	obs.TLSVersion = tc.ConnectionState().Version
	return tc, obs
}

// TCP connects to the target and closes the connection immediately.
// Success proves only that a TCP handshake completed with something
// answering at that address.
func TCP(ctx context.Context, req TCPRequest) Result {
	if err := req.validate(); err != nil {
		return invalid(err)
	}
	ctx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()
	var res Result
	conn, obs := dial(ctx, req.Target)
	res.add(obs)
	if conn != nil {
		_ = conn.Close()
	}
	return res
}

// TLS connects to the target and performs a verified TLS handshake.
func TLS(ctx context.Context, req TLSRequest) Result {
	if err := req.validate(); err != nil {
		return invalid(err)
	}
	if req.ServerName == "" {
		return invalid(errors.New("server name is required"))
	}
	ctx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()
	var res Result
	conn, obs := dial(ctx, req.Target)
	res.add(obs)
	if conn == nil {
		return res
	}
	defer conn.Close()
	stop := watch(ctx, conn)
	defer stop()
	_, obs = handshake(ctx, conn, req.ServerName, req.RootCAs, obs)
	res.add(obs)
	return res
}
