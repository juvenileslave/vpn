package probe

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"time"
)

// HTTP connects to the target, performs a verified TLS handshake for https
// URLs, sends one GET request and reads at most MaxBytes of the body.
// Redirects are not followed and no proxy is consulted.
func HTTP(ctx context.Context, req HTTPRequest) Result {
	if err := req.validate(); err != nil {
		return invalid(err)
	}
	u, err := url.Parse(req.URL)
	switch {
	case err != nil:
		return invalid(err)
	case u.Scheme != "http" && u.Scheme != "https":
		return invalid(errors.New("URL scheme must be http or https"))
	case u.Hostname() == "":
		return invalid(errors.New("URL must have a host"))
	case u.User != nil:
		return invalid(errors.New("URL must not contain userinfo"))
	case req.MaxBytes <= 0:
		return invalid(errors.New("max bytes must be positive"))
	case req.MaxHeaderBytes < 0:
		return invalid(errors.New("max header bytes must not be negative"))
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

	rw := conn
	if u.Scheme == "https" {
		serverName := req.ServerName
		if serverName == "" {
			serverName = u.Hostname()
		}
		tc, tobs := handshake(ctx, conn, serverName, req.RootCAs, obs)
		res.add(tobs)
		if tc == nil {
			return res
		}
		rw = tc
	}
	res.add(transfer(ctx, rw, u, req, obs))
	return res
}

func transfer(ctx context.Context, conn net.Conn, u *url.URL, req HTTPRequest, base Observation) (obs Observation) {
	obs = Observation{
		Stage: StageHTTP, Start: time.Now(),
		LocalAddr: base.LocalAddr, RemoteAddr: base.RemoteAddr,
	}
	defer func() { obs.End = time.Now() }()
	fail := func(o Outcome, err error) Observation {
		obs.Outcome, obs.Error = o, err.Error()
		return obs
	}

	hreq := &http.Request{
		Method:     http.MethodGet,
		URL:        u,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Host:       u.Host,
		Header: http.Header{
			"User-Agent":      {"vpnctl-probe"},
			"Accept-Encoding": {"identity"},
		},
		Close: true,
	}
	if err := hreq.Write(conn); err != nil {
		return fail(classifyNet(ctx, err), err)
	}

	headerLimit := req.MaxHeaderBytes
	if headerLimit == 0 {
		headerLimit = DefaultMaxHeaderBytes
	}
	// The budget is shared by all interim 1xx headers and the final header.
	budget := &budgetReader{r: conn, remaining: headerLimit}
	br := bufio.NewReader(budget)
	var resp *http.Response
	for {
		var err error
		resp, err = http.ReadResponse(br, hreq)
		if err != nil {
			return fail(classifyHTTP(ctx, err), err)
		}
		if resp.StatusCode == http.StatusSwitchingProtocols {
			obs.StatusCode = resp.StatusCode
			return fail(OutcomeHTTPProtocol, errors.New("unrequested protocol switch: "+resp.Status))
		}
		if resp.StatusCode >= 200 || resp.StatusCode < 100 {
			break
		}
		obs.InterimResponses++
	}
	// resp.Body is deliberately not closed: Body.Close may drain the rest
	// of the body without limit. Closing the connection releases it.
	obs.HeaderReceived = time.Now()
	obs.StatusCode = resp.StatusCode
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fail(OutcomeHTTPStatus, errors.New("HTTP status "+resp.Status))
	}

	budget.remaining = math.MaxInt64
	var destination io.Writer = io.Discard
	var digest hash.Hash
	if req.HashBody {
		digest = sha256.New()
		destination = digest
	}
	n, err := io.CopyN(destination, resp.Body, req.MaxBytes)
	obs.BytesRead = n
	obs.BodyDuration = time.Since(obs.HeaderReceived)
	if req.HashBody {
		obs.SHA256 = hex.EncodeToString(digest.Sum(nil))
	}
	switch {
	case errors.Is(err, io.EOF):
	case err != nil:
		return fail(classifyHTTP(ctx, err), err)
	default:
		// No extra read: a peer stalling right after MaxBytes must not turn
		// a completed transfer into a timeout.
		obs.LimitReached = resp.ContentLength != n
	}
	obs.Outcome = OutcomeSuccess
	return obs
}

func classifyHTTP(ctx context.Context, err error) Outcome {
	var opErr *net.OpError
	switch {
	case ctx.Err() != nil, isTimeout(err):
		return classifyNet(ctx, err)
	case errors.Is(err, errHeaderTooLarge):
		return OutcomeHTTPProtocol
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return OutcomeEarlyEOF
	case errors.As(err, &opErr):
		return classifyNet(ctx, err)
	}
	return OutcomeHTTPProtocol
}

// budgetReader fails once its byte budget is spent. It bounds how much of
// the connection the response header parser may consume.
type budgetReader struct {
	r         io.Reader
	remaining int64
}

var errHeaderTooLarge = errors.New("response header exceeds limit")

func (b *budgetReader) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		return 0, errHeaderTooLarge
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.r.Read(p)
	b.remaining -= int64(n)
	return n, err
}
