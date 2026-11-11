package ipcheck

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"syscall"
	"time"
)

// HTTPStatus is the outcome of one HTTP check.
type HTTPStatus string

const (
	HTTPMatched  HTTPStatus = "matched"
	HTTPMismatch HTTPStatus = "mismatch"
	HTTPError    HTTPStatus = "error"
)

// HTTPResult is the outcome for one check. It never contains the URL,
// headers or body.
type HTTPResult struct {
	Name       string
	Status     HTTPStatus
	StatusCode int
	// Truncated reports that the body exceeded MaxBodyBytes while searching
	// for the marker.
	Truncated bool
	Reason    string
	Duration  time.Duration
}

func (c *Checker) probe(ctx context.Context, hc HTTPCheck) (res HTTPResult) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	start := c.now()
	res.Name = hc.Name
	defer func() { res.Duration = c.now().Sub(start) }()

	req, err := http.NewRequestWithContext(ctx, hc.Method, hc.URL, nil)
	if err != nil {
		res.Status, res.Reason = HTTPError, "invalid request"
		return res
	}
	resp, err := c.client.Do(req)
	if err != nil {
		res.Status, res.Reason = HTTPError, requestReason(err)
		return res
	}
	defer resp.Body.Close()
	res.StatusCode = resp.StatusCode

	if !slices.Contains(hc.ExpectStatus, resp.StatusCode) {
		res.Status = HTTPMismatch
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			res.Reason = "redirect not followed (status " + strconv.Itoa(resp.StatusCode) + ")"
		} else {
			res.Reason = "unexpected status " + strconv.Itoa(resp.StatusCode)
		}
		return res
	}
	if hc.BodyContains == "" {
		res.Status = HTTPMatched
		return res
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes+1))
	if len(body) > MaxBodyBytes {
		body, res.Truncated, err = body[:MaxBodyBytes], true, nil
	}
	if bytes.Contains(body, []byte(hc.BodyContains)) {
		res.Status = HTTPMatched
		return res
	}
	switch {
	case err != nil:
		res.Status, res.Reason = HTTPError, "reading body: "+requestReason(err)
	case res.Truncated:
		res.Status, res.Reason = HTTPMismatch, "body marker not found in first "+strconv.Itoa(MaxBodyBytes)+" bytes"
	default:
		res.Status, res.Reason = HTTPMismatch, "body marker not found"
	}
	return res
}

// requestReason maps a transport error to a fixed phrase. *url.Error and
// *net.OpError would expose the URL (possibly with a token) and addresses.
func requestReason(err error) string {
	var (
		netErr   net.Error
		dnsErr   *net.DNSError
		certErr  *tls.CertificateVerificationError
		recErr   tls.RecordHeaderError
		alertErr tls.AlertError
		opErr    *net.OpError
	)
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.As(err, &dnsErr):
		return "dns lookup failed"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.Is(err, syscall.ECONNRESET):
		return "connection reset"
	case errors.As(err, &certErr):
		return "tls certificate verification failed"
	case errors.As(err, &recErr), errors.As(err, &alertErr):
		return "tls handshake failed"
	case errors.As(err, &opErr):
		return "connection failed"
	default:
		return "request failed"
	}
}
