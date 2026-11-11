// Package metrics queries a Prometheus-compatible HTTP API (VictoriaMetrics)
// and evaluates stateless threshold rules against the results.
//
// The package performs no scheduling, persistence or notification: callers
// decide when to evaluate rules and what to do with the resulting alerts.
package metrics

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultMaxBodyBytes limits a response body when Options.MaxBodyBytes is zero.
const DefaultMaxBodyBytes int64 = 8 << 20

// maxAPIMessage bounds the server-provided error text kept in APIError.
const maxAPIMessage = 256

// ResultType is the Prometheus data.resultType of a successful response.
type ResultType string

// Result types accepted by the client. The "string" type is rejected.
const (
	ResultScalar ResultType = "scalar"
	ResultVector ResultType = "vector"
	ResultMatrix ResultType = "matrix"
)

// Sample is one timestamp/value pair. Value may be NaN or ±Inf exactly as
// reported by the server; the rule evaluator treats such values as unknown.
type Sample struct {
	Time  time.Time
	Value float64
}

// Series is one labelled time series. A vector series holds exactly one sample.
type Series struct {
	Labels  map[string]string
	Samples []Sample
}

// Result is a decoded query result. Scalar is set only for ResultScalar;
// Series is used for ResultVector and ResultMatrix.
type Result struct {
	Type     ResultType
	Scalar   Sample
	Series   []Series
	Warnings []string
}

// BasicAuth is an optional HTTP basic credential.
type BasicAuth struct {
	Username string
	Password string
}

// Options configures a Client.
type Options struct {
	// BaseURL is the HTTPS API root; "/api/v1/query" is appended to its path,
	// so a prefix such as "/select/0/prometheus" is kept.
	BaseURL string
	// HTTPClient performs the requests and is required.
	HTTPClient *http.Client
	// Timeout bounds every request, including reading the body. Must be positive.
	Timeout time.Duration
	// MaxBodyBytes limits the response size; zero means DefaultMaxBodyBytes.
	MaxBodyBytes int64
	// BearerToken and BasicAuth are optional and mutually exclusive.
	BearerToken string
	BasicAuth   *BasicAuth
}

// Client queries a Prometheus-compatible API. It never retries requests.
type Client struct {
	queryURL      string
	queryRangeURL string
	http          *http.Client
	timeout       time.Duration
	maxBody       int64
	bearer        string
	basic         *BasicAuth
}

// NewClient validates opts without touching the network.
func NewClient(opts Options) (*Client, error) {
	u, err := url.Parse(opts.BaseURL)
	switch {
	case opts.BaseURL == "":
		return nil, errors.New("metrics: base URL is required")
	case err != nil:
		return nil, errors.New("metrics: base URL is not a valid URL")
	case u.Scheme != "https":
		return nil, errors.New("metrics: base URL must use https")
	case u.Host == "":
		return nil, errors.New("metrics: base URL must include a host")
	case u.User != nil:
		return nil, errors.New("metrics: base URL must not contain credentials")
	case u.RawQuery != "" || u.ForceQuery || u.Fragment != "":
		return nil, errors.New("metrics: base URL must not contain a query or fragment")
	}
	if opts.HTTPClient == nil {
		return nil, errors.New("metrics: HTTP client is required")
	}
	if opts.Timeout <= 0 {
		return nil, errors.New("metrics: timeout must be positive")
	}
	if opts.MaxBodyBytes < 0 {
		return nil, errors.New("metrics: max body size must not be negative")
	}
	if opts.BearerToken != "" && opts.BasicAuth != nil {
		return nil, errors.New("metrics: bearer token and basic auth are mutually exclusive")
	}
	if opts.BasicAuth != nil && opts.BasicAuth.Username == "" {
		return nil, errors.New("metrics: basic auth username is required")
	}
	maxBody := opts.MaxBodyBytes
	if maxBody == 0 {
		maxBody = DefaultMaxBodyBytes
	}
	c := &Client{
		queryURL:      u.JoinPath("api/v1/query").String(),
		queryRangeURL: u.JoinPath("api/v1/query_range").String(),
		http:          opts.HTTPClient,
		timeout:       opts.Timeout,
		maxBody:       maxBody,
		bearer:        opts.BearerToken,
	}
	if opts.BasicAuth != nil {
		b := *opts.BasicAuth
		c.basic = &b
	}
	return c, nil
}

// Query runs an instant query. A zero at lets the server use its current time.
// The result may be a scalar, a vector or (for range selectors) a matrix.
func (c *Client) Query(ctx context.Context, expr string, at time.Time) (Result, error) {
	if strings.TrimSpace(expr) == "" {
		return Result{}, errors.New("metrics: query expression is empty")
	}
	form := url.Values{"query": {expr}}
	if !at.IsZero() {
		form.Set("time", formatTime(at))
	}
	return c.do(ctx, c.queryURL, form, ResultScalar, ResultVector, ResultMatrix)
}

// QueryRange runs a range query over [start, end] with the given step and
// always returns a matrix.
func (c *Client) QueryRange(ctx context.Context, expr string, start, end time.Time, step time.Duration) (Result, error) {
	switch {
	case strings.TrimSpace(expr) == "":
		return Result{}, errors.New("metrics: query expression is empty")
	case start.IsZero() || end.IsZero():
		return Result{}, errors.New("metrics: range start and end are required")
	case end.Before(start):
		return Result{}, errors.New("metrics: range end is before start")
	case step <= 0:
		return Result{}, errors.New("metrics: range step must be positive")
	}
	form := url.Values{
		"query": {expr},
		"start": {formatTime(start)},
		"end":   {formatTime(end)},
		"step":  {strconv.FormatFloat(step.Seconds(), 'f', -1, 64)},
	}
	return c.do(ctx, c.queryRangeURL, form, ResultMatrix)
}

// formatTime renders t as Unix seconds with millisecond precision.
func formatTime(t time.Time) string {
	ms := t.UnixMilli()
	sign := ""
	if ms < 0 {
		sign, ms = "-", -ms
	}
	return fmt.Sprintf("%s%d.%03d", sign, ms/1000, ms%1000)
}

func (c *Client) do(ctx context.Context, endpoint string, form url.Values, allowed ...ResultType) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	// POST keeps long expressions out of URLs and access logs.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return Result{}, &RequestError{Err: err}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	} else if c.basic != nil {
		req.SetBasicAuth(c.basic.Username, c.basic.Password)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return Result{}, requestError(ctx, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBody+1))
	if err != nil {
		return Result{}, requestError(ctx, err)
	}
	if int64(len(body)) > c.maxBody {
		return Result{}, &BodyTooLargeError{Limit: c.maxBody}
	}
	return decodeResponse(resp.StatusCode, body, allowed)
}

// requestError hides transport details (url.Error carries the endpoint) while
// keeping context errors reachable through errors.Is.
func requestError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return &RequestError{Err: ctxErr}
	}
	var uerr *url.Error
	if errors.As(err, &uerr) {
		err = uerr.Err
	}
	return &RequestError{Err: err}
}

// RequestError reports a failed or cancelled HTTP exchange. Use errors.Is with
// context.Canceled or context.DeadlineExceeded to detect cancellation and timeouts.
type RequestError struct {
	Err error
}

func (e *RequestError) Error() string { return "metrics: request failed: " + e.Err.Error() }
func (e *RequestError) Unwrap() error { return e.Err }

// APIError is a response with "status": "error". Message is the server's
// "error" field, truncated and stripped of control characters.
type APIError struct {
	StatusCode int
	Type       string
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("metrics: query error (HTTP %d, %s): %s", e.StatusCode, e.Type, e.Message)
}

// HTTPError is a non-2xx response without a valid Prometheus error envelope.
type HTTPError struct {
	StatusCode int
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("metrics: unexpected HTTP status %d", e.StatusCode)
}

// BodyTooLargeError is returned when a response exceeds the configured limit.
type BodyTooLargeError struct {
	Limit int64
}

func (e *BodyTooLargeError) Error() string {
	return fmt.Sprintf("metrics: response body exceeds %d bytes", e.Limit)
}

// DecodeError is a malformed, truncated or structurally invalid response.
type DecodeError struct {
	Reason string
}

func (e *DecodeError) Error() string { return "metrics: invalid response: " + e.Reason }

// ResultTypeError is a successful response with a result type the call does not accept.
type ResultTypeError struct {
	Got     string
	Allowed []ResultType
}

func (e *ResultTypeError) Error() string {
	names := make([]string, len(e.Allowed))
	for i, t := range e.Allowed {
		names[i] = string(t)
	}
	return fmt.Sprintf("metrics: unexpected result type %q (want %s)", sanitize(e.Got, 32), strings.Join(names, "|"))
}

type envelope struct {
	Status    string          `json:"status"`
	Data      json.RawMessage `json:"data"`
	ErrorType string          `json:"errorType"`
	Error     string          `json:"error"`
	Warnings  []string        `json:"warnings"`
}

type rawData struct {
	ResultType string          `json:"resultType"`
	Result     json.RawMessage `json:"result"`
}

type rawSeries struct {
	Metric map[string]string `json:"metric"`
	Value  json.RawMessage   `json:"value"`
	Values []json.RawMessage `json:"values"`
}

func decodeResponse(status int, body []byte, allowed []ResultType) (Result, error) {
	ok := status >= 200 && status < 300
	var env envelope
	if err := decodeStrictJSON(body, &env); err != nil {
		if !ok {
			return Result{}, &HTTPError{StatusCode: status}
		}
		return Result{}, &DecodeError{Reason: err.Error()}
	}
	switch {
	case env.Status == "error":
		return Result{}, &APIError{
			StatusCode: status,
			Type:       sanitize(env.ErrorType, 64),
			Message:    sanitize(env.Error, maxAPIMessage),
		}
	case !ok:
		return Result{}, &HTTPError{StatusCode: status}
	case env.Status != "success":
		return Result{}, &DecodeError{Reason: "status is neither success nor error"}
	}

	var data rawData
	if len(env.Data) == 0 || bytes.Equal(env.Data, []byte("null")) {
		return Result{}, &DecodeError{Reason: "missing data"}
	}
	if err := decodeStrictJSON(env.Data, &data); err != nil {
		return Result{}, &DecodeError{Reason: "data: " + err.Error()}
	}
	rt := ResultType(data.ResultType)
	accepted := false
	for _, a := range allowed {
		accepted = accepted || rt == a
	}
	if !accepted {
		return Result{}, &ResultTypeError{Got: data.ResultType, Allowed: allowed}
	}

	res := Result{Type: rt, Warnings: env.Warnings}
	if rt == ResultScalar {
		s, err := decodeSample(data.Result)
		if err != nil {
			return Result{}, &DecodeError{Reason: "scalar: " + err.Error()}
		}
		res.Scalar = s
		return res, nil
	}

	var raw []rawSeries
	if err := decodeStrictJSON(data.Result, &raw); err != nil || raw == nil {
		return Result{}, &DecodeError{Reason: "result must be an array of series"}
	}
	res.Series = make([]Series, 0, len(raw))
	for i, r := range raw {
		s := Series{Labels: r.Metric}
		if s.Labels == nil {
			s.Labels = map[string]string{}
		}
		if rt == ResultVector {
			if r.Value == nil || r.Values != nil {
				return Result{}, &DecodeError{Reason: fmt.Sprintf("series %d: vector entry needs exactly \"value\"", i)}
			}
			sample, err := decodeSample(r.Value)
			if err != nil {
				return Result{}, &DecodeError{Reason: fmt.Sprintf("series %d: %v", i, err)}
			}
			s.Samples = []Sample{sample}
		} else {
			if r.Values == nil || r.Value != nil {
				return Result{}, &DecodeError{Reason: fmt.Sprintf("series %d: matrix entry needs exactly \"values\"", i)}
			}
			s.Samples = make([]Sample, len(r.Values))
			for j, v := range r.Values {
				sample, err := decodeSample(v)
				if err != nil {
					return Result{}, &DecodeError{Reason: fmt.Sprintf("series %d sample %d: %v", i, j, err)}
				}
				s.Samples[j] = sample
			}
		}
		res.Series = append(res.Series, s)
	}
	return res, nil
}

// decodeStrictJSON decodes exactly one JSON value; trailing data is an error.
// Messages are generic so that no response content reaches the caller.
func decodeStrictJSON(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		var typeErr *json.UnmarshalTypeError
		switch {
		case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
			return errors.New("truncated JSON")
		case errors.As(err, &typeErr):
			return errors.New("unexpected JSON type for " + sanitize(typeErr.Field, 64))
		default:
			return errors.New("malformed JSON")
		}
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after JSON value")
	}
	return nil
}

// decodeSample parses a [<unix seconds>, "<value>"] pair.
func decodeSample(raw json.RawMessage) (Sample, error) {
	var pair []json.RawMessage
	if err := decodeStrictJSON(raw, &pair); err != nil || len(pair) != 2 {
		return Sample{}, errors.New("sample must be a [timestamp, value] pair")
	}
	// Decoding into any (not json.Number) rejects quoted numbers.
	var tsAny any
	if err := decodeStrictJSON(pair[0], &tsAny); err != nil {
		return Sample{}, errors.New("sample timestamp must be a number")
	}
	ts, isNum := tsAny.(json.Number)
	if !isNum {
		return Sample{}, errors.New("sample timestamp must be a number")
	}
	sec, err := strconv.ParseFloat(string(ts), 64)
	// ±1e12 s covers every realistic timestamp and keeps UnixMilli in range.
	if err != nil || math.IsNaN(sec) || math.Abs(sec) > 1e12 {
		return Sample{}, errors.New("sample timestamp is out of range")
	}
	var vs string
	if err := decodeStrictJSON(pair[1], &vs); err != nil {
		return Sample{}, errors.New("sample value must be a string")
	}
	val, err := strconv.ParseFloat(vs, 64)
	if err != nil {
		var numErr *strconv.NumError
		// Overflow yields ±Inf, which is still a representable value.
		if !errors.As(err, &numErr) || !errors.Is(numErr.Err, strconv.ErrRange) {
			return Sample{}, errors.New("sample value is not a number")
		}
	}
	return Sample{Time: time.UnixMilli(int64(math.Round(sec * 1000))).UTC(), Value: val}, nil
}

// sanitize truncates s to max runes and replaces control characters.
func sanitize(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == max {
			b.WriteString("…")
			break
		}
		if r < 0x20 || r == 0x7f {
			r = ' '
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}
