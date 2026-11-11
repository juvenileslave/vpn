package vless

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// MaxExtraBytes bounds the decoded XHTTP extra JSON.
const MaxExtraBytes = 8 << 10

var xhttpModes = []string{"auto", "packet-up", "stream-up", "stream-one"}

// XHTTPExtra is the supported client-side subset of the XHTTP "extra" object
// from Xray v26.11.9. Zero values mean "Xray default" and are omitted.
type XHTTPExtra struct {
	Headers              map[string]string `json:"headers,omitempty"`
	XPaddingBytes        *Range            `json:"xPaddingBytes,omitempty"`
	XPaddingObfsMode     bool              `json:"xPaddingObfsMode,omitempty"`
	XPaddingKey          string            `json:"xPaddingKey,omitempty"`
	XPaddingHeader       string            `json:"xPaddingHeader,omitempty"`
	XPaddingPlacement    string            `json:"xPaddingPlacement,omitempty"`
	XPaddingMethod       string            `json:"xPaddingMethod,omitempty"`
	UplinkHTTPMethod     string            `json:"uplinkHTTPMethod,omitempty"`
	SessionIDPlacement   string            `json:"sessionIDPlacement,omitempty"`
	SessionIDKey         string            `json:"sessionIDKey,omitempty"`
	SeqPlacement         string            `json:"seqPlacement,omitempty"`
	SeqKey               string            `json:"seqKey,omitempty"`
	UplinkDataPlacement  string            `json:"uplinkDataPlacement,omitempty"`
	UplinkDataKey        string            `json:"uplinkDataKey,omitempty"`
	UplinkChunkSize      *Range            `json:"uplinkChunkSize,omitempty"`
	NoGRPCHeader         bool              `json:"noGRPCHeader,omitempty"`
	ScMaxEachPostBytes   *Range            `json:"scMaxEachPostBytes,omitempty"`
	ScMinPostsIntervalMs *Range            `json:"scMinPostsIntervalMs,omitempty"`
	Xmux                 *Xmux             `json:"xmux,omitempty"`
}

// Xmux is optional XHTTP connection multiplexing; it is never required.
type Xmux struct {
	MaxConcurrency   *Range `json:"maxConcurrency,omitempty"`
	MaxConnections   *Range `json:"maxConnections,omitempty"`
	CMaxReuseTimes   *Range `json:"cMaxReuseTimes,omitempty"`
	HMaxRequestTimes *Range `json:"hMaxRequestTimes,omitempty"`
	HMaxReusableSecs *Range `json:"hMaxReusableSecs,omitempty"`
	HKeepAlivePeriod *int64 `json:"hKeepAlivePeriod,omitempty"`
}

// Range is a non-negative Xray integer range; From == To is a single value.
type Range struct {
	From, To int32
}

// MarshalJSON emits an integer for a single value and "from-to" otherwise,
// the two forms Xray accepts.
func (r Range) MarshalJSON() ([]byte, error) {
	if r.From == r.To {
		return []byte(strconv.Itoa(int(r.From))), nil
	}
	return json.Marshal(strconv.Itoa(int(r.From)) + "-" + strconv.Itoa(int(r.To)))
}

var (
	xPaddingPlacements = []string{"cookie", "header", "query", "queryInHeader"}
	xPaddingMethods    = []string{"repeat-x", "tokenish"}
	idPlacements       = []string{"path", "cookie", "header", "query"}
	dataPlacements     = []string{"auto", "body", "cookie", "header"}
	safeKeyRe          = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)
)

// serverOnlyExtra are XHTTP options Xray reads only on the server side.
var serverOnlyExtra = []string{"noSSEHeader", "scMaxBufferedPosts", "scStreamUpServerSecs", "serverMaxHeaderBytes"}

// unsupportedExtra are valid Xray options deliberately outside this subset.
var unsupportedExtra = []string{"downloadSettings", "h2Params", "sessionIDTable", "sessionIDLength", "extra"}

func parseExtra(raw string, x *XHTTP) (*XHTTPExtra, error) {
	if len(raw) > MaxExtraBytes {
		return nil, fieldErr("extra", "exceeds %d bytes", MaxExtraBytes)
	}
	obj, err := decodeObject("extra", []byte(raw))
	if err != nil {
		return nil, err
	}
	e := &XHTTPExtra{}
	for _, k := range sortedKeys(obj) {
		f, v := "extra."+k, obj[k]
		switch k {
		case "host", "path", "mode":
			// Xray ignores these inside extra; a different value is a conflict.
			var s string
			if err := decodeScalar(f, v, &s, "must be a string"); err != nil {
				return nil, err
			}
			if s != map[string]string{"host": x.Host, "path": x.Path, "mode": x.Mode}[k] {
				return nil, fieldErr(f, "conflicts with the link parameter %q", k)
			}
		case "headers":
			if e.Headers, err = parseHeaders(f, v); err != nil {
				return nil, err
			}
		case "xPaddingBytes":
			err = decodeRangeInto(f, v, &e.XPaddingBytes)
		case "uplinkChunkSize":
			err = decodeRangeInto(f, v, &e.UplinkChunkSize)
		case "scMaxEachPostBytes":
			err = decodeRangeInto(f, v, &e.ScMaxEachPostBytes)
		case "scMinPostsIntervalMs":
			err = decodeRangeInto(f, v, &e.ScMinPostsIntervalMs)
		case "xPaddingObfsMode":
			err = decodeScalar(f, v, &e.XPaddingObfsMode, "must be a boolean")
		case "noGRPCHeader":
			err = decodeScalar(f, v, &e.NoGRPCHeader, "must be a boolean")
		case "xPaddingKey":
			err = decodeToken(f, v, &e.XPaddingKey)
		case "xPaddingHeader":
			err = decodeToken(f, v, &e.XPaddingHeader)
		case "sessionIDKey":
			err = decodeToken(f, v, &e.SessionIDKey)
		case "seqKey":
			err = decodeToken(f, v, &e.SeqKey)
		case "uplinkDataKey":
			err = decodeToken(f, v, &e.UplinkDataKey)
		case "uplinkHTTPMethod":
			if err = decodeToken(f, v, &e.UplinkHTTPMethod); err == nil {
				e.UplinkHTTPMethod = strings.ToUpper(e.UplinkHTTPMethod)
			}
		case "xPaddingPlacement":
			err = decodeEnum(f, v, &e.XPaddingPlacement, xPaddingPlacements)
		case "xPaddingMethod":
			err = decodeEnum(f, v, &e.XPaddingMethod, xPaddingMethods)
		case "sessionIDPlacement":
			err = decodeEnum(f, v, &e.SessionIDPlacement, idPlacements)
		case "seqPlacement":
			err = decodeEnum(f, v, &e.SeqPlacement, idPlacements)
		case "uplinkDataPlacement":
			err = decodeEnum(f, v, &e.UplinkDataPlacement, dataPlacements)
		case "xmux":
			e.Xmux, err = parseXmux(f, v)
		default:
			switch {
			case slices.Contains(serverOnlyExtra, k):
				return nil, fieldErr(f, "server-side option is not applicable to a client outbound")
			case slices.Contains(unsupportedExtra, k):
				return nil, fieldErr(f, "not supported by this parser")
			case safeKeyRe.MatchString(k):
				return nil, fieldErr(f, "unknown option")
			default:
				return nil, fieldErr("extra", "unknown option")
			}
		}
		if err != nil {
			return nil, err
		}
	}

	// Cross-field rules enforced by Xray v26.11.9 at config load.
	if r := e.XPaddingBytes; r != nil && r.From == 0 {
		return nil, fieldErr("extra.xPaddingBytes", "padding cannot be disabled")
	}
	if e.UplinkHTTPMethod == "GET" && x.Mode != "packet-up" {
		return nil, fieldErr("extra.uplinkHTTPMethod", "GET requires mode packet-up")
	}
	if (e.UplinkDataPlacement == "cookie" || e.UplinkDataPlacement == "header") && x.Mode != "packet-up" {
		return nil, fieldErr("extra.uplinkDataPlacement", "cookie and header placement require mode packet-up")
	}
	if m := e.Xmux; m != nil && m.MaxConnections != nil && m.MaxConnections.To > 0 &&
		m.MaxConcurrency != nil && m.MaxConcurrency.To > 0 {
		return nil, fieldErr("extra.xmux", "maxConnections conflicts with maxConcurrency")
	}

	if isZeroExtra(e) {
		return nil, nil
	}
	return e, nil
}

func isZeroExtra(e *XHTTPExtra) bool {
	b, _ := json.Marshal(e)
	return string(b) == "{}"
}

func parseHeaders(field string, v json.RawMessage) (map[string]string, error) {
	obj, err := decodeObject(field, v)
	if err != nil {
		return nil, err
	}
	headers := make(map[string]string, len(obj))
	seen := map[string]bool{}
	for _, name := range sortedKeys(obj) {
		if !tokenRe.MatchString(name) {
			return nil, fieldErr(field, "malformed header name")
		}
		f := field + "." + name
		lower := strings.ToLower(name)
		if lower == "host" {
			return nil, fieldErr(f, "use the host link parameter instead")
		}
		if seen[lower] {
			return nil, fieldErr(f, "duplicate header (case-insensitive)")
		}
		seen[lower] = true
		var val string
		if err := decodeScalar(f, obj[name], &val, "must be a string"); err != nil {
			return nil, err
		}
		if strings.IndexFunc(val, func(r rune) bool { return unicode.IsControl(r) && r != '\t' }) >= 0 {
			return nil, fieldErr(f, "contains control characters")
		}
		headers[name] = val
	}
	return headers, nil
}

var xmuxRanges = []string{"maxConcurrency", "maxConnections", "cMaxReuseTimes", "hMaxRequestTimes", "hMaxReusableSecs"}

func parseXmux(field string, v json.RawMessage) (*Xmux, error) {
	obj, err := decodeObject(field, v)
	if err != nil {
		return nil, err
	}
	m := &Xmux{}
	targets := map[string]**Range{
		"maxConcurrency": &m.MaxConcurrency, "maxConnections": &m.MaxConnections,
		"cMaxReuseTimes": &m.CMaxReuseTimes, "hMaxRequestTimes": &m.HMaxRequestTimes,
		"hMaxReusableSecs": &m.HMaxReusableSecs,
	}
	for _, k := range sortedKeys(obj) {
		f := field + "." + k
		switch {
		case slices.Contains(xmuxRanges, k):
			err = decodeRangeInto(f, obj[k], targets[k])
		case k == "hKeepAlivePeriod":
			var n int64
			if n, err = strconv.ParseInt(string(obj[k]), 10, 64); err != nil {
				return nil, fieldErr(f, "must be an integer")
			}
			m.HKeepAlivePeriod = &n
		case safeKeyRe.MatchString(k):
			return nil, fieldErr(f, "unknown option")
		default:
			return nil, fieldErr(field, "unknown option")
		}
		if err != nil {
			return nil, err
		}
	}
	if *m == (Xmux{}) {
		return nil, nil
	}
	return m, nil
}

// decodeObject decodes one JSON object, rejecting duplicate keys and trailing
// data. Decoder errors are not wrapped because they may quote input bytes.
func decodeObject(field string, data []byte) (map[string]json.RawMessage, error) {
	invalid := fieldErr(field, "must be a JSON object")
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, invalid
	}
	obj := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, invalid
		}
		key, _ := tok.(string)
		if _, dup := obj[key]; dup {
			if safeKeyRe.MatchString(key) {
				return nil, fieldErr(field+"."+key, "duplicate key")
			}
			return nil, fieldErr(field, "duplicate key")
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, invalid
		}
		obj[key] = v
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, invalid
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, invalid
	}
	return obj, nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func decodeScalar(field string, v json.RawMessage, dst any, reason string) error {
	if string(v) == "null" || json.Unmarshal(v, dst) != nil {
		return fieldErr(field, "%s", reason)
	}
	return nil
}

func decodeToken(field string, v json.RawMessage, dst *string) error {
	if err := decodeScalar(field, v, dst, "must be a string"); err != nil {
		return err
	}
	if !tokenRe.MatchString(*dst) {
		return fieldErr(field, "must be a non-empty HTTP token")
	}
	return nil
}

func decodeEnum(field string, v json.RawMessage, dst *string, allowed []string) error {
	if err := decodeScalar(field, v, dst, "must be a string"); err != nil {
		return err
	}
	if !slices.Contains(allowed, *dst) {
		return fieldErr(field, "unsupported value (supported: %s)", strings.Join(allowed, ", "))
	}
	return nil
}

func decodeRangeInto(field string, v json.RawMessage, dst **Range) error {
	invalid := fieldErr(field, `must be a non-negative integer or "from-to" range`)
	s := string(v)
	if strings.HasPrefix(s, `"`) {
		if json.Unmarshal(v, &s) != nil {
			return invalid
		}
	}
	from, to, isRange := strings.Cut(s, "-")
	if !isRange {
		to = from
	}
	a, err1 := strconv.ParseInt(from, 10, 32)
	b, err2 := strconv.ParseInt(to, 10, 32)
	if err1 != nil || err2 != nil || a < 0 || b < 0 || strings.HasPrefix(from, "+") || strings.HasPrefix(to, "+") {
		return invalid
	}
	if a > b {
		return fieldErr(field, "range start exceeds end")
	}
	*dst = &Range{From: int32(a), To: int32(b)}
	return nil
}
