package globalping

import "time"

// MeasurementStatus is the overall measurement status. Any value other than
// StatusInProgress is final.
type MeasurementStatus string

const (
	StatusInProgress MeasurementStatus = "in-progress"
	StatusFinished   MeasurementStatus = "finished"
)

// TestStatus is the status of a single probe test. Any value other than
// TestInProgress is final.
type TestStatus string

const (
	TestInProgress TestStatus = "in-progress"
	TestFinished   TestStatus = "finished"
	TestFailed     TestStatus = "failed"
	TestOffline    TestStatus = "offline"
)

// Protocol values accepted by the HTTP measurement.
const (
	ProtocolHTTP  = "HTTP"
	ProtocolHTTPS = "HTTPS"
	ProtocolHTTP2 = "HTTP2"
)

// HTTPMeasurementRequest describes an HTTP measurement from probes in Russia.
// Zero values select the API defaults.
type HTTPMeasurementRequest struct {
	// Target is a hostname or IP address, without scheme, port or path.
	Target string
	// Limit is the maximum number of probes: 1..50 without a token, up to
	// 500 with one. Zero means 1.
	Limit int
	// Protocol is ProtocolHTTP, ProtocolHTTPS (API default) or ProtocolHTTP2.
	Protocol string
	// Port is 1..65535; zero uses 443 for HTTPS/HTTP2 and 80 for HTTP.
	Port int
	// IPVersion is 4 or 6 and is only valid for hostname targets.
	IPVersion int
	// Method is HEAD (API default), GET or OPTIONS.
	Method string
	// Path must start with "/" when set; Query is without the leading "?".
	Path  string
	Query string
	// Host overrides the Host header sent by the probe.
	Host string
}

// CreatedMeasurement is the accepted (202) response to a create request.
type CreatedMeasurement struct {
	ID          string
	ProbesCount int
	// Location is the measurement URL from the Location header, validated
	// to point at the configured API origin and the returned ID.
	Location  string
	RateLimit RateLimit
}

// Measurement is a measurement state with HTTP results.
type Measurement struct {
	ID          string
	Target      string
	Status      MeasurementStatus
	CreatedAt   time.Time
	UpdatedAt   time.Time
	ProbesCount int
	Results     []Result
}

// Result is one probe's test.
type Result struct {
	Probe Probe
	HTTP  HTTPResult
}

// Probe is the location metadata of the probe that ran the test.
type Probe struct {
	Continent string
	Region    string
	Country   string
	State     string // empty outside countries with states
	City      string
	ASN       int
	Network   string
	Latitude  float64
	Longitude float64
	Tags      []string
}

// HTTPResult is the typed HTTP test result. Raw output, raw headers, raw
// body and parsed response headers are intentionally not exposed.
type HTTPResult struct {
	Status TestStatus
	// FailureSource is "target", "resolver" or "internal" for failed tests
	// when the API reports it.
	FailureSource string
	// The fields below are set only for finished tests.
	StatusCode      int
	StatusCodeName  string
	ResolvedAddress string
	Truncated       bool
	Timings         *HTTPTimings
	TLS             *TLSInfo // nil for plain HTTP or when no certificate is available
}

// HTTPTimings are the probe-side request phases.
type HTTPTimings struct {
	Total     time.Duration
	DNS       *time.Duration // nil when the target is an IP address
	TCP       time.Duration
	TLS       *time.Duration // nil for plain HTTP
	FirstByte time.Duration
	Download  time.Duration
}

// TLSInfo is the certificate metadata observed by the probe.
type TLSInfo struct {
	Protocol       string
	CipherName     string
	Authorized     bool
	Error          string // reason when Authorized is false
	CreatedAt      time.Time
	ExpiresAt      time.Time
	SubjectCN      string
	SubjectAlt     string
	IssuerC        string
	IssuerO        string
	IssuerCN       string
	KeyType        string
	KeyBits        int
	SerialNumber   string
	Fingerprint256 string
}
