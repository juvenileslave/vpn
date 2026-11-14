package probe

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// PinnedCoreVersion is the accepted immutable profiles runtime, not a download instruction.
const PinnedCoreVersion = "26.11.9"

const (
	StageAuth          Stage = "auth"
	StageTransferSmall Stage = "transfer_small"
	StageThroughput    Stage = "throughput"
	StageControlTLS    Stage = "control_tls"
	SmallBytes               = 1 << 20
	LargeBytes               = 20 << 20
)

const (
	OutcomeSkipped           Outcome = "skipped"
	OutcomeSizeMismatch      Outcome = "size_mismatch"
	OutcomeIntegrityMismatch Outcome = "integrity_mismatch"
	OutcomeCoverMismatch     Outcome = "cover_mismatch"
	OutcomeAuthFailed        Outcome = "auth_failed"
)

var ladderStages = [...]Stage{StageTCP, StageTLS, StageAuth, StageTransferSmall, StageThroughput}

var (
	labelPattern  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]{0,61}[A-Za-z0-9])?$`)
	digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	namePattern   = regexp.MustCompile(`(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

// Vantage labels a declared actual network. Different names in the same Network
// are not independent controls. Kind is in_country, outside or local_dc.
type Vantage struct {
	Name    string `json:"name"`
	Network string `json:"network"`
	Kind    string `json:"kind"`
}

// Budgets includes setup and each one-shot stage under Overall. Persistence and
// owned-process cleanup have separate, bounded local budgets, never network retries.
type Budgets struct {
	Overall time.Duration `json:"overall_ns"`
	Setup   time.Duration `json:"setup_ns"`
	TCP     time.Duration `json:"tcp_ns"`
	TLS     time.Duration `json:"tls_ns"`
	Auth    time.Duration `json:"auth_ns"`
	Small   time.Duration `json:"small_ns"`
	Large   time.Duration `json:"large_ns"`
	Control time.Duration `json:"control_ns"`
}

// Endpoint is an explicit HTTP representation reached through VLESS, not DNS.
// SHA256 and Bytes are required expectations; URLs never appear in reports.
type Endpoint struct {
	Address netip.Addr `json:"address"`
	Port    uint16     `json:"port"`
	URL     string     `json:"url"`
	Bytes   int64      `json:"bytes"`
	SHA256  string     `json:"sha256"`
}

type Endpoints struct {
	Auth  Endpoint `json:"auth"`
	Small Endpoint `json:"small"`
	Large Endpoint `json:"large"`
}

// LadderRequest consumes a client produced by the accepted profiles renderer.
// Only its local listener, literal node address and logging are adapted in a
// private copy; no credentials, transport policy or server bundle are rendered here.
type LadderRequest struct {
	Node              string
	Target            Target
	ServerName        string
	ControlServerName string
	CoverIssuerSHA256 string
	RootCAs           *x509.CertPool
	ProfileFile       string
	ProfileAddress    netip.Addr
	XrayPath          string
	Vantage           Vantage
	Budgets           Budgets
	Endpoints         Endpoints
	ThroughputFloor   int64
}

// Event contains only bounded facts. ErrorCode is authored, never a socket,
// certificate, HTTP, process or filesystem error string.
type Event struct {
	Target        string        `json:"target"`
	Vantage       Vantage       `json:"vantage"`
	Family        Family        `json:"family"`
	Scope         string        `json:"scope"`
	Stage         Stage         `json:"stage"`
	Outcome       Outcome       `json:"outcome"`
	ErrorCode     string        `json:"error_code"`
	ObservedAt    time.Time     `json:"observed_at"`
	Duration      time.Duration `json:"duration_ns"`
	BodyDuration  time.Duration `json:"body_duration_ns"`
	Bytes         int64         `json:"bytes"`
	ExpectedBytes int64         `json:"expected_bytes"`
	TimeBudget    time.Duration `json:"time_budget_ns"`
	Integrity     bool          `json:"integrity_verified"`
	Certificate   *Certificate  `json:"certificate,omitempty"`
}

// RunReport describes an entire attempt, including explicitly skipped stages.
// Identities bind comparisons without retaining addresses, names or endpoints.
type RunReport struct {
	Schema           int     `json:"schema"`
	RunID            string  `json:"run_id"`
	Target           string  `json:"target"`
	Family           Family  `json:"family"`
	Vantage          Vantage `json:"vantage"`
	EndpointIdentity string  `json:"endpoint_identity"`
	ConfigIdentity   string  `json:"config_identity"`
	SNIIdentity      string  `json:"sni_identity"`
	ControlIdentity  string  `json:"control_identity"`
	CoreVersion      string  `json:"core_version"`
	Budgets          Budgets `json:"budgets"`
	ThroughputFloor  int64   `json:"throughput_floor_bytes_s"`
	Complete         bool    `json:"complete"`
	Outcome          string  `json:"outcome"`
	ErrorCode        string  `json:"error_code"`
	Events           []Event `json:"events"`
	Persisted        bool    `json:"persisted"`
}

// codedError is an authored, secret-safe probe failure. Callers classify it by
// code through Code or errors.Is, never by matching the message text.
type codedError struct{ code string }

func (e codedError) Error() string { return "probe: " + e.code }

// Is lets errors.Is match another authored error with the same code, including
// the sentinels below, without exposing the code as a string comparison.
func (e codedError) Is(target error) bool {
	other, ok := target.(codedError)
	return ok && other.code == e.code
}

func shortError(code string) error { return codedError{code: code} }

// Authored cleanup failures are checked with errors.Is by callers that must not
// mistake them for a core startup failure.
var (
	errPrivateCleanupFailed = shortError("private_cleanup_failed")
	errXrayCleanupFailed    = shortError("xray_cleanup_failed")
)

// Code returns the authored code of a probe failure. It reports false for any
// error that did not originate from shortError, so callers never print an
// arbitrary error message.
func Code(err error) (string, bool) {
	var coded codedError
	if errors.As(err, &coded) {
		return coded.code, true
	}
	return "", false
}

func identity(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func (r LadderRequest) identities() (endpoint, config, sni string) {
	endpoint = identity(netip.AddrPortFrom(r.Target.Address, r.Target.Port).String())
	// NUL-separated, validated fields bind the measurement contract, not secrets.
	parts := []string{endpoint, r.ServerName, r.CoverIssuerSHA256, strconv.FormatInt(r.ThroughputFloor, 10)}
	for _, value := range []Endpoint{r.Endpoints.Auth, r.Endpoints.Small, r.Endpoints.Large} {
		parts = append(parts, netip.AddrPortFrom(value.Address, value.Port).String(), value.URL,
			strconv.FormatInt(value.Bytes, 10), value.SHA256)
	}
	return endpoint, identity(strings.Join(parts, "\x00")), identity(r.ServerName)
}

func (v Vantage) valid() bool {
	if !labelPattern.MatchString(v.Name) || !labelPattern.MatchString(v.Network) {
		return false
	}
	return v.Kind == "in_country" || v.Kind == "outside" || v.Kind == "local_dc"
}

func (b Budgets) validate() error {
	if b.Overall <= 0 || b.Overall > 5*time.Minute {
		return shortError("invalid_budgets")
	}
	for _, budget := range []time.Duration{b.Setup, b.TCP, b.TLS, b.Auth, b.Small, b.Large, b.Control} {
		if budget <= 0 || budget > b.Overall {
			return shortError("invalid_budgets")
		}
	}
	return nil
}

func (e Endpoint) validate() error {
	u, err := url.Parse(e.URL)
	if err != nil || u == nil {
		return shortError("invalid_endpoint")
	}
	unsafeURL := u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != ""
	validScheme := u.Scheme == "http" || u.Scheme == "https"
	if unsafeURL || !validScheme || u.Hostname() == "" || !digestPattern.MatchString(e.SHA256) {
		return shortError("invalid_endpoint")
	}
	if e.Bytes <= 0 || e.Bytes > LargeBytes || !e.Address.IsValid() || e.Address.Zone() != "" ||
		e.Address.Is4In6() || e.Address.IsUnspecified() || e.Address.IsMulticast() || e.Port == 0 {
		return shortError("invalid_endpoint")
	}
	return nil
}

func (r LadderRequest) validate() error {
	_, sniIPError := netip.ParseAddr(r.ServerName)
	if !labelPattern.MatchString(r.Node) || !r.Vantage.valid() || !namePattern.MatchString(r.ServerName) ||
		len(r.ServerName) > 253 || r.Target.SourceIP.IsValid() || sniIPError == nil {
		return shortError("invalid_request")
	}
	if r.ControlServerName != "" && (!namePattern.MatchString(r.ControlServerName) ||
		len(r.ControlServerName) > 253 || r.ControlServerName == r.ServerName) {
		return shortError("invalid_control_sni")
	}
	if r.ControlServerName != "" {
		if _, err := netip.ParseAddr(r.ControlServerName); err == nil {
			return shortError("invalid_control_sni")
		}
	}
	if r.CoverIssuerSHA256 != "" && !digestPattern.MatchString(r.CoverIssuerSHA256) {
		return shortError("invalid_cover_identity")
	}
	if err := r.Target.validate(); err != nil {
		return shortError("invalid_target")
	}
	if err := r.Budgets.validate(); err != nil {
		return err
	}
	for _, endpoint := range []Endpoint{r.Endpoints.Auth, r.Endpoints.Small, r.Endpoints.Large} {
		if err := endpoint.validate(); err != nil {
			return err
		}
	}
	if r.Endpoints.Auth.Bytes > 16<<10 || r.Endpoints.Small.Bytes != SmallBytes ||
		r.Endpoints.Large.Bytes != LargeBytes || r.ThroughputFloor <= 0 || r.ThroughputFloor > 1_000_000_000_000 {
		return shortError("invalid_transfer_contract")
	}
	return nil
}
