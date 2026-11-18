// Package entrance evaluates accepted probe-ladder evidence as a three-valued
// entrance acceptance gate and describes an offline entrance-rotation plan.
//
// The package performs no network, provider, DNS, panel or publication action.
// It consumes only recorded ladder observations and turns them into a decision
// that an accepted publication path can consult: a profile is usable only for
// a clean entrance proven from at least two independent declared in-country
// vantage points. A datacenter, local or outside success never counts as an
// in-country (Wi-Fi/mobile) success, and absent or contradictory evidence is
// unknown, never ok.
package entrance

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/juvenileslave/vpn/vpnctl/internal/probe"
)

// State is the three-valued entrance acceptance result.
type State string

// Gate states. Only StateClean makes a profile usable.
const (
	StateClean   State = "clean"
	StateFailed  State = "failed"
	StateUnknown State = "unknown"
)

// FailureClass separates an entrance block from a tunnel/exit fault and from a
// probe/client-side failure. It is empty for a clean or merely insufficient gate.
type FailureClass string

// Failure classes.
const (
	FailureNone     FailureClass = ""
	FailureEntrance FailureClass = "entrance"
	FailureExit     FailureClass = "exit"
	FailureClient   FailureClass = "client"
)

// Authored, secret-safe reason codes. They never contain addresses, names,
// URLs, certificate text or provider messages.
const (
	// ReasonCleanEntrance marks a gate that accepted the entrance.
	ReasonCleanEntrance = "clean_entrance"
	// ReasonEntranceTCP means the TCP connect stage failed before TLS.
	ReasonEntranceTCP = "entrance_tcp"
	// ReasonEntranceSNI means TCP succeeded but the declared-SNI TLS stage did
	// not complete (timeout, handshake failure or early close).
	ReasonEntranceSNI = "entrance_sni"
	// ReasonEntranceCertificate means the declared-SNI TLS stage completed
	// with a certificate verification failure. It is an entrance failure but
	// not proof of filtering.
	ReasonEntranceCertificate = "entrance_certificate"
	// ReasonEntranceCover means the verified certificate issuer differs from
	// the declared cover identity.
	ReasonEntranceCover = "entrance_cover"
	// ReasonEntranceReality means REALITY/VLESS/XHTTP authentication or the
	// first authenticated request failed after TCP and TLS succeeded.
	ReasonEntranceReality = "entrance_reality"
	// ReasonExitTransfer means the entrance stages succeeded but the bounded
	// 1 MiB transfer through the tunnel failed or failed integrity.
	ReasonExitTransfer = "exit_transfer"
	// ReasonExitThroughput means the entrance and 1 MiB transfer succeeded but
	// the 20 MiB measurement failed.
	ReasonExitThroughput = "exit_throughput"
	// ReasonClientFailure means the recorded attempt failed locally (canceled,
	// invalid request, unavailable source, pinned-core/setup failure), so it
	// proves nothing about the entrance.
	ReasonClientFailure = "client_failure"
	// ReasonInsufficientEvidence means at least one declared in-country
	// vantage lacks fresh, complete, non-contradictory accepted evidence.
	ReasonInsufficientEvidence = "insufficient_evidence"
	// ReasonNoRUVantage means no declared in-country vantage exists; datacenter
	// or local evidence alone can never produce a clean gate.
	ReasonNoRUVantage = "no_ru_vantage"
	// ReasonIndependentVantage means fewer than two independent in-country
	// networks have clean accepted evidence.
	ReasonIndependentVantage = "independent_vantage"
	// ReasonUncorroboratedFailure means an in-country vantage observed an
	// entrance or exit failure, but fewer than two independent in-country
	// networks carry fresh accepted evidence, so the gate cannot attribute the
	// failure to the entrance.
	ReasonUncorroboratedFailure = "uncorroborated_failure"
	// ReasonContradictoryEvidence means two fresh accepted runs for one vantage
	// disagree on stage outcomes or a run is dated in the future.
	ReasonContradictoryEvidence = "contradictory_evidence"
	// ReasonInvalidEvidencePlan means the comparison plan itself is malformed.
	ReasonInvalidEvidencePlan = "invalid_evidence_plan"
)

// RequiredIndependentVantages is the number of independent declared in-country
// networks a clean gate requires.
const RequiredIndependentVantages = 2

// Scope describes exactly which recorded evidence window and declared vantage
// points the gate evaluated. It contains labels and opaque plan identities
// only, never addresses or names.
type Scope struct {
	Target                string          `json:"target"`
	Family                probe.Family    `json:"family"`
	From                  time.Time       `json:"from"`
	To                    time.Time       `json:"to"`
	Vantages              []probe.Vantage `json:"vantages"`
	RUVantages            []string        `json:"ru_vantages"`
	IndependentRUNetworks int             `json:"independent_ru_networks"`
	RequiredRUVantages    int             `json:"required_ru_vantages"`
	RUVantageVerified     bool            `json:"ru_vantage_verified"`
	QueryTruncated        bool            `json:"query_truncated"`
}

// VantageResult is the per-vantage contribution to the gate. A missing or
// unusable vantage is StateUnknown with a short reason code. Stages lists the
// bounded recorded facts the decision used.
type VantageResult struct {
	Vantage      probe.Vantage `json:"vantage"`
	State        State         `json:"state"`
	FailureClass FailureClass  `json:"failure_class,omitempty"`
	FailureCode  string        `json:"failure_code,omitempty"`
	ObservedAt   time.Time     `json:"observed_at,omitempty"`
	Stages       []StageResult `json:"stages"`
}

// StageResult is one accepted ladder stage reduced to bounded, secret-free
// facts. It carries no addresses, names, URLs or certificate bytes.
type StageResult struct {
	Stage         probe.Stage   `json:"stage"`
	Outcome       probe.Outcome `json:"outcome"`
	ErrorCode     string        `json:"error_code,omitempty"`
	Bytes         int64         `json:"bytes"`
	ExpectedBytes int64         `json:"expected_bytes"`
	Duration      time.Duration `json:"duration_ns"`
}

// Gate is the pure entrance acceptance decision. Usable is true only for a
// clean entrance; every failed or unknown gate leaves publication closed.
type Gate struct {
	Schema          int             `json:"schema"`
	Target          string          `json:"target"`
	Family          probe.Family    `json:"family"`
	State           State           `json:"state"`
	Usable          bool            `json:"usable"`
	Reason          string          `json:"reason"`
	FailureClass    FailureClass    `json:"failure_class,omitempty"`
	FailureCode     string          `json:"failure_code,omitempty"`
	Scope           Scope           `json:"scope"`
	Vantages        []VantageResult `json:"vantages"`
	MissingEvidence []string        `json:"missing_evidence"`
	EvaluatedAt     time.Time       `json:"evaluated_at"`
}

var (
	labelPattern  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]{0,61}[A-Za-z0-9])?$`)
	printPattern  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9_-]{0,61}[A-Za-z0-9])?$`)
	digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

var entranceStages = [...]probe.Stage{
	probe.StageTCP, probe.StageTLS, probe.StageAuth, probe.StageTransferSmall, probe.StageThroughput,
}

// clientCodes are authored ladder codes produced by local setup/cleanup rather
// than by the remote path.
var clientCodes = map[string]bool{
	"xray_start_failed":   true,
	"cleanup_failed":      true,
	"run_identity_failed": true,
	"profile_invalid":     true,
}

type vantageEvidence struct {
	seen      bool
	at        time.Time
	stages    map[probe.Stage]probe.Event
	accepted  bool
	client    bool
	invalid   string
	invalidAt time.Time
	conflict  bool
	signature string
}

// Evaluate turns recorded ladder attempts into an entrance decision. It is
// pure: no network, clock, environment, store or provider access. Reports that
// do not match the plan's target, family, opaque identities and throughput
// contract are ignored; only the newest accepted run per declared vantage is
// classified. An in-country failure must be corroborated by fresh accepted
// evidence from at least two independent in-country networks, otherwise the
// gate is unknown rather than failed. Entrance failure dominates exit failure,
// missing evidence yields unknown, and only complete clean evidence from at
// least two independent in-country networks yields a usable gate.
func Evaluate(plan probe.DiagnosisPlan, reports []probe.RunReport) Gate {
	gate := Gate{
		Schema: 1, Target: plan.Target, Family: plan.Family, EvaluatedAt: plan.Now,
		State: StateUnknown, Usable: false, Reason: ReasonInsufficientEvidence,
		Scope: Scope{Target: plan.Target, Family: plan.Family,
			Vantages: make([]probe.Vantage, 0), RUVantages: make([]string, 0),
			RequiredRUVantages: RequiredIndependentVantages, QueryTruncated: plan.QueryTruncated},
		Vantages: make([]VantageResult, 0), MissingEvidence: make([]string, 0),
	}
	missing := func(code string) { gate.MissingEvidence = append(gate.MissingEvidence, code) }
	unknown := func(code string) Gate {
		gate.State, gate.Usable, gate.Reason = StateUnknown, false, code
		return gate
	}
	if !validPlan(plan) {
		missing(ReasonInvalidEvidencePlan)
		return unknown(ReasonInvalidEvidencePlan)
	}
	gate.Scope.From = plan.Now.Add(-plan.Window)
	gate.Scope.To = plan.Now
	// Truncation drops only the oldest stored rows. The newest run for every
	// vantage is still present, so it is a diagnostic and never replaces a
	// fresh complete evaluation with a permanent unknown.

	declared := make(map[string]probe.Vantage, len(plan.Vantages))
	ruOrder := make([]string, 0, len(plan.Vantages))
	ruNetworks := make(map[string]bool)
	for _, vantage := range plan.Vantages {
		declared[vantage.Name] = vantage
		gate.Scope.Vantages = append(gate.Scope.Vantages, vantage)
		if vantage.Kind == "in_country" {
			ruOrder = append(ruOrder, vantage.Name)
			gate.Scope.RUVantages = append(gate.Scope.RUVantages, vantage.Name)
			ruNetworks[vantage.Network] = true
		}
	}
	gate.Scope.IndependentRUNetworks = len(ruNetworks)

	evidence := make(map[string]*vantageEvidence, len(plan.Vantages))
	signatures := make(map[string]map[string]bool, len(plan.Vantages))
	for _, report := range reports {
		vantage, wanted := declared[report.Vantage.Name]
		if !wanted || report.Vantage != vantage || report.Target != plan.Target ||
			report.Family != plan.Family || report.EndpointIdentity != plan.EndpointIdentity ||
			report.ConfigIdentity != plan.ConfigIdentity || report.SNIIdentity != plan.SNIIdentity ||
			report.ThroughputFloor != plan.ThroughputFloor {
			continue
		}
		state := evidence[vantage.Name]
		if state == nil {
			state = &vantageEvidence{}
			evidence[vantage.Name] = state
			signatures[vantage.Name] = make(map[string]bool, 1)
		}
		state.seen = true
		at := runTime(report)
		if at.Before(gate.Scope.From) {
			continue
		}
		stages, accepted := report.AcceptedStages()
		if at.After(plan.Now) {
			state.invalid, state.invalidAt = ReasonContradictoryEvidence, at
			continue
		}
		if accepted {
			for _, event := range stages {
				if event.ObservedAt.Before(gate.Scope.From) || event.ObservedAt.Add(event.Duration).After(plan.Now) {
					accepted = false
				}
			}
		}
		if !accepted {
			if clientEvidence(report) {
				state.client = true
			} else if !state.accepted || at.After(state.at) {
				state.invalid, state.invalidAt = ReasonInsufficientEvidence, at
			}
			continue
		}
		signature := signatureOf(stages)
		if len(signatures[vantage.Name]) > 0 && !signatures[vantage.Name][signature] {
			state.conflict = true
		}
		signatures[vantage.Name][signature] = true
		if !state.accepted || at.After(state.at) {
			state.at, state.stages, state.accepted, state.signature = at, stages, true, signature
			if state.invalid != "" && !at.Before(state.invalidAt) {
				state.invalid = ""
			}
		}
	}

	ruFailure := "" // first declared in-country failure code
	ruFailureClass := FailureNone
	clientFailure := false
	contradictory := false
	missingEvidence := false
	cleanNetworks := make(map[string]bool)
	// observedNetworks counts in-country networks with a conclusive accepted
	// result (clean or failed). A client-side result proves nothing about the
	// entrance and never corroborates a failure.
	observedNetworks := make(map[string]bool)

	for _, vantage := range plan.Vantages {
		state := evidence[vantage.Name]
		result := VantageResult{Vantage: vantage, State: StateUnknown, Stages: make([]StageResult, 0, len(entranceStages))}
		inCountry := vantage.Kind == "in_country"
		switch {
		case state == nil || !state.seen:
			result.FailureCode = ReasonInsufficientEvidence
			if inCountry {
				missingEvidence = true
				missing("fresh_complete_vantage:" + vantage.Name)
			}
		case state.conflict:
			result.FailureCode = ReasonContradictoryEvidence
			if inCountry {
				contradictory = true
				missing(ReasonContradictoryEvidence + ":" + vantage.Name)
			}
		case state.client:
			result.FailureClass = FailureClient
			result.FailureCode = ReasonClientFailure
			if inCountry {
				clientFailure = true
				missing(ReasonClientFailure + ":" + vantage.Name)
			}
		case state.invalid != "":
			result.FailureCode = state.invalid
			if inCountry {
				missingEvidence = true
				missing("invalid_evidence:" + vantage.Name)
			}
		case state.accepted:
			result.State, result.FailureClass, result.FailureCode = classify(state.stages)
			result.ObservedAt = state.at
			result.Stages = stageResults(state.stages)
			if result.State == StateFailed && ruFailure == "" && inCountry {
				ruFailure, ruFailureClass = result.FailureCode, result.FailureClass
			} else if result.State == StateFailed && inCountry && ruFailureClass == FailureExit &&
				result.FailureClass == FailureEntrance {
				ruFailure, ruFailureClass = result.FailureCode, result.FailureClass
			}
			if result.FailureClass == FailureClient && inCountry {
				clientFailure = true
				missing(ReasonClientFailure + ":" + vantage.Name)
			} else if inCountry && result.State != StateUnknown {
				observedNetworks[vantage.Network] = true
			}
			if result.State == StateClean && inCountry {
				cleanNetworks[vantage.Network] = true
			}
		default:
			// Fresh evidence exists only outside the window.
			result.FailureCode = ReasonInsufficientEvidence
			if inCountry {
				missingEvidence = true
				missing("fresh_complete_vantage:" + vantage.Name)
			}
		}
		gate.Vantages = append(gate.Vantages, result)
	}

	switch {
	case ruFailure != "" && len(observedNetworks) >= RequiredIndependentVantages:
		gate.State, gate.Usable, gate.Reason = StateFailed, false, ruFailure
		gate.FailureClass, gate.FailureCode = ruFailureClass, ruFailure
		return gate
	case contradictory:
		return unknown(ReasonContradictoryEvidence)
	case clientFailure:
		gate.State, gate.Usable, gate.Reason = StateUnknown, false, ReasonClientFailure
		gate.FailureClass, gate.FailureCode = FailureClient, ReasonClientFailure
		return gate
	case len(ruOrder) == 0:
		missing(ReasonNoRUVantage)
		return unknown(ReasonNoRUVantage)
	case missingEvidence:
		return unknown(ReasonInsufficientEvidence)
	case ruFailure != "":
		missing(ReasonUncorroboratedFailure)
		return unknown(ReasonUncorroboratedFailure)
	case len(cleanNetworks) < RequiredIndependentVantages:
		missing(ReasonIndependentVantage)
		return unknown(ReasonIndependentVantage)
	}

	gate.State, gate.Usable, gate.Reason = StateClean, true, ReasonCleanEntrance
	gate.Scope.RUVantageVerified = true
	return gate
}

// validPlan rejects a malformed comparison plan without touching any store.
func validPlan(plan probe.DiagnosisPlan) bool {
	if !labelPattern.MatchString(plan.Target) || !printPattern.MatchString(plan.Target) ||
		(plan.Family != probe.IPv4 && plan.Family != probe.IPv6) ||
		!digestPattern.MatchString(plan.EndpointIdentity) || !digestPattern.MatchString(plan.ConfigIdentity) ||
		!digestPattern.MatchString(plan.SNIIdentity) || plan.Now.IsZero() ||
		plan.Window <= 0 || plan.Window > 30*time.Minute || plan.ThroughputFloor <= 0 ||
		len(plan.Vantages) == 0 || len(plan.Vantages) > 16 {
		return false
	}
	seen := make(map[string]bool)
	for _, vantage := range plan.Vantages {
		// Labels are echoed verbatim. Refuse dotted labels so an operator
		// cannot accidentally print an IPv4 address or DNS name as a label.
		if !vantage.Valid() || !printPattern.MatchString(vantage.Name) ||
			!printPattern.MatchString(vantage.Network) || seen[vantage.Name] {
			return false
		}
		seen[vantage.Name] = true
	}
	return true
}

// classify maps a complete accepted ladder attempt to an entrance state. The
// ladder stops at the first failing stage, so the first non-success stage in
// acceptance order is the observed failure.
func classify(stages map[probe.Stage]probe.Event) (State, FailureClass, string) {
	for _, stage := range entranceStages {
		event, exists := stages[stage]
		if !exists || event.Outcome == probe.OutcomeSuccess {
			continue
		}
		switch event.Outcome {
		case probe.OutcomeCanceled, probe.OutcomeInvalidRequest, probe.OutcomeSourceUnavailable:
			return StateUnknown, FailureClient, ReasonClientFailure
		}
		if clientCodes[event.ErrorCode] {
			return StateUnknown, FailureClient, ReasonClientFailure
		}
		switch stage {
		case probe.StageTCP:
			return StateFailed, FailureEntrance, ReasonEntranceTCP
		case probe.StageTLS:
			switch event.Outcome {
			case probe.OutcomeCertificateUntrusted, probe.OutcomeHostnameMismatch, probe.OutcomeCertificateInvalid:
				return StateFailed, FailureEntrance, ReasonEntranceCertificate
			case probe.OutcomeCoverMismatch:
				return StateFailed, FailureEntrance, ReasonEntranceCover
			}
			return StateFailed, FailureEntrance, ReasonEntranceSNI
		case probe.StageAuth:
			return StateFailed, FailureEntrance, ReasonEntranceReality
		case probe.StageTransferSmall:
			return StateFailed, FailureExit, ReasonExitTransfer
		case probe.StageThroughput:
			return StateFailed, FailureExit, ReasonExitThroughput
		}
	}
	return StateClean, FailureNone, ""
}

// stageResults reduces the accepted stage set to ordered bounded facts.
func stageResults(stages map[probe.Stage]probe.Event) []StageResult {
	results := make([]StageResult, 0, len(entranceStages))
	for _, stage := range entranceStages {
		event := stages[stage]
		results = append(results, StageResult{
			Stage: stage, Outcome: event.Outcome, ErrorCode: event.ErrorCode,
			Bytes: event.Bytes, ExpectedBytes: event.ExpectedBytes, Duration: event.Duration,
		})
	}
	return results
}

// clientEvidence reports whether a non-accepted attempt failed locally rather
// than on the measured path.
func clientEvidence(report probe.RunReport) bool {
	for _, event := range report.Events {
		switch event.Outcome {
		case probe.OutcomeCanceled, probe.OutcomeInvalidRequest, probe.OutcomeSourceUnavailable:
			return true
		}
		if clientCodes[event.ErrorCode] {
			return true
		}
	}
	return false
}

// runTime is the end of the newest recorded stage.
func runTime(report probe.RunReport) time.Time {
	var newest time.Time
	for _, event := range report.Events {
		if end := event.ObservedAt.Add(event.Duration); end.After(newest) {
			newest = end
		}
	}
	return newest
}

// signatureOf keeps only stable outcome classes, so ordinary timing variation
// does not look like contradictory evidence.
func signatureOf(stages map[probe.Stage]probe.Event) string {
	parts := make([]string, 0, len(stages))
	for stage, event := range stages {
		parts = append(parts, string(stage)+":"+string(event.Outcome)+":"+event.ErrorCode)
	}
	sort.Strings(parts)
	return strings.Join(parts, ";")
}

// DigestIdentity is the opaque identity of an operator label, used by the
// rotation plan so that no address or hostname reaches output or the store.
func DigestIdentity(label string) string {
	digest := sha256.Sum256([]byte(label))
	return hex.EncodeToString(digest[:])
}
