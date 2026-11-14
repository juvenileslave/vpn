package probe

import (
	"sort"
	"time"
)

// DiagnosisPlan declares every expected vantage and the exact comparable
// contract. Now is supplied, so classification is deterministic and pure.
type DiagnosisPlan struct {
	Target           string
	Family           Family
	EndpointIdentity string
	ConfigIdentity   string
	SNIIdentity      string
	ControlIdentity  string
	Vantages         []Vantage
	Now              time.Time
	Window           time.Duration
	ThroughputFloor  int64
	QueryTruncated   bool
}

type Scope struct {
	Target   string    `json:"target"`
	Family   Family    `json:"family"`
	Vantages []Vantage `json:"vantages"`
	From     time.Time `json:"from"`
	To       time.Time `json:"to"`
	Global   bool      `json:"global"`
}

type Measurement struct {
	Vantage        string        `json:"vantage"`
	Stage          Stage         `json:"stage"`
	Bytes          int64         `json:"bytes"`
	Duration       time.Duration `json:"body_duration_ns"`
	BytesPerSecond float64       `json:"bytes_per_second"`
}

// Verdict is a scoped hypothesis, never a claim about a particular censorship
// system and never an instruction to rotate, ban, write or remediate anything.
type Verdict struct {
	Verdict         string        `json:"verdict"`
	Confidence      string        `json:"confidence"`
	Outcome         string        `json:"outcome"`
	MissingEvidence []string      `json:"missing_evidence"`
	Scope           Scope         `json:"scope"`
	Measurements    []Measurement `json:"measurements"`
}

type stageSet map[Stage]Event

// Classify rejects partial, stale, contradictory and single-network evidence.
// Different families, endpoints, SNI, transfer contracts and Globalping HTTP
// observations are never joined into an authorized node-path claim.
func Classify(plan DiagnosisPlan, reports []RunReport) Verdict {
	verdict := Verdict{
		Verdict: "unknown", Confidence: "none", Outcome: "insufficient_evidence",
		MissingEvidence: make([]string, 0), Measurements: make([]Measurement, 0),
		Scope: Scope{Target: plan.Target, Family: plan.Family, Vantages: make([]Vantage, 0),
			From: plan.Now.Add(-plan.Window), To: plan.Now, Global: false},
	}
	missing := func(code string) { verdict.MissingEvidence = append(verdict.MissingEvidence, code) }
	if !labelPattern.MatchString(plan.Target) || (plan.Family != IPv4 && plan.Family != IPv6) ||
		!digestPattern.MatchString(plan.EndpointIdentity) || !digestPattern.MatchString(plan.ConfigIdentity) ||
		!digestPattern.MatchString(plan.SNIIdentity) || plan.Window <= 0 || plan.Window > 30*time.Minute ||
		plan.ThroughputFloor <= 0 || len(plan.Vantages) == 0 || len(plan.Vantages) > 16 {
		missing("invalid_evidence_plan")
		return verdict
	}
	if plan.QueryTruncated {
		missing("query_truncated")
		return verdict
	}
	declared := make(map[string]Vantage, len(plan.Vantages))
	networks := make(map[string]bool, len(plan.Vantages))
	for _, vantage := range plan.Vantages {
		if !vantage.valid() || declared[vantage.Name].Name != "" {
			missing("invalid_vantages")
			return verdict
		}
		declared[vantage.Name] = vantage
		networks[vantage.Network] = true
	}
	if len(networks) < 2 {
		missing("independent_vantage")
	}

	latest := make(map[string]RunReport, len(plan.Vantages))
	sets := make(map[string]stageSet, len(plan.Vantages))
	signatures := make(map[string]string, len(plan.Vantages))
	latestAt := make(map[string]time.Time, len(plan.Vantages))
	invalid := make(map[string]bool)
	conflicts := make(map[string]bool)
	for _, report := range reports {
		if report.Target != plan.Target || report.Family != plan.Family ||
			report.EndpointIdentity != plan.EndpointIdentity || report.ConfigIdentity != plan.ConfigIdentity ||
			report.SNIIdentity != plan.SNIIdentity {
			continue
		}
		vantage, wanted := declared[report.Vantage.Name]
		if !wanted || report.Vantage != vantage {
			continue
		}
		at := runTime(report)
		if at.Before(verdict.Scope.From) {
			continue
		}
		if at.After(plan.Now) {
			invalid[vantage.Name] = true
			continue
		}
		stages, valid := completeStages(report)
		for _, event := range report.Events {
			if event.ObservedAt.Before(verdict.Scope.From) || event.ObservedAt.Add(event.Duration).After(plan.Now) {
				valid = false
			}
		}
		if !valid || report.ThroughputFloor != plan.ThroughputFloor {
			invalid[vantage.Name] = true
			continue
		}
		signature := evidenceSignature(stages, plan.ThroughputFloor)
		if previous, exists := signatures[vantage.Name]; exists && previous != signature {
			conflicts[vantage.Name] = true
		}
		signatures[vantage.Name] = signature
		if previous, exists := latestAt[vantage.Name]; !exists || at.After(previous) {
			latestAt[vantage.Name] = at
			latest[vantage.Name] = report
			sets[vantage.Name] = stages
		}
	}
	for _, vantage := range plan.Vantages {
		if invalid[vantage.Name] {
			missing("partial_or_invalid:" + vantage.Name)
		}
		if conflicts[vantage.Name] {
			missing("contradictory_evidence:" + vantage.Name)
		}
		stages, exists := sets[vantage.Name]
		if !exists {
			missing("fresh_complete_vantage:" + vantage.Name)
			continue
		}
		verdict.Scope.Vantages = append(verdict.Scope.Vantages, vantage)
		if event := stages[StageThroughput]; event.BodyDuration > 0 && event.Bytes > 0 {
			verdict.Measurements = append(verdict.Measurements, Measurement{
				Vantage: vantage.Name, Stage: StageThroughput, Bytes: event.Bytes,
				Duration: event.BodyDuration, BytesPerSecond: rate(event),
			})
		}
	}
	if len(verdict.MissingEvidence) > 0 {
		return verdict
	}

	allOutage, hasOutside := true, false
	for _, vantage := range plan.Vantages {
		hasOutside = hasOutside || vantage.Kind == "outside"
		allOutage = allOutage && reachabilityFailure(sets[vantage.Name])
	}
	if allOutage && hasOutside {
		return supported(verdict, "node_outage")
	}

	insideNetworks := make(map[string]bool)
	for _, vantage := range plan.Vantages {
		if vantage.Kind == "in_country" && sets[vantage.Name][StageTCP].Outcome == OutcomeTimeout {
			insideNetworks[vantage.Network] = true
		}
	}
	insideTimeout, outsideReachable, ipCompatible := false, false, true
	for _, vantage := range plan.Vantages {
		stages := sets[vantage.Name]
		if vantage.Kind == "in_country" && stages[StageTCP].Outcome == OutcomeTimeout {
			insideTimeout = true
			continue
		}
		if vantage.Kind == "in_country" && stages[StageTCP].Outcome == OutcomeSuccess {
			ipCompatible = false
		}
		if !healthy(stages) {
			ipCompatible = false
		}
		if vantage.Kind == "outside" && healthy(stages) && !insideNetworks[vantage.Network] {
			outsideReachable = true
		}
	}
	if insideTimeout && outsideReachable && ipCompatible {
		return supported(verdict, "ip_block")
	}

	candidates := make([]string, 0, 3)
	for _, pattern := range []string{"sni_filter", "dpi_stream_stall", "throttling"} {
		found, compatible := false, true
		for _, vantage := range plan.Vantages {
			stages := sets[vantage.Name]
			matches := false
			switch pattern {
			case "sni_filter":
				matches = plan.ControlIdentity != "" && latest[vantage.Name].ControlIdentity == plan.ControlIdentity &&
					sniFailure(stages) && stages[StageControlTLS].Outcome == OutcomeSuccess
			case "dpi_stream_stall":
				matches = streamStall(stages)
			case "throttling":
				matches = healthy(stages) && rate(stages[StageThroughput]) < float64(plan.ThroughputFloor)
			}
			found = found || matches
			compatible = compatible && (matches || healthy(stages))
		}
		if found && compatible {
			candidates = append(candidates, pattern)
		}
	}
	if len(candidates) == 1 {
		return supported(verdict, candidates[0])
	}
	if len(candidates) > 1 {
		missing("contradictory_failure_patterns")
		return verdict
	}
	if !hasOutside {
		missing("outside_reachability_control")
	}
	if insideTimeout && !outsideReachable {
		missing("independent_outside_reachability_control")
	}
	for _, vantage := range plan.Vantages {
		stages := sets[vantage.Name]
		if sniFailure(stages) && (plan.ControlIdentity == "" || latest[vantage.Name].ControlIdentity != plan.ControlIdentity ||
			stages[StageControlTLS].Outcome != OutcomeSuccess) {
			missing("same_address_control_sni:" + vantage.Name)
		}
		if stages[StageAuth].Outcome != OutcomeSuccess {
			missing("authenticated_path:" + vantage.Name)
		}
		if event := stages[StageThroughput]; event.Outcome == OutcomeTimeout && event.Bytes >= 16<<10 && event.Bytes <= 20<<10 {
			missing("measured_stream_close_or_reset:" + vantage.Name)
		}
	}
	if len(verdict.MissingEvidence) == 0 {
		missing("no_supported_failure_pattern")
	}
	return verdict
}

func supported(verdict Verdict, name string) Verdict {
	verdict.Verdict, verdict.Confidence, verdict.Outcome = name, "moderate", "supported"
	return verdict
}

func runTime(report RunReport) time.Time {
	var newest time.Time
	for _, event := range report.Events {
		if end := event.ObservedAt.Add(event.Duration); end.After(newest) {
			newest = end
		}
	}
	return newest
}

func completeStages(report RunReport) (stageSet, bool) {
	stages := make(stageSet, len(report.Events))
	if report.Schema != 1 || !report.Complete || report.RunID == "" || len(report.Events) < 5 || len(report.Events) > 6 {
		return stages, false
	}
	for _, event := range report.Events {
		if event.Target != report.Target || event.Family != report.Family || event.Vantage != report.Vantage ||
			event.ObservedAt.IsZero() || event.Duration < 0 || event.BodyDuration < 0 || event.BodyDuration > event.Duration ||
			event.Bytes < 0 || stages[event.Stage].Stage != "" {
			return stages, false
		}
		if event.Certificate != nil && event.Outcome == OutcomeSuccess &&
			(!event.Certificate.Verified || !event.Certificate.SANMatch) {
			return stages, false
		}
		if event.Stage == StageControlTLS {
			if event.Scope != "same_address_control" || report.ControlIdentity == "" {
				return stages, false
			}
			if event.Bytes != 0 || event.ExpectedBytes != 0 || event.BodyDuration != 0 {
				return stages, false
			}
			if event.Outcome == OutcomeSuccess && (event.ErrorCode != "" || event.Duration <= 0) {
				return stages, false
			}
			if event.Outcome != OutcomeSuccess && event.ErrorCode == "" {
				return stages, false
			}
		} else if event.Scope != "node_path" {
			return stages, false
		}
		if event.Stage != StageControlTLS {
			known := false
			for _, stage := range ladderStages {
				known = known || stage == event.Stage
			}
			if !known {
				return stages, false
			}
		}
		stages[event.Stage] = event
	}
	failed := false
	var previousEnd time.Time
	for _, stage := range ladderStages {
		event, exists := stages[stage]
		if !exists || event.ObservedAt.Before(previousEnd) {
			return stages, false
		}
		previousEnd = event.ObservedAt.Add(event.Duration)
		if failed {
			if event.Outcome != OutcomeSkipped || event.ErrorCode != "stage_not_run" || event.Bytes != 0 || event.Duration != 0 {
				return stages, false
			}
			continue
		}
		if event.Outcome == OutcomeSkipped || event.Outcome == "" {
			return stages, false
		}
		if event.Outcome != OutcomeSuccess {
			if event.ErrorCode == "" || event.Outcome == OutcomeCanceled || event.Outcome == OutcomeInvalidRequest {
				return stages, false
			}
			failed = true
			continue
		}
		if event.ErrorCode != "" {
			return stages, false
		}
		if stage == StageAuth || stage == StageTransferSmall || stage == StageThroughput {
			expected := event.ExpectedBytes
			if stage == StageAuth && (expected <= 0 || expected > 16<<10) {
				return stages, false
			}
			if stage == StageTransferSmall && expected != SmallBytes {
				return stages, false
			}
			if stage == StageThroughput && expected != LargeBytes {
				return stages, false
			}
			if !event.Integrity || event.Bytes != expected || event.Duration <= 0 || event.BodyDuration <= 0 {
				return stages, false
			}
		}
	}
	return stages, true
}

func healthy(stages stageSet) bool {
	for _, stage := range ladderStages {
		if stages[stage].Outcome != OutcomeSuccess {
			return false
		}
	}
	return true
}

func reachabilityFailure(stages stageSet) bool {
	tcp, tls := stages[StageTCP], stages[StageTLS]
	if tcp.Outcome == OutcomeSuccess && stages[StageControlTLS].Outcome == OutcomeSuccess {
		return false
	}
	if tcp.Outcome == OutcomeTimeout || tcp.Outcome == OutcomeRefused {
		return true
	}
	return tcp.Outcome == OutcomeSuccess && (tls.Outcome == OutcomeTimeout || tls.Outcome == OutcomeHandshakeFailed)
}

func sniFailure(stages stageSet) bool {
	tls := stages[StageTLS]
	return stages[StageTCP].Outcome == OutcomeSuccess && (tls.Outcome == OutcomeTimeout || tls.Outcome == OutcomeHandshakeFailed)
}

func streamStall(stages stageSet) bool {
	for _, stage := range ladderStages[:4] {
		if stages[stage].Outcome != OutcomeSuccess {
			return false
		}
	}
	large := stages[StageThroughput]
	closed := large.Outcome == OutcomeEarlyEOF || large.Outcome == OutcomeNetworkError
	return closed && large.ExpectedBytes == LargeBytes && large.Bytes >= 16<<10 && large.Bytes <= 20<<10 && large.BodyDuration > 0
}

func rate(event Event) float64 {
	if event.BodyDuration <= 0 {
		return 0
	}
	return float64(event.Bytes) / event.BodyDuration.Seconds()
}

func evidenceSignature(stages stageSet, floor int64) string {
	// Stable outcome/boundary classes, not fluctuating timestamps or speed values.
	keys := make([]string, 0, len(stages))
	for stage, event := range stages {
		value := string(stage) + ":" + string(event.Outcome) + ":" + event.ErrorCode
		if stage == StageThroughput {
			if streamStall(stages) {
				value += ":boundary"
			}
			if healthy(stages) && rate(event) < float64(floor) {
				value += ":slow"
			}
		}
		keys = append(keys, value)
	}
	sort.Strings(keys)
	var result string
	for _, value := range keys {
		result += value + ";"
	}
	return result
}
