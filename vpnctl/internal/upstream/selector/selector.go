package selector

import (
	"time"

	"github.com/juvenileslave/vpn/vpnctl/internal/upstream/candidate"
)

// Filter is the per-source selection filter.
type Filter struct {
	Countries           []string      // ISO 3166-1 alpha-2 uppercase; empty = any
	MaxLatency          time.Duration // 0 = no bound
	MinSuccessfulProbes int           // 0 is treated as 1
}

// Probe is one bounded probe observation for a candidate.
type Probe struct {
	Outcome string        // "success" | "failure" | "timeout"
	Latency time.Duration // meaningful for success
	Country string        // observed country; "" = unknown
}

// Input pairs a parsed candidate with its probes (in observation order).
type Input struct {
	Candidate candidate.Candidate
	Probes    []Probe
}

// Reason values for a decision.
const (
	ReasonSelected     = "selected"
	ReasonNoCandidates = "no_candidates"
	ReasonNoHealthy    = "no_healthy"
	ReasonFiltered     = "filtered"
)

// Decision is the deterministic selection result. Candidate is nil when the
// slot must render a blackhole outbound; Blackhole is then true.
type Decision struct {
	Candidate *candidate.Candidate
	Reason    string
	Blackhole bool
}

// Select chooses at most one healthy, eligible candidate for a fixed slot.
//
// Tie-break: among eligible candidates, Select chooses the one with the
// smallest minimum success latency; on a latency tie, it chooses the
// lexicographically smaller Candidate.ID so selection is independent of
// input order.
func Select(inputs []Input, filter Filter) Decision {
	if len(inputs) == 0 {
		return Decision{Reason: ReasonNoCandidates, Blackhole: true}
	}

	minProbes := filter.MinSuccessfulProbes
	if minProbes < 1 {
		minProbes = 1
	}

	var allowedCountries map[string]struct{}
	if len(filter.Countries) > 0 {
		allowedCountries = make(map[string]struct{}, len(filter.Countries))
		for _, c := range filter.Countries {
			if c == "" {
				continue
			}
			allowedCountries[c] = struct{}{}
		}
	}

	anyHealthy := false
	hasBest := false
	var bestCandidate candidate.Candidate
	var bestLatency time.Duration

	for _, in := range inputs {
		successCount := 0
		hasNegativeLatency := false
		var minLatency time.Duration
		var observedCountry string

		for _, p := range in.Probes {
			if p.Outcome != "success" {
				continue
			}
			if p.Latency < 0 {
				hasNegativeLatency = true
				continue
			}
			if successCount == 0 || p.Latency < minLatency {
				minLatency = p.Latency
			}
			successCount++
			observedCountry = p.Country
		}

		if hasNegativeLatency || successCount < minProbes {
			continue
		}
		anyHealthy = true

		if filter.MaxLatency != 0 && minLatency > filter.MaxLatency {
			continue
		}

		if len(filter.Countries) > 0 {
			if observedCountry == "" {
				continue
			}
			if _, ok := allowedCountries[observedCountry]; !ok {
				continue
			}
		}

		// Tie-break: smallest minimum success latency wins; equal latencies
		// break ties by lexicographically smaller Candidate.ID.
		if !hasBest || minLatency < bestLatency || (minLatency == bestLatency && in.Candidate.ID < bestCandidate.ID) {
			bestCandidate = in.Candidate
			bestLatency = minLatency
			hasBest = true
		}
	}

	if !anyHealthy {
		return Decision{Reason: ReasonNoHealthy, Blackhole: true}
	}
	if !hasBest {
		return Decision{Reason: ReasonFiltered, Blackhole: true}
	}

	selected := bestCandidate
	return Decision{
		Candidate: &selected,
		Reason:    ReasonSelected,
		Blackhole: false,
	}
}
