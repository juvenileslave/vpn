package selector

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/juvenileslave/vpn/vpnctl/internal/upstream/candidate"
)

func testCandidate(hexChar, label string) candidate.Candidate {
	return candidate.Candidate{
		ID:       strings.Repeat(hexChar, 64),
		Scheme:   candidate.SchemeVLESS,
		Label:    label,
		Outbound: json.RawMessage(`{}`),
	}
}

func TestSelectSingleHealthy(t *testing.T) {
	c := testCandidate("a", "alpha")
	d := Select([]Input{
		{
			Candidate: c,
			Probes:    []Probe{{Outcome: "success", Latency: 42 * time.Millisecond, Country: "DE"}},
		},
	}, Filter{})

	if d.Blackhole || d.Reason != ReasonSelected || d.Candidate == nil {
		t.Fatalf("got decision %+v, want selected non-blackhole", d)
	}
	if d.Candidate.ID != c.ID || d.Candidate.Label != c.Label {
		t.Fatalf("got candidate %+v, want %+v", *d.Candidate, c)
	}
}

func TestSelectLowestLatencyOrderIndependent(t *testing.T) {
	fast := Input{
		Candidate: testCandidate("b", "fast"),
		Probes: []Probe{
			{Outcome: "failure", Latency: 5 * time.Millisecond, Country: "DE"},
			{Outcome: "success", Latency: 80 * time.Millisecond, Country: "DE"},
			{Outcome: "success", Latency: 25 * time.Millisecond, Country: "DE"},
		},
	}
	slow := Input{
		Candidate: testCandidate("a", "slow"),
		Probes:    []Probe{{Outcome: "success", Latency: 50 * time.Millisecond, Country: "DE"}},
	}

	d1 := Select([]Input{fast, slow}, Filter{})
	d2 := Select([]Input{slow, fast}, Filter{})

	for i, d := range []Decision{d1, d2} {
		if d.Blackhole || d.Reason != ReasonSelected || d.Candidate == nil {
			t.Fatalf("order %d: got %+v, want selected", i, d)
		}
		if d.Candidate.ID != fast.Candidate.ID {
			t.Fatalf("order %d: got ID %s, want %s", i, d.Candidate.ID, fast.Candidate.ID)
		}
	}
}

func TestSelectTieBreakBySmallerID(t *testing.T) {
	low := Input{
		Candidate: testCandidate("1", "low-id"),
		Probes:    []Probe{{Outcome: "success", Latency: 30 * time.Millisecond, Country: "NL"}},
	}
	high := Input{
		Candidate: testCandidate("2", "high-id"),
		Probes:    []Probe{{Outcome: "success", Latency: 30 * time.Millisecond, Country: "NL"}},
	}

	d1 := Select([]Input{low, high}, Filter{})
	d2 := Select([]Input{high, low}, Filter{})

	for i, d := range []Decision{d1, d2} {
		if d.Blackhole || d.Reason != ReasonSelected || d.Candidate == nil {
			t.Fatalf("order %d: got %+v, want selected", i, d)
		}
		if d.Candidate.ID != low.Candidate.ID {
			t.Fatalf("order %d: got ID %s, want %s", i, d.Candidate.ID, low.Candidate.ID)
		}
	}
}

func TestSelectMinSuccessfulProbes(t *testing.T) {
	oneOK := Input{
		Candidate: testCandidate("a", "one-ok"),
		Probes: []Probe{
			{Outcome: "success", Latency: 10 * time.Millisecond, Country: "DE"},
			{Outcome: "timeout", Latency: 0, Country: ""},
		},
	}
	twoOK := Input{
		Candidate: testCandidate("b", "two-ok"),
		Probes: []Probe{
			{Outcome: "success", Latency: 40 * time.Millisecond, Country: "DE"},
			{Outcome: "success", Latency: 60 * time.Millisecond, Country: "DE"},
		},
	}

	// Default 0 is treated as 1.
	dDefault := Select([]Input{oneOK}, Filter{MinSuccessfulProbes: 0})
	if dDefault.Blackhole || dDefault.Reason != ReasonSelected || dDefault.Candidate == nil {
		t.Fatalf("default min probes: got %+v, want selected", dDefault)
	}

	// Requiring 2 excludes a candidate with only 1 success.
	dNotEnough := Select([]Input{oneOK}, Filter{MinSuccessfulProbes: 2})
	if !dNotEnough.Blackhole || dNotEnough.Reason != ReasonNoHealthy || dNotEnough.Candidate != nil {
		t.Fatalf("min probes 2 (insufficient): got %+v, want no_healthy blackhole", dNotEnough)
	}

	dTwo := Select([]Input{oneOK, twoOK}, Filter{MinSuccessfulProbes: 2})
	if dTwo.Blackhole || dTwo.Reason != ReasonSelected || dTwo.Candidate == nil {
		t.Fatalf("min probes 2: got %+v, want selected", dTwo)
	}
	if dTwo.Candidate.ID != twoOK.Candidate.ID {
		t.Fatalf("min probes 2: got ID %s, want %s", dTwo.Candidate.ID, twoOK.Candidate.ID)
	}
}

func TestSelectMaxLatency(t *testing.T) {
	fast := Input{
		Candidate: testCandidate("a", "fast"),
		Probes:    []Probe{{Outcome: "success", Latency: 50 * time.Millisecond, Country: "DE"}},
	}
	slow := Input{
		Candidate: testCandidate("b", "slow"),
		Probes:    []Probe{{Outcome: "success", Latency: 150 * time.Millisecond, Country: "DE"}},
	}

	d := Select([]Input{slow, fast}, Filter{MaxLatency: 100 * time.Millisecond})
	if d.Blackhole || d.Reason != ReasonSelected || d.Candidate == nil {
		t.Fatalf("max latency keep fast: got %+v, want selected", d)
	}
	if d.Candidate.ID != fast.Candidate.ID {
		t.Fatalf("max latency keep fast: got ID %s, want %s", d.Candidate.ID, fast.Candidate.ID)
	}

	dAllFiltered := Select([]Input{slow, fast}, Filter{MaxLatency: 25 * time.Millisecond})
	if !dAllFiltered.Blackhole || dAllFiltered.Reason != ReasonFiltered || dAllFiltered.Candidate != nil {
		t.Fatalf("max latency all excluded: got %+v, want filtered blackhole", dAllFiltered)
	}
}

func TestSelectCountryAllowlist(t *testing.T) {
	unknown := Input{
		Candidate: testCandidate("a", "unknown"),
		Probes:    []Probe{{Outcome: "success", Latency: 10 * time.Millisecond, Country: ""}},
	}
	de := Input{
		Candidate: testCandidate("b", "de"),
		Probes: []Probe{
			{Outcome: "success", Latency: 60 * time.Millisecond, Country: "US"},
			{Outcome: "success", Latency: 50 * time.Millisecond, Country: "DE"},
			{Outcome: "failure", Latency: 5 * time.Millisecond, Country: "FR"},
		},
	}
	us := Input{
		Candidate: testCandidate("c", "us"),
		Probes:    []Probe{{Outcome: "success", Latency: 20 * time.Millisecond, Country: "US"}},
	}

	// Non-empty allowlist selects matching country and ignores faster non-matching/unknown.
	d := Select([]Input{unknown, us, de}, Filter{Countries: []string{"NL", "DE"}})
	if d.Blackhole || d.Reason != ReasonSelected || d.Candidate == nil {
		t.Fatalf("allowlist match: got %+v, want selected", d)
	}
	if d.Candidate.ID != de.Candidate.ID {
		t.Fatalf("allowlist match: got ID %s, want %s", d.Candidate.ID, de.Candidate.ID)
	}

	// Unknown country never matches a non-empty allowlist.
	dUnknown := Select([]Input{unknown}, Filter{Countries: []string{"DE", ""}})
	if !dUnknown.Blackhole || dUnknown.Reason != ReasonFiltered || dUnknown.Candidate != nil {
		t.Fatalf("unknown country excluded: got %+v, want filtered blackhole", dUnknown)
	}

	// Empty allowlist accepts any country including unknown.
	dAny := Select([]Input{unknown, de}, Filter{})
	if dAny.Blackhole || dAny.Reason != ReasonSelected || dAny.Candidate == nil {
		t.Fatalf("empty allowlist: got %+v, want selected", dAny)
	}
	if dAny.Candidate.ID != unknown.Candidate.ID {
		t.Fatalf("empty allowlist: got ID %s, want %s", dAny.Candidate.ID, unknown.Candidate.ID)
	}
}

func TestSelectEmptyAndNoHealthy(t *testing.T) {
	dEmpty := Select(nil, Filter{})
	if !dEmpty.Blackhole || dEmpty.Reason != ReasonNoCandidates || dEmpty.Candidate != nil {
		t.Fatalf("empty inputs: got %+v, want no_candidates blackhole", dEmpty)
	}

	dNoHealthy := Select([]Input{
		{
			Candidate: testCandidate("a", "failing"),
			Probes: []Probe{
				{Outcome: "failure", Latency: 10 * time.Millisecond, Country: "DE"},
				{Outcome: "timeout", Latency: 10 * time.Millisecond, Country: "DE"},
				{Outcome: "unknown", Latency: 10 * time.Millisecond, Country: "DE"},
			},
		},
	}, Filter{})
	if !dNoHealthy.Blackhole || dNoHealthy.Reason != ReasonNoHealthy || dNoHealthy.Candidate != nil {
		t.Fatalf("all failing: got %+v, want no_healthy blackhole", dNoHealthy)
	}
}

func TestSelectNegativeLatency(t *testing.T) {
	bad := Input{
		Candidate: testCandidate("a", "negative"),
		Probes:    []Probe{{Outcome: "success", Latency: -5 * time.Millisecond, Country: "DE"}},
	}
	good := Input{
		Candidate: testCandidate("b", "good"),
		Probes:    []Probe{{Outcome: "success", Latency: 40 * time.Millisecond, Country: "DE"}},
	}

	dOnlyBad := Select([]Input{bad}, Filter{})
	if !dOnlyBad.Blackhole || dOnlyBad.Candidate != nil {
		t.Fatalf("only negative latency: got %+v, want blackhole", dOnlyBad)
	}

	dMixed := Select([]Input{bad, good}, Filter{})
	if dMixed.Blackhole || dMixed.Reason != ReasonSelected || dMixed.Candidate == nil {
		t.Fatalf("negative plus good: got %+v, want good selected", dMixed)
	}
	if dMixed.Candidate.ID != good.Candidate.ID {
		t.Fatalf("negative plus good: got ID %s, want %s", dMixed.Candidate.ID, good.Candidate.ID)
	}

	dNegMax := Select([]Input{good}, Filter{MaxLatency: -1 * time.Millisecond})
	if !dNegMax.Blackhole || dNegMax.Reason != ReasonFiltered || dNegMax.Candidate != nil {
		t.Fatalf("negative max latency: got %+v, want filtered blackhole", dNegMax)
	}
}

func TestSelectReturnsCopyAndDoesNotMutateInputsOrFilter(t *testing.T) {
	inputs := []Input{
		{
			Candidate: testCandidate("b", "beta"),
			Probes:    []Probe{{Outcome: "success", Latency: 50 * time.Millisecond, Country: "NL"}},
		},
		{
			Candidate: testCandidate("a", "alpha"),
			Probes:    []Probe{{Outcome: "success", Latency: 20 * time.Millisecond, Country: "DE"}},
		},
	}
	inputsSnap := []Input{
		{
			Candidate: inputs[0].Candidate,
			Probes:    append([]Probe(nil), inputs[0].Probes...),
		},
		{
			Candidate: inputs[1].Candidate,
			Probes:    append([]Probe(nil), inputs[1].Probes...),
		},
	}
	filter := Filter{
		Countries:           []string{"US", "DE", "NL"},
		MaxLatency:          100 * time.Millisecond,
		MinSuccessfulProbes: 1,
	}
	countriesSnap := append([]string(nil), filter.Countries...)

	d := Select(inputs, filter)
	if d.Blackhole || d.Reason != ReasonSelected || d.Candidate == nil {
		t.Fatalf("got %+v, want selected", d)
	}
	if d.Candidate == &inputs[1].Candidate {
		t.Fatalf("returned candidate aliases input slice element")
	}

	// Mutating the returned candidate value must not affect inputs.
	d.Candidate.Label = "mutated"
	d.Candidate.ID = strings.Repeat("f", 64)

	if !reflect.DeepEqual(inputs, inputsSnap) {
		t.Fatalf("inputs were mutated: got %+v, want %+v", inputs, inputsSnap)
	}
	if !reflect.DeepEqual(filter.Countries, countriesSnap) {
		t.Fatalf("filter.Countries was mutated: got %v, want %v", filter.Countries, countriesSnap)
	}
}
