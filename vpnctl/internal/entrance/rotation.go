package entrance

import (
	"errors"
	"regexp"
	"time"

	"github.com/juvenileslave/vpn/vpnctl/internal/probe"
)

// ErrInvalidRotation marks a malformed rotation request. It never contains the
// rejected value.
var ErrInvalidRotation = errors.New("entrance: invalid rotation request")

// Provider is an accepted read-only cloud client family.
type Provider string

// Accepted providers.
const (
	ProviderHetzner    Provider = "hetzner"
	ProviderCloudflare Provider = "cloudflare"
)

// RotationState is the plan outcome. A ready plan still performs no mutation.
type RotationState string

// Rotation plan states.
const (
	RotationReady   RotationState = "ready"
	RotationRefused RotationState = "refused"
)

// Rotation step statuses.
const (
	StepPassed  = "passed"
	StepPlanned = "planned"
	StepRefused = "refused"
	StepBlocked = "blocked"
	StepManual  = "manual"
)

// RotationRequest identifies the entrance mapping by operator labels, never by
// addresses, hostnames or credentials. CurrentEntrance and CandidateEntrance
// are bounded labels such as "entrance-a" that the operator maps to a provider
// resource outside this repository.
type RotationRequest struct {
	Node              string
	Family            probe.Family
	Provider          Provider
	CurrentEntrance   string
	CandidateEntrance string
	// Confirmed records an explicit operator confirmation for the plan. It is
	// required before the plan can be marked ready; it does not authorize an
	// automatic provider write.
	Confirmed bool
}

// RotationStep is one ordered, typed plan step.
type RotationStep struct {
	Kind   string `json:"kind"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// RotationPlan is an offline, secret-free description of an entrance-address
// rotation. It contains preflight, read-only verification, the mutation
// refusal, post-change entrance verification and rollback. No provider call,
// DNS change, panel write or production action is performed.
type RotationPlan struct {
	Schema            int           `json:"schema"`
	Node              string        `json:"node"`
	Family            probe.Family  `json:"family"`
	Provider          Provider      `json:"provider"`
	CurrentIdentity   string        `json:"current_identity"`
	CandidateIdentity string        `json:"candidate_identity"`
	State             RotationState `json:"state"`
	// Mutation is the authored refusal reason. Even a ready plan does not
	// execute it.
	Mutation  string         `json:"mutation"`
	Steps     []RotationStep `json:"steps"`
	Rollback  []RotationStep `json:"rollback"`
	CreatedAt time.Time      `json:"created_at"`
}

// rotationLabelPattern admits operator mapping labels but not IP literals,
// hostnames (dots) or IPv6 text (colons), so a plan cannot silently carry a
// real address.
var rotationLabelPattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9_-]{0,61}[A-Za-z0-9])?$`)

// ProviderPreflight names the accepted read-only client operations that an
// operator (or a future authorized CLI step) can use to verify the mapping.
// They are not executed here.
func ProviderPreflight(provider Provider) string {
	switch provider {
	case ProviderHetzner:
		return "hetzner.ListServers and hetzner.ListPrimaryIPs (accepted read-only client; not executed)"
	case ProviderCloudflare:
		return "cloudflare.ListZones and cloudflare.ListDNSRecords (accepted read-only client; not executed)"
	}
	return ""
}

// PlanRotation validates a rotation request and returns an offline plan. A
// request without explicit operator confirmation yields a refused plan with
// no mutation step; a confirmed request yields a ready plan whose mutation
// step is still refused because the accepted cloud clients expose reads only.
// An invalid request returns ErrInvalidRotation and no plan.
func PlanRotation(request RotationRequest, now time.Time) (RotationPlan, error) {
	if !labelPattern.MatchString(request.Node) ||
		(request.Family != probe.IPv4 && request.Family != probe.IPv6) ||
		(request.Provider != ProviderHetzner && request.Provider != ProviderCloudflare) ||
		!rotationLabelPattern.MatchString(request.CurrentEntrance) ||
		!rotationLabelPattern.MatchString(request.CandidateEntrance) ||
		request.CurrentEntrance == request.CandidateEntrance || now.IsZero() {
		return RotationPlan{}, ErrInvalidRotation
	}
	plan := RotationPlan{
		Schema:            1,
		Node:              request.Node,
		Family:            request.Family,
		Provider:          request.Provider,
		CurrentIdentity:   DigestIdentity(request.CurrentEntrance),
		CandidateIdentity: DigestIdentity(request.CandidateEntrance),
		State:             RotationRefused,
		Mutation:          "provider_write_not_implemented",
		Steps:             make([]RotationStep, 0, 5),
		Rollback:          make([]RotationStep, 0, 3),
		CreatedAt:         now,
	}
	plan.Steps = append(plan.Steps, RotationStep{
		Kind:   "preflight",
		Status: StepPassed,
		Detail: "offline validation: bounded labels, distinct current/candidate entrance, accepted provider",
	})
	plan.Steps = append(plan.Steps, RotationStep{
		Kind:   "readonly_verify",
		Status: StepPlanned,
		Detail: ProviderPreflight(request.Provider),
	})
	if !request.Confirmed {
		plan.Steps = append(plan.Steps, RotationStep{
			Kind:   "confirmation",
			Status: StepRefused,
			Detail: "explicit operator confirmation is required; current entrance is unchanged",
		})
		plan.Steps = append(plan.Steps, RotationStep{
			Kind:   "mutation",
			Status: StepBlocked,
			Detail: "not reached: confirmation required",
		})
	} else {
		plan.State = RotationReady
		plan.Steps = append(plan.Steps, RotationStep{
			Kind:   "confirmation",
			Status: StepPassed,
			Detail: "operator confirmation recorded; owner authorization is still required for any provider write",
		})
		plan.Steps = append(plan.Steps, RotationStep{
			Kind:   "mutation",
			Status: StepRefused,
			Detail: "provider_write_not_implemented: accepted cloud clients expose GET only; entrance address is unchanged",
		})
	}
	plan.Steps = append(plan.Steps, RotationStep{
		Kind:   "entrance_verify",
		Status: StepManual,
		Detail: "after an operator-approved provider change, run vpnctl entrance gate on fresh observations; publish only for state=clean from at least two independent in-country vantages",
	})
	plan.Rollback = append(plan.Rollback,
		RotationStep{
			Kind:   "restore_mapping",
			Status: StepManual,
			Detail: "restore the previous entrance mapping (current identity) through the provider console or API; verify it with the accepted read-only client",
		},
		RotationStep{
			Kind:   "verify_entrance",
			Status: StepManual,
			Detail: "run vpnctl entrance gate for the restored mapping; keep publication closed until state=clean",
		},
		RotationStep{
			Kind:   "record_outcome",
			Status: StepManual,
			Detail: "record the outcome outside this repository; no automatic DNS, firewall or publication change",
		},
	)
	return plan, nil
}
