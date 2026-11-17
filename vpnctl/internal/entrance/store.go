package entrance

import (
	"context"

	"github.com/juvenileslave/vpn/vpnctl/internal/store"
)

// Record stages written to the accepted probes table. They are decision
// markers, not new ladder observations.
const (
	// StageGate is the stage marker of one persisted entrance gate decision.
	StageGate = "entrance_gate"
	// StageRotationPlan is the stage marker of one persisted rotation plan.
	StageRotationPlan = "entrance_rotation_plan"
	// ReasonConfirmationRequired is the persisted refusal code of an
	// unconfirmed rotation plan.
	ReasonConfirmationRequired = "confirmation_required"
)

// AppendGate records the entrance decision as one unscoped probe row bound to
// the node label, address family and evaluation time. Schema version 3 allows
// ladder context only on run-scoped rows, so this marker deliberately carries
// no identities or vantage labels; the evidence it summarizes remains in the
// ladder rows, and the full scope is printed by the CLI. A store failure is
// returned unchanged and must be treated as an error, never as a clean gate.
func AppendGate(ctx context.Context, database *store.Store, gate Gate) error {
	// A successful probe row must carry an empty error_code. Only a clean gate
	// is recorded as success; every refused or unresolved gate is a failure
	// whose error_code is the authored reason. The fallback never applies to a
	// clean marker.
	outcome, code := store.OutcomeSuccess, ""
	if gate.State != StateClean {
		outcome, code = store.OutcomeFailure, gate.Reason
		if code == "" {
			code = ReasonInsufficientEvidence
		}
	}
	_, err := database.AppendProbe(ctx, store.ProbeRecord{
		Target:     gate.Target,
		Stage:      StageGate,
		Family:     store.Family(gate.Family),
		Outcome:    outcome,
		ObservedAt: gate.EvaluatedAt,
		ErrorCode:  code,
	})
	return err
}

// AppendRotationPlan records the offline rotation decision. It contains no
// addresses, provider resources or credentials: only the node label, family
// and the plan state. A mutation-capable plan is never recorded as executed.
func AppendRotationPlan(ctx context.Context, database *store.Store, plan RotationPlan) error {
	outcome, code := store.OutcomeSuccess, ""
	if plan.State != RotationReady {
		outcome, code = store.OutcomeFailure, ReasonConfirmationRequired
	}
	_, err := database.AppendProbe(ctx, store.ProbeRecord{
		Target:     plan.Node,
		Stage:      StageRotationPlan,
		Family:     store.Family(plan.Family),
		Outcome:    outcome,
		ObservedAt: plan.CreatedAt,
		ErrorCode:  code,
	})
	return err
}
