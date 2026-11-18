package entrance

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/juvenileslave/vpn/vpnctl/internal/probe"
	"github.com/juvenileslave/vpn/vpnctl/internal/store"
)

func testRotation(confirmed bool) RotationRequest {
	return RotationRequest{
		Node:              "exit-test",
		Family:            probe.IPv4,
		Provider:          ProviderHetzner,
		CurrentEntrance:   "entrance-a",
		CandidateEntrance: "entrance-b",
		Confirmed:         confirmed,
	}
}

func TestRotationRefusesWithoutOperatorConfirmation(t *testing.T) {
	plan, err := PlanRotation(testRotation(false), time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if plan.State != RotationRefused || plan.Mutation != "provider_write_not_implemented" {
		t.Fatalf("plan = %+v", plan)
	}
	if len(plan.Rollback) == 0 {
		t.Fatal("refused plan lost rollback steps")
	}
	var confirmation, mutation *RotationStep
	verify := false
	for index := range plan.Steps {
		step := &plan.Steps[index]
		switch step.Kind {
		case "confirmation":
			confirmation = step
		case "mutation":
			mutation = step
		case "entrance_verify":
			verify = true
		}
	}
	if confirmation == nil || confirmation.Status != StepRefused {
		t.Fatalf("confirmation step = %+v", confirmation)
	}
	if mutation == nil || mutation.Status != StepBlocked {
		t.Fatalf("mutation step = %+v", mutation)
	}
	if !verify {
		t.Fatal("plan lacks entrance verification step")
	}
}

func TestConfirmedRotationPlanIsReadyButStillRefusesMutation(t *testing.T) {
	plan, err := PlanRotation(testRotation(true), time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if plan.State != RotationReady {
		t.Fatalf("plan = %+v", plan)
	}
	var mutation *RotationStep
	for index := range plan.Steps {
		if plan.Steps[index].Kind == "mutation" {
			mutation = &plan.Steps[index]
		}
	}
	if mutation == nil || mutation.Status != StepRefused ||
		!strings.Contains(mutation.Detail, "provider_write_not_implemented") {
		t.Fatalf("mutation step = %+v", mutation)
	}
	if len(plan.Steps) != 5 || len(plan.Rollback) != 3 {
		t.Fatalf("steps = %+v rollback = %+v", plan.Steps, plan.Rollback)
	}
	for _, step := range plan.Rollback {
		if step.Status != StepManual {
			t.Fatalf("rollback step is not manual: %+v", step)
		}
	}
	if plan.CurrentIdentity == plan.CandidateIdentity ||
		plan.CurrentIdentity == "entrance-a" || plan.CandidateIdentity == "entrance-b" {
		t.Fatalf("identities are not opaque: %+v", plan)
	}
	if len(plan.CurrentIdentity) != 64 || len(plan.CandidateIdentity) != 64 {
		t.Fatalf("identities = %q, %q", plan.CurrentIdentity, plan.CandidateIdentity)
	}
}

func TestRotationRejectsInvalidRequests(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	cases := []RotationRequest{
		{Node: "bad node", Family: probe.IPv4, Provider: ProviderHetzner, CurrentEntrance: "a", CandidateEntrance: "b"},
		{Node: "exit-test", Family: probe.IPv4, Provider: "unknown", CurrentEntrance: "a", CandidateEntrance: "b"},
		{Node: "exit-test", Family: probe.IPv4, Provider: ProviderHetzner, CurrentEntrance: "a", CandidateEntrance: "a"},
		{Node: "exit-test", Family: probe.IPv4, Provider: ProviderHetzner, CurrentEntrance: "192.0.2.10", CandidateEntrance: "b"},
		{Node: "exit-test", Family: probe.IPv4, Provider: ProviderHetzner, CurrentEntrance: "cover.example.test", CandidateEntrance: "b"},
	}
	for _, request := range cases {
		if _, err := PlanRotation(request, now); err != ErrInvalidRotation {
			t.Fatalf("request %+v accepted: %v", request, err)
		}
	}
	if _, err := PlanRotation(testRotation(true), time.Time{}); err != ErrInvalidRotation {
		t.Fatalf("zero time accepted: %v", err)
	}
}

func TestPersistedRotationEvidenceIsSecretFree(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	ready, err := PlanRotation(testRotation(true), now)
	if err != nil {
		t.Fatal(err)
	}
	refused, err := PlanRotation(testRotation(false), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := AppendRotationPlan(ctx, database, ready); err != nil {
		t.Fatal(err)
	}
	if err := AppendRotationPlan(ctx, database, refused); err != nil {
		t.Fatal(err)
	}
	records, err := database.LatestProbes(ctx, "exit-test", 10)
	if err != nil || len(records) != 2 {
		t.Fatalf("records = %+v, err = %v", records, err)
	}
	for _, record := range records {
		if record.Stage != StageRotationPlan {
			t.Fatalf("record = %+v", record)
		}
		if record.RunID != "" || record.Vantage != "" || record.EndpointIdentity != "" {
			t.Fatalf("rotation marker leaked ladder scope: %+v", record)
		}
		switch record.Outcome {
		case store.OutcomeSuccess:
			if record.ErrorCode != "" {
				t.Fatalf("ready record has error code: %+v", record)
			}
		case store.OutcomeFailure:
			if record.ErrorCode != ReasonConfirmationRequired {
				t.Fatalf("refused record = %+v", record)
			}
		default:
			t.Fatalf("record outcome = %+v", record)
		}
	}
}
