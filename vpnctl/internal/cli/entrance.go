package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/juvenileslave/vpn/vpnctl/internal/entrance"
	"github.com/juvenileslave/vpn/vpnctl/internal/probe"
	"github.com/juvenileslave/vpn/vpnctl/internal/store"
)

type entranceOutput struct {
	Gate      *entrance.Gate         `json:"gate,omitempty"`
	Rotation  *entrance.RotationPlan `json:"rotation,omitempty"`
	ErrorCode string                 `json:"error_code,omitempty"`
}

func runEntrance(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return usageError(stderr, "entrance requires gate or rotation")
	}
	switch args[0] {
	case "gate":
		return runEntranceGate(args[1:], stdout, stderr)
	case "rotation":
		if len(args) < 2 || args[1] != "plan" {
			return usageError(stderr, "entrance rotation requires plan")
		}
		return runEntranceRotationPlan(args[2:], stdout, stderr)
	default:
		return usageError(stderr, fmt.Sprintf("unknown entrance subcommand %q", args[0]))
	}
}

func runEntranceGate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("entrance gate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	node := fs.String("node", "", "node label in the external inputs")
	family := fs.String("family", "ipv4", "ipv4 or ipv6; never fallback")
	inputsPath := fs.String("inputs", os.Getenv("VPNCTL_PROBE_INPUTS"), "external private inputs file")
	storePath := fs.String("store", os.Getenv("VPNCTL_STATE_DB"), "local state database")
	format := fs.String("format", "text", "text or json")
	jsonFlag := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return usageError(stderr, "invalid entrance gate arguments")
	}
	if *jsonFlag {
		*format = "json"
	}
	if *node == "" || *inputsPath == "" || *storePath == "" ||
		(*family != "ipv4" && *family != "ipv6") || (*format != "text" && *format != "json") {
		return usageError(stderr, "--node, --inputs and --store are required; family/format must be valid")
	}
	fail := func(code string) int {
		if *format == "json" {
			if err := json.NewEncoder(stdout).Encode(entranceOutput{ErrorCode: code}); err != nil {
				fmt.Fprintln(stderr, "entrance: output_failed")
			}
		} else {
			fmt.Fprintln(stderr, "entrance: "+code)
		}
		return ExitError
	}
	failCode := func(err error, fallback string) int {
		code, ok := probe.Code(err)
		if !ok {
			code = fallback
		}
		return fail(code)
	}

	inputs, err := probe.LoadInputs(*inputsPath)
	if err != nil {
		return failCode(err, "inputs_invalid")
	}
	request, err := inputs.Diagnose(*node, probe.Family(*family), "")
	if err != nil {
		return failCode(err, "target_inputs_invalid")
	}
	plan, err := inputs.DiagnosisPlan(request, time.Now())
	if err != nil {
		return fail("evidence_plan_invalid")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	local, stopLocal := context.WithTimeout(ctx, 5*time.Second)
	database, err := store.Open(local, *storePath)
	stopLocal()
	if err != nil {
		return fail("store_open_failed")
	}
	closed := false
	defer func() {
		if !closed {
			_ = database.Close()
		}
	}()

	local, stopRead := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	runs, truncated, err := probe.ReadRuns(local, database, request.Node)
	stopRead()
	if err != nil {
		return fail("store_read_failed")
	}
	plan.QueryTruncated = truncated
	gate := entrance.Evaluate(plan, runs)

	persist, stopPersist := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	err = entrance.AppendGate(persist, database, gate)
	stopPersist()
	if err != nil {
		return fail("store_append_failed")
	}
	if err := database.Close(); err != nil {
		closed = true
		return fail("store_close_failed")
	}
	closed = true
	if err := renderEntrance(stdout, entranceOutput{Gate: &gate}, *format); err != nil {
		fmt.Fprintln(stderr, "entrance: output_failed")
		return ExitError
	}
	return entranceExitCode(gate.State)
}

// entranceExitCode maps a gate state to the documented exit codes: clean is
// success, an observed gate failure is 4, and insufficient evidence is 3.
func entranceExitCode(state entrance.State) int {
	switch state {
	case entrance.StateClean:
		return ExitOK
	case entrance.StateFailed:
		return ExitProbeFailure
	default:
		return ExitInsufficient
	}
}

func runEntranceRotationPlan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("entrance rotation plan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	node := fs.String("node", "", "node label")
	provider := fs.String("provider", "", "hetzner or cloudflare")
	current := fs.String("current", "", "bounded label of the current entrance mapping")
	candidate := fs.String("candidate", "", "bounded label of the candidate entrance mapping")
	family := fs.String("family", "ipv4", "ipv4 or ipv6")
	storePath := fs.String("store", os.Getenv("VPNCTL_STATE_DB"), "local state database")
	format := fs.String("format", "text", "text or json")
	jsonFlag := fs.Bool("json", false, "JSON output")
	confirm := fs.Bool("confirm", false, "explicit operator confirmation for the plan")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return usageError(stderr, "invalid entrance rotation plan arguments")
	}
	if *jsonFlag {
		*format = "json"
	}
	if *node == "" || *provider == "" || *current == "" || *candidate == "" || *storePath == "" ||
		(*family != "ipv4" && *family != "ipv6") || (*format != "text" && *format != "json") {
		return usageError(stderr, "--node, --provider, --current, --candidate and --store are required; family/format must be valid")
	}
	fail := func(code string) int {
		if *format == "json" {
			if err := json.NewEncoder(stdout).Encode(entranceOutput{ErrorCode: code}); err != nil {
				fmt.Fprintln(stderr, "entrance: output_failed")
			}
		} else {
			fmt.Fprintln(stderr, "entrance: "+code)
		}
		return ExitError
	}

	plan, err := entrance.PlanRotation(entrance.RotationRequest{
		Node:              *node,
		Family:            probe.Family(*family),
		Provider:          entrance.Provider(*provider),
		CurrentEntrance:   *current,
		CandidateEntrance: *candidate,
		Confirmed:         *confirm,
	}, time.Now())
	if err != nil {
		if errors.Is(err, entrance.ErrInvalidRotation) {
			return fail("rotation_invalid")
		}
		return fail("rotation_plan_failed")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	local, stopLocal := context.WithTimeout(ctx, 5*time.Second)
	database, err := store.Open(local, *storePath)
	stopLocal()
	if err != nil {
		return fail("store_open_failed")
	}
	persist, stopPersist := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	err = entrance.AppendRotationPlan(persist, database, plan)
	stopPersist()
	if err != nil {
		_ = database.Close()
		return fail("store_append_failed")
	}
	if err := database.Close(); err != nil {
		return fail("store_close_failed")
	}
	if err := renderEntrance(stdout, entranceOutput{Rotation: &plan}, *format); err != nil {
		fmt.Fprintln(stderr, "entrance: output_failed")
		return ExitError
	}
	if plan.State == entrance.RotationReady {
		return ExitOK
	}
	return ExitRefused
}

func renderEntrance(output io.Writer, result entranceOutput, format string) error {
	if format == "json" {
		return json.NewEncoder(output).Encode(result)
	}
	if result.Gate != nil {
		gate := result.Gate
		if _, err := fmt.Fprintf(output,
			"entrance gate %s family=%s state=%s usable=%t reason=%s failure_class=%s failure_code=%s\n",
			gate.Target, gate.Family, gate.State, gate.Usable, gate.Reason, gate.FailureClass, gate.FailureCode); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(output,
			"  scope: window=%s..%s ru_vantages=%v independent_ru_networks=%d required=%d ru_verified=%t global=%t\n",
			gate.Scope.From.Format(time.RFC3339Nano), gate.Scope.To.Format(time.RFC3339Nano),
			gate.Scope.RUVantages, gate.Scope.IndependentRUNetworks, gate.Scope.RequiredRUVantages,
			gate.Scope.RUVantageVerified, gate.Scope.Global); err != nil {
			return err
		}
		for _, vantage := range gate.Vantages {
			if _, err := fmt.Fprintf(output, "  vantage=%s network=%s kind=%s state=%s class=%s code=%s at=%s\n",
				vantage.Vantage.Name, vantage.Vantage.Network, vantage.Vantage.Kind, vantage.State,
				vantage.FailureClass, vantage.FailureCode, vantage.ObservedAt.Format(time.RFC3339Nano)); err != nil {
				return err
			}
			for _, stage := range vantage.Stages {
				if _, err := fmt.Fprintf(output, "    %s: %s code=%s bytes=%d/%d duration=%s\n",
					stage.Stage, stage.Outcome, stage.ErrorCode, stage.Bytes, stage.ExpectedBytes, stage.Duration); err != nil {
					return err
				}
			}
		}
		if _, err := fmt.Fprintf(output, "  missing_evidence: %v\n", gate.MissingEvidence); err != nil {
			return err
		}
	}
	if result.Rotation != nil {
		plan := result.Rotation
		if _, err := fmt.Fprintf(output,
			"entrance rotation plan node=%s family=%s provider=%s state=%s mutation=%s\n",
			plan.Node, plan.Family, plan.Provider, plan.State, plan.Mutation); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(output, "  current_identity=%s candidate_identity=%s\n",
			plan.CurrentIdentity, plan.CandidateIdentity); err != nil {
			return err
		}
		for _, step := range plan.Steps {
			if _, err := fmt.Fprintf(output, "  %s: %s — %s\n", step.Kind, step.Status, step.Detail); err != nil {
				return err
			}
		}
		for _, step := range plan.Rollback {
			if _, err := fmt.Fprintf(output, "  rollback/%s: %s — %s\n", step.Kind, step.Status, step.Detail); err != nil {
				return err
			}
		}
	}
	if result.ErrorCode != "" {
		if _, err := fmt.Fprintf(output, "error_code: %s\n", result.ErrorCode); err != nil {
			return err
		}
	}
	return nil
}
