package probe

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"time"
)

// RunLadder performs one attempt per stage on the explicitly selected node path.
// Ordinary network failures are observations, not errors. Setup and cleanup
// failures are errors and never produce a complete/successful report.
func RunLadder(ctx context.Context, request LadderRequest) (report RunReport, err error) {
	endpoint, config, sni := request.identities()
	report = RunReport{
		Schema: 1, Target: request.Node, Family: request.Target.Family, Vantage: request.Vantage,
		EndpointIdentity: endpoint, ConfigIdentity: config, SNIIdentity: sni,
		CoreVersion: PinnedCoreVersion, Budgets: request.Budgets, ThroughputFloor: request.ThroughputFloor,
		Outcome: "error", Events: make([]Event, 0, 6),
	}
	if request.ControlServerName != "" {
		report.ControlIdentity = identity(request.ControlServerName)
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return report, shortError("run_identity_failed")
	}
	report.RunID = hex.EncodeToString(random[:])
	if err := request.validate(); err != nil {
		return report, err
	}
	ctx, cancel := context.WithTimeout(ctx, request.Budgets.Overall)
	defer cancel()
	setup, stopSetup := context.WithTimeout(ctx, request.Budgets.Setup)
	err = checkCore(setup, request.XrayPath)
	stopSetup()
	if err != nil {
		report.ErrorCode = setupCode(err)
		return report, shortError(report.ErrorCode)
	}
	profile, err := loadProfile(&request)
	if err != nil {
		report.ErrorCode = "profile_invalid"
		return report, err
	}

	var connection net.Conn
	var core *coreProcess
	var lifecycleError error
	defer func() {
		if connection != nil {
			_ = connection.Close()
		}
		if core != nil {
			if cleanupErr := core.close(); cleanupErr != nil {
				report.Outcome, report.ErrorCode, report.Complete = "error", "cleanup_failed", false
				err = cleanupErr
				report.Events = append(report.Events, Event{
					Target: request.Node, Family: request.Target.Family, Vantage: request.Vantage,
					Scope: "node_path", Stage: StageRequest, Outcome: OutcomeAuthFailed,
					ErrorCode: "cleanup_failed", ObservedAt: time.Now().UTC(),
				})
			}
		}
	}()
	blocked := false
	for _, stage := range ladderStages {
		budget := stageBudget(request.Budgets, stage)
		event := Event{
			Target: request.Node, Family: request.Target.Family, Vantage: request.Vantage,
			Scope: "node_path", Stage: stage, ObservedAt: time.Now().UTC(), TimeBudget: budget,
			Outcome: OutcomeSkipped, ErrorCode: "stage_not_run",
		}
		endpoint := stageEndpoint(request.Endpoints, stage)
		if endpoint != nil {
			event.ExpectedBytes = endpoint.Bytes
		}
		if blocked {
			report.Events = append(report.Events, event)
			continue
		}
		stageContext, stop := context.WithTimeout(ctx, budget)
		var observation Observation
		switch stage {
		case StageTCP:
			connection, observation = dial(stageContext, request.Target)
		case StageTLS:
			watchStop := watch(stageContext, connection)
			_, observation = handshake(stageContext, connection, request.ServerName, request.RootCAs, Observation{})
			watchStop()
			_ = connection.Close()
			connection = nil
			if observation.Outcome == OutcomeSuccess && request.CoverIssuerSHA256 != "" &&
				(observation.Certificate == nil || observation.Certificate.IssuerSHA256 != request.CoverIssuerSHA256) {
				observation.Outcome = OutcomeCoverMismatch
			}
		case StageAuth:
			started := time.Now()
			core, err = startCore(
				ctx,
				&request,
				profile,
				stageContext,
			)
			if err != nil {
				lifecycleError = err
				observation = Observation{Start: started, End: time.Now(), Outcome: contextOutcome(stageContext)}
				if stageContext.Err() == nil {
					event.ErrorCode = "xray_start_failed"
				}
			} else {
				// The child must outlive this stage. Its overall deadline remains
				// enforced by the parent, and each request has its own socket watch.
				observation = core.request(stageContext, *endpoint, request.RootCAs)
				observation.Start = started
			}
		default:
			observation = core.request(stageContext, *endpoint, request.RootCAs)
		}
		stop()
		event = finishEvent(event, observation, endpoint)
		if event.Outcome != OutcomeSuccess {
			blocked = true
			report.ErrorCode = event.ErrorCode
		}
		report.Events = append(report.Events, event)
	}
	if request.ControlServerName != "" {
		event := Event{
			Target: request.Node, Vantage: request.Vantage, Family: request.Target.Family,
			Scope: "same_address_control", Stage: StageControlTLS, TimeBudget: request.Budgets.Control,
			ObservedAt: time.Now().UTC(), Outcome: OutcomeSkipped, ErrorCode: "stage_not_run",
		}
		if report.Events[0].Outcome == OutcomeSuccess {
			control := request.Target
			control.Timeout = request.Budgets.Control
			observation := TLS(ctx, TLSRequest{Target: control, ServerName: request.ControlServerName, RootCAs: request.RootCAs}).Last()
			event.ObservedAt, event.Duration, event.Certificate = observation.Start.UTC(), observation.Duration(), observation.Certificate
			event.Outcome = observation.Outcome
			event.ErrorCode = ""
			if event.Outcome != OutcomeSuccess {
				event.ErrorCode = string(event.Outcome)
			}
		}
		report.Events = append(report.Events, event)
	}

	report.Complete = true
	report.Outcome = "success"
	if blocked {
		report.Outcome = "failure"
	}
	if lifecycleError != nil {
		report.Outcome, report.Complete = "error", false
		report.ErrorCode = "xray_start_failed"
		if lifecycleError.Error() == "probe: private_cleanup_failed" || lifecycleError.Error() == "probe: xray_cleanup_failed" {
			report.ErrorCode = "cleanup_failed"
		}
		report.Events = append(report.Events, Event{
			Target: request.Node, Family: request.Target.Family, Vantage: request.Vantage,
			Scope: "node_path", Stage: StageRequest, Outcome: OutcomeAuthFailed,
			ErrorCode: report.ErrorCode, ObservedAt: time.Now().UTC(),
		})
		return report, lifecycleError
	}
	return report, nil
}
func finishEvent(event Event, observation Observation, endpoint *Endpoint) Event {
	event.ObservedAt, event.Duration = observation.Start.UTC(), observation.Duration()
	event.Bytes, event.BodyDuration, event.Certificate = observation.BytesRead, observation.BodyDuration, observation.Certificate
	event.Outcome = observation.Outcome
	if endpoint != nil && event.Outcome == OutcomeSuccess {
		switch {
		case event.Bytes != endpoint.Bytes || observation.LimitReached:
			event.Outcome = OutcomeSizeMismatch
		case observation.SHA256 != endpoint.SHA256:
			event.Outcome = OutcomeIntegrityMismatch
		default:
			event.Integrity = true
		}
	}
	if event.Outcome == OutcomeSuccess {
		event.ErrorCode = ""
		return event
	}
	if event.ErrorCode == "stage_not_run" {
		event.ErrorCode = string(event.Outcome)
	}
	if event.Stage == StageAuth && event.ErrorCode != "xray_start_failed" {
		if event.Outcome == OutcomeTimeout {
			event.ErrorCode = "auth_timeout"
		} else if event.Outcome != OutcomeCanceled {
			event.ErrorCode = "auth_failed"
		}
	}
	return event
}

func stageBudget(b Budgets, stage Stage) time.Duration {
	switch stage {
	case StageTCP:
		return b.TCP
	case StageTLS:
		return b.TLS
	case StageAuth:
		return b.Auth
	case StageTransferSmall:
		return b.Small
	default:
		return b.Large
	}
}

func stageEndpoint(e Endpoints, stage Stage) *Endpoint {
	switch stage {
	case StageAuth:
		return &e.Auth
	case StageTransferSmall:
		return &e.Small
	case StageThroughput:
		return &e.Large
	default:
		return nil
	}
}

func contextOutcome(ctx context.Context) Outcome {
	if errors.Is(ctx.Err(), context.Canceled) {
		return OutcomeCanceled
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return OutcomeTimeout
	}
	return OutcomeAuthFailed
}

func setupCode(err error) string {
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	// checkCore only returns authored codes.
	switch err.Error() {
	case "probe: explicit_xray_path_required":
		return "explicit_xray_path_required"
	case "probe: xray_unavailable":
		return "xray_unavailable"
	case "probe: xray_version_mismatch":
		return "xray_version_mismatch"
	default:
		return "xray_version_failed"
	}
}
