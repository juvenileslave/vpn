package probe

import (
	"context"
	"time"

	"github.com/juvenileslave/vpn/vpnctl/internal/store"
)

// AppendRun persists bounded observations through the accepted AppendProbe API.
// Appends are deliberately not retried. A crash/partial write cannot masquerade
// as a complete run when diagnosis reconstructs the five stage records.
func AppendRun(ctx context.Context, database *store.Store, report *RunReport) error {
	for _, event := range report.Events {
		outcome := store.OutcomeFailure
		if event.Outcome == OutcomeSuccess {
			outcome = store.OutcomeSuccess
		} else if event.Outcome == OutcomeTimeout {
			outcome = store.OutcomeTimeout
		}
		if event.ExpectedBytes > 0 && event.Outcome == OutcomeSuccess &&
			(!event.Integrity || event.Bytes != event.ExpectedBytes) {
			return shortError("invalid_transfer_observation")
		}
		sni := report.SNIIdentity
		if event.Stage == StageControlTLS {
			sni = report.ControlIdentity
		}
		_, err := database.AppendProbe(ctx, store.ProbeRecord{
			Target: report.Target, Stage: string(event.Stage), Family: store.Family(report.Family),
			Outcome: outcome, ObservedAt: event.ObservedAt, Duration: event.Duration,
			Bytes: event.Bytes, ErrorCode: event.ErrorCode,
			RunID: report.RunID, Vantage: report.Vantage.Name, Network: report.Vantage.Network,
			VantageKind: report.Vantage.Kind, Scope: event.Scope,
			EndpointIdentity: report.EndpointIdentity, ConfigIdentity: report.ConfigIdentity, SNIIdentity: sni,
			ExpectedBytes: event.ExpectedBytes, BodyDuration: event.BodyDuration, ThroughputFloor: report.ThroughputFloor,
		})
		if err != nil {
			return shortError("store_append_failed")
		}
	}
	report.Persisted = len(report.Events) > 0
	return nil
}

// ReadRuns reconstructs metadata only. Legacy primitives and Globalping HTTP
// remain distinct evidence, not substitute REALITY/VLESS handshakes.
func ReadRuns(ctx context.Context, database *store.Store, node string) ([]RunReport, bool, error) {
	records, err := database.LatestProbes(ctx, node, store.MaxLimit)
	if err != nil {
		return nil, false, shortError("store_read_failed")
	}
	runs := make([]RunReport, 0)
	positions := make(map[string]int)
	invalid := make(map[string]bool)
	for _, record := range records {
		if record.RunID == "" || record.Scope == "external_http" {
			continue
		}
		index, exists := positions[record.RunID]
		if !exists {
			index = len(runs)
			positions[record.RunID] = index
			runs = append(runs, RunReport{
				Schema: 1, RunID: record.RunID, Target: record.Target, Family: Family(record.Family),
				Vantage:          Vantage{Name: record.Vantage, Network: record.Network, Kind: record.VantageKind},
				EndpointIdentity: record.EndpointIdentity, ConfigIdentity: record.ConfigIdentity,
				ThroughputFloor: record.ThroughputFloor, Events: make([]Event, 0, 6), Persisted: true,
			})
		}
		run := &runs[index]
		if run.Target != record.Target || run.Family != Family(record.Family) ||
			run.EndpointIdentity != record.EndpointIdentity || run.ConfigIdentity != record.ConfigIdentity ||
			run.ThroughputFloor != record.ThroughputFloor {
			invalid[record.RunID] = true
		}
		outcome := Outcome(record.ErrorCode)
		if record.Outcome == store.OutcomeSuccess {
			outcome = OutcomeSuccess
		} else if record.Outcome == store.OutcomeTimeout {
			outcome = OutcomeTimeout
		} else if record.ErrorCode == "stage_not_run" {
			outcome = OutcomeSkipped
		}
		if record.Stage == string(StageControlTLS) {
			run.ControlIdentity = record.SNIIdentity
		} else {
			if run.SNIIdentity != "" && run.SNIIdentity != record.SNIIdentity {
				invalid[record.RunID] = true
			}
			run.SNIIdentity = record.SNIIdentity
		}
		run.Events = append(run.Events, Event{
			Target: record.Target, Vantage: Vantage{Name: record.Vantage, Network: record.Network, Kind: record.VantageKind},
			Family: Family(record.Family), Scope: record.Scope, Stage: Stage(record.Stage),
			Outcome: outcome, ErrorCode: record.ErrorCode, ObservedAt: record.ObservedAt,
			Duration: record.Duration, BodyDuration: record.BodyDuration, Bytes: record.Bytes,
			ExpectedBytes: record.ExpectedBytes, Integrity: outcome == OutcomeSuccess && record.ExpectedBytes > 0,
		})
	}
	for index := range runs {
		run := &runs[index]
		count := 0
		for _, event := range run.Events {
			if event.Scope == "node_path" {
				count++
			}
		}
		run.Complete = count == len(ladderStages) && !invalid[run.RunID]
	}
	return runs, len(records) == store.MaxLimit, nil
}

// DiagnosisPlan selects a declared, bounded comparison window; Classify never
// consults a clock, store, network, environment or mutable process state.
func (i Inputs) DiagnosisPlan(request LadderRequest, now time.Time) (DiagnosisPlan, error) {
	window, err := i.window()
	if err != nil {
		return DiagnosisPlan{}, err
	}
	endpoint, config, sni := request.identities()
	control := ""
	if request.ControlServerName != "" {
		control = identity(request.ControlServerName)
	}
	return DiagnosisPlan{
		Target: request.Node, Family: request.Target.Family, EndpointIdentity: endpoint,
		ConfigIdentity: config, SNIIdentity: sni, ControlIdentity: control,
		Vantages: i.Vantages, Now: now.UTC(), Window: window, ThroughputFloor: request.ThroughputFloor,
	}, nil
}
