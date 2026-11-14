package probe

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/netip"
	"strconv"
	"time"

	"github.com/juvenileslave/vpn/vpnctl/internal/globalping"
	"github.com/juvenileslave/vpn/vpnctl/internal/store"
)

// GlobalpingInput consumes the accepted client's typed result, not raw API
// output. No request, polling, retry or provider endpoint is started by import.
// Port/family are explicit because Measurement does not expose request options.
type GlobalpingInput struct {
	Measurement globalping.Measurement `json:"measurement"`
	Port        uint16                 `json:"port"`
	Family      Family                 `json:"family"`
}

// AppendGlobalping retains only HTTP observations in their own external_http
// scope. They cannot satisfy TCP/control-SNI/auth/transfer evidence in Classify.
func AppendGlobalping(ctx context.Context, database *store.Store, request LadderRequest, path string) (int, error) {
	var input GlobalpingInput
	if err := readJSON(path, 1<<20, &input); err != nil {
		return 0, shortError("globalping_input_invalid")
	}
	measurement := input.Measurement
	validTarget := measurement.Target == request.Target.Address.String() || measurement.Target == request.ServerName
	if !validTarget || input.Port != request.Target.Port || input.Family != request.Target.Family ||
		measurement.Status != globalping.StatusFinished || len(measurement.Results) == 0 || len(measurement.Results) > 500 {
		return 0, shortError("globalping_scope_invalid")
	}
	at := measurement.UpdatedAt
	if at.IsZero() {
		at = measurement.CreatedAt
	}
	if at.Before(time.Unix(0, 0)) || at.After(time.Now()) || at.IsZero() {
		return 0, shortError("globalping_time_invalid")
	}
	endpoint, config, sni := request.identities()
	for index, result := range measurement.Results {
		if result.Probe.ASN <= 0 || uint64(result.Probe.ASN) > 0xffffffff {
			return index, shortError("globalping_vantage_invalid")
		}
		if result.HTTP.Status == globalping.TestFinished {
			address, err := netip.ParseAddr(result.HTTP.ResolvedAddress)
			if err != nil || address != request.Target.Address {
				return index, shortError("globalping_address_mismatch")
			}
		}
		outcome, code := store.OutcomeFailure, "globalping_unknown"
		switch result.HTTP.Status {
		case globalping.TestFinished:
			if result.HTTP.StatusCode >= 200 && result.HTTP.StatusCode < 300 && !result.HTTP.Truncated {
				outcome, code = store.OutcomeSuccess, ""
			} else {
				code = "globalping_http_incomplete"
			}
			if result.HTTP.TLS != nil && !result.HTTP.TLS.Authorized {
				outcome, code = store.OutcomeFailure, "globalping_tls_unverified"
			}
		case globalping.TestFailed:
			switch result.HTTP.FailureSource {
			case "target":
				code = "globalping_target_failed"
			case "resolver":
				code = "globalping_resolver_failed"
			case "internal":
				code = "globalping_internal_failed"
			}
		case globalping.TestOffline:
			code = "globalping_offline"
		}
		var duration time.Duration
		if result.HTTP.Timings != nil {
			duration = result.HTTP.Timings.Total
			if duration < 0 || duration > 5*time.Minute {
				return index, shortError("globalping_timing_invalid")
			}
		}
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return index, shortError("run_identity_failed")
		}
		_, err := database.AppendProbe(ctx, store.ProbeRecord{
			Target: request.Node, Stage: "globalping_http", Family: store.Family(request.Target.Family),
			Outcome: outcome, ErrorCode: code, ObservedAt: at.UTC(), Duration: duration,
			RunID: hex.EncodeToString(random[:]), Vantage: "globalping-" + strconv.Itoa(index+1),
			Network: "globalping-asn-" + strconv.Itoa(result.Probe.ASN), VantageKind: "external_http", Scope: "external_http",
			EndpointIdentity: endpoint, ConfigIdentity: config, SNIIdentity: sni,
		})
		if err != nil {
			return index, shortError("store_append_failed")
		}
	}
	return len(measurement.Results), nil
}
