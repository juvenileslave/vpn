package store

import "regexp"

var (
	runPattern  = regexp.MustCompile(`^[a-f0-9]{32}$`)
	hashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

func validateProbeContext(r ProbeRecord) error {
	if r.RunID == "" {
		if r.Vantage != "" || r.Network != "" || r.VantageKind != "" || r.Scope != "" ||
			r.EndpointIdentity != "" || r.ConfigIdentity != "" || r.SNIIdentity != "" ||
			r.ExpectedBytes != 0 || r.BodyDuration != 0 || r.ThroughputFloor != 0 {
			return invalid("unscoped probe must not contain ladder context")
		}
		return nil
	}
	if !runPattern.MatchString(r.RunID) || !targetPattern.MatchString(r.Vantage) ||
		!targetPattern.MatchString(r.Network) || !hashPattern.MatchString(r.EndpointIdentity) ||
		!hashPattern.MatchString(r.ConfigIdentity) || !hashPattern.MatchString(r.SNIIdentity) {
		return invalid("probe context must contain bounded labels and canonical opaque identities")
	}
	switch r.VantageKind {
	case "in_country", "outside", "local_dc", "external_http":
	default:
		return invalid("probe vantage kind is invalid")
	}
	switch r.Scope {
	case "node_path", "same_address_control":
		if r.VantageKind == "external_http" {
			return invalid("external http evidence cannot represent an authorized node path")
		}
	case "external_http":
		if r.VantageKind != "external_http" || r.Stage != "globalping_http" {
			return invalid("external http evidence must retain its own stage and vantage kind")
		}
	default:
		return invalid("probe scope is invalid")
	}
	if r.ExpectedBytes < 0 || r.ExpectedBytes > 20<<20 || r.BodyDuration < 0 ||
		r.BodyDuration > r.Duration || r.ThroughputFloor < 0 || r.ThroughputFloor > 1_000_000_000_000 {
		return invalid("probe transfer measurements are out of bounds")
	}
	return nil
}
