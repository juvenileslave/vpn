package alerts

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/juvenileslave/vpn/vpnctl/internal/metrics"
	"github.com/juvenileslave/vpn/vpnctl/internal/store"
)

var (
	scopePattern    = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,31}$`)
	ruleNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
)

func validScope(s string) bool {
	return scopePattern.MatchString(s)
}

// ValidRuleName reports whether name is a valid metric rule name.
func ValidRuleName(name string) bool {
	return ruleNamePattern.MatchString(name)
}

// FormatLabels renders labels deterministically for CLI output.
func FormatLabels(labels map[string]string) string {
	return formatLabels(labels)
}

// makeOutbox renders the notification and wraps it in a durable queue entry.
// The dedupe key is derived from the rule identity, event, label fingerprint
// and pre-transition revision, never from the message text.
func (w *Worker) makeOutbox(st store.AlertState, event store.AlertEvent, reason string, now time.Time) *store.AlertOutbox {
	return &store.AlertOutbox{
		Rule:          st.Rule,
		Event:         event,
		Fingerprint:   st.Fingerprint,
		DedupeKey:     dedupeKey(st, event),
		Severity:      st.Severity,
		Message:       buildMessage(st, event, reason, w.cfg.Scope, now),
		CreatedAt:     now,
		NextAttemptAt: now,
		ExpiresAt:     now.Add(w.cfg.OutboxMaxAge),
	}
}

func dedupeKey(st store.AlertState, event store.AlertEvent) string {
	fp := st.Fingerprint
	if len(fp) > 8 {
		fp = fp[:8]
	}
	return fmt.Sprintf("alerts.%s.%s.%s.%d", st.Rule, event, fp, st.Revision)
}

// buildMessage renders one bounded plain-text notification. It contains the
// rule, severity, observation scope, state, value, comparison, threshold,
// labels and evaluation timestamp. Tokens, query expressions and raw API
// responses never appear because they are not part of AlertState.
func buildMessage(st store.AlertState, event store.AlertEvent, reason, scope string, at time.Time) string {
	header := fmt.Sprintf("%s rule=%s severity=%s scope=%s", event, st.Rule, st.Severity, scope)
	var body string
	comparison := st.Comparison
	if comparison == "" {
		comparison = "?"
	}
	switch event {
	case store.EventUnknown:
		body = fmt.Sprintf("state=unknown reason=%s condition=%s %s", reason, comparison, formatValue(st.Threshold))
	case store.EventRemoved:
		body = fmt.Sprintf("state=removed last_state=%s value=%s condition=%s %s",
			st.State, formatValue(st.Value), comparison, formatValue(st.Threshold))
	default:
		body = fmt.Sprintf("state=%s value=%s condition=%s %s",
			st.State, formatValue(st.Value), comparison, formatValue(st.Threshold))
	}
	labels := formatLabels(st.Labels)
	lines := []string{
		header,
		body,
		"observed_at=" + at.UTC().Format(time.RFC3339),
		"labels=" + labels,
	}
	return sanitizeMessage(strings.Join(lines, "\n"))
}

func formatValue(v float64) string {
	return strconv.FormatFloat(v, 'g', -1, 64)
}

func formatLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return "-"
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+labels[k])
	}
	return sanitizeField(strings.Join(parts, ","))
}

// sanitizeField replaces control characters, including newlines, with spaces.
// Structural message newlines are added by the caller, so a label value must
// never introduce its own line.
func sanitizeField(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			b.WriteRune(' ')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// sanitizeMessage replaces control characters that a plain-text sink could
// interpret and bounds the message length.
func sanitizeMessage(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n':
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			b.WriteRune(' ')
		default:
			b.WriteRune(r)
		}
	}
	return truncateRunes(b.String(), maxMessageRunes)
}

func truncateRunes(s string, max int) string {
	if max < 4 || len([]rune(s)) <= max {
		return s
	}
	runes := []rune(s)
	return string(runes[:max-3]) + "..."
}

// CheckResult is one typed result of `vpnctl metrics check`.
type CheckResult struct {
	Rule       string            `json:"rule"`
	Severity   string            `json:"severity"`
	State      metrics.State     `json:"state"`
	Value      *float64          `json:"value,omitempty"`
	Threshold  float64           `json:"threshold"`
	Comparison string            `json:"comparison"`
	Labels     map[string]string `json:"labels,omitempty"`
	Series     int               `json:"series"`
	Reason     string            `json:"reason,omitempty"`
}

// Check evaluates rules once and returns typed results. An invalid rule set
// returns the validation error before any query; query failures are reported
// as unknown states, never as ok.
func Check(ctx context.Context, q metrics.Querier, rules []metrics.Rule, at time.Time) ([]CheckResult, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context is required", ErrInvalidConfig)
	}
	if q == nil {
		return nil, fmt.Errorf("%w: metrics querier is required", ErrInvalidConfig)
	}
	evaluated, err := metrics.Evaluate(ctx, q, rules, at)
	if err != nil {
		return nil, err
	}
	byName := make(map[string]metrics.Rule, len(rules))
	for _, r := range rules {
		byName[r.Name] = r
	}
	out := make([]CheckResult, 0, len(evaluated))
	for _, a := range evaluated {
		r := byName[a.Rule]
		res := CheckResult{
			Rule:       a.Rule,
			Severity:   string(a.Severity),
			State:      a.State,
			Threshold:  a.Threshold,
			Comparison: string(r.Comparison),
			Series:     a.Series,
		}
		if a.State != metrics.StateUnknown {
			v := a.Value
			res.Value = &v
			res.Labels = a.Labels
		} else {
			res.Reason = unknownReason(a.Err)
		}
		out = append(out, res)
	}
	return out, nil
}
