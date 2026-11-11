package metrics

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Aggregation reduces the values of all returned series to one number.
type Aggregation string

// Supported aggregations.
const (
	AggMax Aggregation = "max"
	AggMin Aggregation = "min"
	AggSum Aggregation = "sum"
	AggAvg Aggregation = "avg"
)

// Comparison is the operator in "<value> <comparison> <threshold>".
type Comparison string

// Supported comparisons.
const (
	CmpGreater      Comparison = ">"
	CmpGreaterEqual Comparison = ">="
	CmpLess         Comparison = "<"
	CmpLessEqual    Comparison = "<="
	CmpEqual        Comparison = "=="
	CmpNotEqual     Comparison = "!="
)

// Severity classifies a firing rule.
type Severity string

// Supported severities.
const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// Rule is a threshold rule: the rule fires when the aggregated query value
// satisfies Comparison against Threshold.
type Rule struct {
	Name        string      `yaml:"name"`
	Query       string      `yaml:"query"`
	Aggregation Aggregation `yaml:"aggregation"`
	Comparison  Comparison  `yaml:"comparison"`
	Threshold   float64     `yaml:"threshold"`
	Severity    Severity    `yaml:"severity"`
}

// State is the outcome of evaluating one rule.
type State string

// Possible states. Unknown means the rule could not be decided; it is never
// reported as ok.
const (
	StateFiring  State = "firing"
	StateOK      State = "ok"
	StateUnknown State = "unknown"
)

// Alert is the result of evaluating one rule once.
type Alert struct {
	Rule      string
	Severity  Severity
	State     State
	Value     float64 // aggregated value; meaningful only when State is not unknown
	Threshold float64
	// Labels are those of the deciding series for max/min and the labels
	// shared by every series for sum/avg.
	Labels map[string]string
	// Series is the number of series that contributed to Value.
	Series int
	// Err explains an unknown state.
	Err error
}

// Querier runs an instant query; *Client implements it.
type Querier interface {
	Query(ctx context.Context, expr string, at time.Time) (Result, error)
}

// Problem is one rule validation failure at a path such as "rules[1].query".
type Problem struct {
	Path    string
	Message string
}

func (p Problem) String() string { return p.Path + ": " + p.Message }

// ValidationError lists every problem found in a rule set.
type ValidationError struct {
	Problems []Problem
}

func (e *ValidationError) Error() string {
	lines := make([]string, len(e.Problems))
	for i, p := range e.Problems {
		lines[i] = p.String()
	}
	return "metrics: invalid rules:\n" + strings.Join(lines, "\n")
}

// ErrNoData marks an unknown alert caused by an empty result.
var ErrNoData = errors.New("metrics: query returned no data")

// ErrNonFinite marks an unknown alert caused by a NaN or infinite value.
var ErrNonFinite = errors.New("metrics: query returned a non-finite value")

var ruleName = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

// ValidateRules checks every rule and reports all problems at once.
func ValidateRules(rules []Rule) error {
	var problems []Problem
	add := func(i int, field, msg string) {
		problems = append(problems, Problem{Path: fmt.Sprintf("rules[%d].%s", i, field), Message: msg})
	}
	if len(rules) == 0 {
		problems = append(problems, Problem{Path: "rules", Message: "at least one rule is required"})
	}
	seen := map[string]int{}
	for i, r := range rules {
		switch prev, dup := seen[r.Name]; {
		case !ruleName.MatchString(r.Name):
			add(i, "name", "must match "+ruleName.String())
		case dup:
			add(i, "name", fmt.Sprintf("duplicates rules[%d]", prev))
		default:
			seen[r.Name] = i
		}
		if strings.TrimSpace(r.Query) == "" {
			add(i, "query", "must not be empty")
		}
		switch r.Aggregation {
		case AggMax, AggMin, AggSum, AggAvg:
		default:
			add(i, "aggregation", "must be one of max, min, sum, avg")
		}
		switch r.Comparison {
		case CmpGreater, CmpGreaterEqual, CmpLess, CmpLessEqual, CmpEqual, CmpNotEqual:
		default:
			add(i, "comparison", "must be one of >, >=, <, <=, ==, !=")
		}
		if math.IsNaN(r.Threshold) || math.IsInf(r.Threshold, 0) {
			add(i, "threshold", "must be a finite number")
		}
		switch r.Severity {
		case SeverityInfo, SeverityWarning, SeverityCritical:
		default:
			add(i, "severity", "must be one of info, warning, critical")
		}
	}
	if len(problems) > 0 {
		return &ValidationError{Problems: problems}
	}
	return nil
}

// LoadRules strictly decodes a single YAML document of the form
// "rules: [...]" and validates it. Unknown fields are rejected.
func LoadRules(r io.Reader) ([]Rule, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("metrics: read rules: %w", err)
	}
	var doc struct {
		Rules []Rule `yaml:"rules"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("metrics: rules document is empty")
		}
		return nil, fmt.Errorf("metrics: parse rules: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("metrics: rules file must contain exactly one YAML document")
	}
	if err := ValidateRules(doc.Rules); err != nil {
		return nil, err
	}
	return doc.Rules, nil
}

// Evaluate validates rules, then runs one instant query per rule at time at
// (zero means server time). Query failures become unknown alerts; only an
// invalid rule set returns an error, before any request is made.
func Evaluate(ctx context.Context, q Querier, rules []Rule, at time.Time) ([]Alert, error) {
	if err := ValidateRules(rules); err != nil {
		return nil, err
	}
	alerts := make([]Alert, len(rules))
	for i, r := range rules {
		alerts[i] = evaluate(ctx, q, r, at)
	}
	return alerts, nil
}

type point struct {
	labels map[string]string
	value  float64
}

func evaluate(ctx context.Context, q Querier, r Rule, at time.Time) Alert {
	alert := Alert{Rule: r.Name, Severity: r.Severity, State: StateUnknown, Threshold: r.Threshold}
	if err := ctx.Err(); err != nil {
		alert.Err = err
		return alert
	}
	res, err := q.Query(ctx, r.Query, at)
	if err != nil {
		alert.Err = err
		return alert
	}

	var points []point
	switch res.Type {
	case ResultScalar:
		points = []point{{labels: map[string]string{}, value: res.Scalar.Value}}
	case ResultVector, ResultMatrix:
		// For a matrix only the latest sample of each series is used; window
		// semantics belong in the query (max_over_time and similar).
		for _, s := range res.Series {
			if len(s.Samples) == 0 {
				continue
			}
			latest := s.Samples[0]
			for _, smp := range s.Samples[1:] {
				if smp.Time.After(latest.Time) {
					latest = smp
				}
			}
			points = append(points, point{labels: s.Labels, value: latest.Value})
		}
	default:
		alert.Err = &ResultTypeError{Got: string(res.Type), Allowed: []ResultType{ResultScalar, ResultVector, ResultMatrix}}
		return alert
	}
	if len(points) == 0 {
		alert.Err = ErrNoData
		return alert
	}
	for _, p := range points {
		if math.IsNaN(p.value) || math.IsInf(p.value, 0) {
			alert.Err = ErrNonFinite
			return alert
		}
	}

	value, labels := aggregate(r.Aggregation, points)
	if math.IsInf(value, 0) {
		// A sum of finite values can still overflow.
		alert.Err = ErrNonFinite
		return alert
	}
	alert.Value = value
	alert.Labels = labels
	alert.Series = len(points)
	if compare(r.Comparison, value, r.Threshold) {
		alert.State = StateFiring
	} else {
		alert.State = StateOK
	}
	return alert
}

func aggregate(agg Aggregation, points []point) (float64, map[string]string) {
	switch agg {
	case AggMax, AggMin:
		best := points[0]
		for _, p := range points[1:] {
			if (agg == AggMax && p.value > best.value) || (agg == AggMin && p.value < best.value) {
				best = p
			}
		}
		return best.value, maps.Clone(best.labels)
	default:
		sum := 0.0
		common := maps.Clone(points[0].labels)
		for _, p := range points {
			sum += p.value
			for k, v := range common {
				if p.labels[k] != v {
					delete(common, k)
				}
			}
		}
		if agg == AggAvg {
			return sum / float64(len(points)), common
		}
		return sum, common
	}
}

func compare(c Comparison, v, t float64) bool {
	switch c {
	case CmpGreater:
		return v > t
	case CmpGreaterEqual:
		return v >= t
	case CmpLess:
		return v < t
	case CmpLessEqual:
		return v <= t
	case CmpEqual:
		return v == t
	default:
		return v != t
	}
}
