package metrics

import (
	"context"
	"errors"
	"maps"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"
)

func rule(agg Aggregation, cmp Comparison, threshold float64) Rule {
	return Rule{Name: "test", Query: "q", Aggregation: agg, Comparison: cmp, Threshold: threshold, Severity: SeverityWarning}
}

// evalOne evaluates r against a real client backed by an httptest server.
func evalOne(t *testing.T, r Rule, h http.HandlerFunc) Alert {
	t.Helper()
	alerts, err := Evaluate(context.Background(), newTestClient(t, h, nil), []Rule{r}, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	return alerts[0]
}

const threeSeries = `{"status":"success","data":{"resultType":"vector","result":[
	{"metric":{"job":"node","instance":"a","role":"exit"},"value":[1700000000,"10"]},
	{"metric":{"job":"node","instance":"b","role":"relay"},"value":[1700000000,"30"]},
	{"metric":{"job":"node","instance":"c","role":"exit"},"value":[1700000000,"20"]}]}}`

func TestAggregationAndLabels(t *testing.T) {
	cases := []struct {
		agg    Aggregation
		value  float64
		labels map[string]string
	}{
		{AggMax, 30, map[string]string{"job": "node", "instance": "b", "role": "relay"}},
		{AggMin, 10, map[string]string{"job": "node", "instance": "a", "role": "exit"}},
		{AggSum, 60, map[string]string{"job": "node"}},
		{AggAvg, 20, map[string]string{"job": "node"}},
	}
	for _, tc := range cases {
		t.Run(string(tc.agg), func(t *testing.T) {
			a := evalOne(t, rule(tc.agg, CmpGreaterEqual, tc.value), respond(200, threeSeries))
			if a.State != StateFiring || a.Value != tc.value || a.Series != 3 || a.Err != nil {
				t.Fatalf("alert = %+v", a)
			}
			if !maps.Equal(a.Labels, tc.labels) {
				t.Fatalf("labels = %v, want %v", a.Labels, tc.labels)
			}
		})
	}
}

func TestComparisonBoundaries(t *testing.T) {
	scalar := respond(200, `{"status":"success","data":{"resultType":"scalar","result":[1700000000,"80"]}}`)
	cases := []struct {
		cmp       Comparison
		threshold float64
		want      State
	}{
		{CmpGreater, 80, StateOK},
		{CmpGreater, 79.999, StateFiring},
		{CmpGreaterEqual, 80, StateFiring},
		{CmpGreaterEqual, 80.001, StateOK},
		{CmpLess, 80, StateOK},
		{CmpLess, 80.001, StateFiring},
		{CmpLessEqual, 80, StateFiring},
		{CmpLessEqual, 79.999, StateOK},
		{CmpEqual, 80, StateFiring},
		{CmpEqual, 81, StateOK},
		{CmpNotEqual, 80, StateOK},
		{CmpNotEqual, 81, StateFiring},
	}
	for _, tc := range cases {
		a := evalOne(t, rule(AggMax, tc.cmp, tc.threshold), scalar)
		if a.State != tc.want || a.Value != 80 || a.Threshold != tc.threshold {
			t.Errorf("80 %s %v: alert = %+v, want %s", tc.cmp, tc.threshold, a, tc.want)
		}
	}
}

func TestMatrixUsesLatestSamplePerSeries(t *testing.T) {
	body := `{"status":"success","data":{"resultType":"matrix","result":[
		{"metric":{"node":"a"},"values":[[1700000060,"5"],[1700000000,"100"]]},
		{"metric":{"node":"b"},"values":[]},
		{"metric":{"node":"c"},"values":[[1700000000,"1"],[1700000060,"7"]]}]}}`
	a := evalOne(t, rule(AggMax, CmpGreater, 6), respond(200, body))
	if a.State != StateFiring || a.Value != 7 || a.Series != 2 || a.Labels["node"] != "c" {
		t.Fatalf("alert = %+v", a)
	}
}

func TestUnknownStates(t *testing.T) {
	cases := []struct {
		name string
		h    http.HandlerFunc
		want error
	}{
		{"empty vector", respond(200, `{"status":"success","data":{"resultType":"vector","result":[]}}`), ErrNoData},
		{"empty matrix", respond(200, `{"status":"success","data":{"resultType":"matrix","result":[]}}`), ErrNoData},
		{"matrix without samples", respond(200, `{"status":"success","data":{"resultType":"matrix","result":[{"metric":{},"values":[]}]}}`), ErrNoData},
		{"NaN sample", respond(200, `{"status":"success","data":{"resultType":"vector","result":[
			{"metric":{},"value":[1,"5"]},{"metric":{},"value":[1,"NaN"]}]}}`), ErrNonFinite},
		{"infinite scalar", respond(200, `{"status":"success","data":{"resultType":"scalar","result":[1,"-Inf"]}}`), ErrNonFinite},
		{"sum overflow", respond(200, `{"status":"success","data":{"resultType":"vector","result":[
			{"metric":{},"value":[1,"1.7e308"]},{"metric":{},"value":[1,"1.7e308"]}]}}`), ErrNonFinite},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := rule(AggSum, CmpGreater, 0)
			a := evalOne(t, r, tc.h)
			if a.State != StateUnknown || !errors.Is(a.Err, tc.want) || a.Labels != nil {
				t.Fatalf("alert = %+v", a)
			}
		})
	}

	failures := map[string]http.HandlerFunc{
		"status error": respond(422, `{"status":"error","errorType":"execution","error":"x"}`),
		"429":          respond(429, ""),
		"500":          respond(500, ""),
		"malformed":    respond(200, `{`),
	}
	for name, h := range failures {
		t.Run(name, func(t *testing.T) {
			// A rule that would fire for any value still must not report ok or firing.
			a := evalOne(t, rule(AggMax, CmpNotEqual, math.MaxFloat64), h)
			if a.State != StateUnknown || a.Err == nil {
				t.Fatalf("alert = %+v", a)
			}
		})
	}
}

func TestEvaluateContinuesAfterFailure(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.PostForm.Get("query") == "broken" {
			respond(503, "")(w, r)
			return
		}
		respond(200, `{"status":"success","data":{"resultType":"scalar","result":[1,"1"]}}`)(w, r)
	}, nil)
	rules := []Rule{
		{Name: "broken", Query: "broken", Aggregation: AggMax, Comparison: CmpGreater, Threshold: 0, Severity: SeverityCritical},
		{Name: "fine", Query: "fine", Aggregation: AggMax, Comparison: CmpGreater, Threshold: 5, Severity: SeverityInfo},
	}
	alerts, err := Evaluate(context.Background(), c, rules, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if alerts[0].State != StateUnknown || alerts[0].Rule != "broken" || alerts[0].Severity != SeverityCritical {
		t.Errorf("alert 0 = %+v", alerts[0])
	}
	if alerts[1].State != StateOK || alerts[1].Value != 1 || alerts[1].Rule != "fine" {
		t.Errorf("alert 1 = %+v", alerts[1])
	}
}

func TestEvaluateTimeoutIsUnknown(t *testing.T) {
	l := &lateHandler{}
	c := newTestClient(t, l.serve, func(o *Options) { o.Timeout = 50 * time.Millisecond })
	l.h = blockUntilDone(t, nil)
	alerts, err := Evaluate(context.Background(), c, []Rule{rule(AggMax, CmpGreater, 0)}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if alerts[0].State != StateUnknown || !errors.Is(alerts[0].Err, context.DeadlineExceeded) {
		t.Fatalf("alert = %+v", alerts[0])
	}
}

func TestEvaluateValidatesBeforeRequests(t *testing.T) {
	calls := 0
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { calls++ }, nil)
	rules := []Rule{rule(AggMax, CmpGreater, 1), {Name: "bad", Query: "q", Aggregation: "median", Comparison: ">", Severity: SeverityInfo}}
	_, err := Evaluate(context.Background(), c, rules, time.Time{})
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v", err)
	}
	if calls != 0 {
		t.Fatalf("requests made before validation: %d", calls)
	}
}

func TestValidateRules(t *testing.T) {
	valid := rule(AggAvg, CmpLess, 5)
	if err := ValidateRules([]Rule{valid}); err != nil {
		t.Fatalf("valid rule rejected: %v", err)
	}
	bad := []Rule{
		valid,
		valid, // duplicate name
		{Name: "Bad Name", Query: " ", Aggregation: "median", Comparison: "=>", Threshold: math.NaN(), Severity: "page"},
		{Name: "inf", Query: "q", Aggregation: AggMax, Comparison: CmpEqual, Threshold: math.Inf(1), Severity: SeverityInfo},
	}
	err := ValidateRules(bad)
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v", err)
	}
	want := []string{
		"rules[1].name: duplicates rules[0]",
		"rules[2].name: must match",
		"rules[2].query: must not be empty",
		"rules[2].aggregation: must be one of",
		"rules[2].comparison: must be one of",
		"rules[2].threshold: must be a finite number",
		"rules[2].severity: must be one of",
		"rules[3].threshold: must be a finite number",
	}
	if len(ve.Problems) != len(want) {
		t.Fatalf("problems = %v", ve.Problems)
	}
	for i, p := range ve.Problems {
		if !strings.HasPrefix(p.String(), want[i]) {
			t.Errorf("problem %d = %q, want prefix %q", i, p, want[i])
		}
	}
	if err := ValidateRules(nil); err == nil {
		t.Error("empty rule set accepted")
	}
}

func TestLoadRules(t *testing.T) {
	rules, err := LoadRules(strings.NewReader(`
rules:
  - name: node-disk-usage
    query: 100 * (1 - node_filesystem_avail_bytes / node_filesystem_size_bytes)
    aggregation: max
    comparison: ">="
    threshold: 90
    severity: critical
  - name: provider-balance
    query: provider_balance
    aggregation: min
    comparison: "<"
    threshold: 5.5
    severity: warning
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 || rules[0].Comparison != CmpGreaterEqual || rules[0].Threshold != 90 ||
		rules[1].Aggregation != AggMin || rules[1].Threshold != 5.5 {
		t.Fatalf("rules = %+v", rules)
	}

	bad := map[string]string{
		"empty":         "",
		"unknown field": "rules:\n  - name: a\n    query: q\n    aggregation: max\n    comparison: '>'\n    threshold: 1\n    severity: info\n    for: 5m\n",
		"two documents": "rules: []\n---\nrules: []\n",
		"nan threshold": "rules:\n  - name: a\n    query: q\n    aggregation: max\n    comparison: '>'\n    threshold: .nan\n    severity: info\n",
		"no rules":      "rules: []\n",
		"wrong type":    "rules:\n  - name: a\n    query: q\n    aggregation: max\n    comparison: '>'\n    threshold: high\n    severity: info\n",
	}
	for name, doc := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadRules(strings.NewReader(doc)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}
