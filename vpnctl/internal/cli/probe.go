package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/juvenileslave/vpn/vpnctl/internal/probe"
	"github.com/juvenileslave/vpn/vpnctl/internal/store"
)

const (
	// ExitInsufficient means no conservative diagnosis is supported by the evidence.
	ExitInsufficient = 3
	// ExitProbeFailure means an attempted node-path stage failed (not a verdict).
	ExitProbeFailure = 4
)

type probeOutput struct {
	Probe                *probe.RunReport `json:"probe,omitempty"`
	Diagnosis            *probe.Verdict   `json:"diagnosis,omitempty"`
	ExternalHTTPImported int              `json:"external_http_imported"`
	ErrorCode            string           `json:"error_code,omitempty"`
}

func runProbe(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "ladder" {
		return usageError(stderr, "probe requires ladder")
	}
	return runDiagnosisCommand(args[1:], stdout, stderr, true)
}

func runDiagnosisCommand(args []string, stdout, stderr io.Writer, ladder bool) int {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	node := fs.String("node", "", "node label in the external inputs")
	family := fs.String("family", "ipv4", "ipv4 or ipv6; never fallback")
	inputsPath := fs.String("inputs", os.Getenv("VPNCTL_PROBE_INPUTS"), "external private inputs file")
	storePath := fs.String("store", os.Getenv("VPNCTL_STATE_DB"), "local state database")
	xrayPath := fs.String("xray", os.Getenv("VPNCTL_XRAY_PATH"), "explicit pinned Xray binary path")
	vantage := fs.String("vantage", "", "explicit actual vantage; defaults to inputs.local_vantage")
	format := fs.String("format", "text", "text or json")
	jsonFlag := fs.Bool("json", false, "JSON output")
	globalpingPath := fs.String("globalping-file", "", "optional typed Globalping HTTP evidence; no provider calls")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return usageError(stderr, "invalid probe/diagnose arguments")
	}
	if *jsonFlag {
		*format = "json"
	}
	if *node == "" || *inputsPath == "" || *storePath == "" || (*family != "ipv4" && *family != "ipv6") ||
		(*format != "text" && *format != "json") || (ladder && *xrayPath == "") {
		return usageError(stderr, "--node, --inputs, --store and (for ladder) --xray are required; family/format must be valid")
	}
	fail := func(code string) int {
		if *format == "json" {
			if err := json.NewEncoder(stdout).Encode(probeOutput{ErrorCode: code}); err != nil {
				fmt.Fprintln(stderr, "probe: output_failed")
			}
		} else {
			fmt.Fprintln(stderr, "probe: "+code)
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
	var request probe.LadderRequest
	if ladder {
		request, err = inputs.Ladder(*node, probe.Family(*family), *vantage)
	} else {
		request, err = inputs.Diagnose(*node, probe.Family(*family), *vantage)
	}
	if err != nil {
		return failCode(err, "target_inputs_invalid")
	}
	request.XrayPath = *xrayPath
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
	output := probeOutput{}
	var runErr error
	if ladder {
		report, err := probe.RunLadder(ctx, request)
		runErr = err
		output.Probe = &report
		if len(report.Events) > 0 {
			// Persist cancellation/failure facts too, under an explicit local-only
			// budget that cannot restart or lengthen the network probe.
			persist, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			err = probe.AppendRun(persist, database, &report)
			stop()
			if err != nil {
				return fail("store_append_failed")
			}
		}
		if runErr != nil {
			output.ErrorCode = report.ErrorCode
			if output.ErrorCode == "" {
				output.ErrorCode = "probe_setup_failed"
			}
		}
	}
	if *globalpingPath != "" {
		local, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		count, err := probe.AppendGlobalping(local, database, request, *globalpingPath)
		stop()
		if err != nil {
			return fail("globalping_import_failed")
		}
		output.ExternalHTTPImported = count
	}
	local, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	runs, truncated, err := probe.ReadRuns(local, database, request.Node)
	stop()
	if err != nil {
		return fail("store_read_failed")
	}
	plan, err := inputs.DiagnosisPlan(request, time.Now())
	if err != nil {
		return fail("evidence_plan_invalid")
	}
	plan.QueryTruncated = truncated
	diagnosis := probe.Classify(plan, runs)
	output.Diagnosis = &diagnosis
	closeErr := database.Close()
	closed = true
	if closeErr != nil {
		return fail("store_close_failed")
	}
	if err := renderProbe(stdout, output, *format); err != nil {
		fmt.Fprintln(stderr, "probe: output_failed")
		return ExitError
	}
	if runErr != nil {
		return ExitError
	}
	if ladder {
		if output.Probe.Outcome != "success" {
			return ExitProbeFailure
		}
		return ExitOK
	}
	if diagnosis.Verdict == "unknown" {
		return ExitInsufficient
	}
	return ExitOK
}

func renderProbe(output io.Writer, result probeOutput, format string) error {
	if format == "json" {
		return json.NewEncoder(output).Encode(result)
	}
	if result.Probe != nil {
		run := result.Probe
		if _, err := fmt.Fprintf(output, "probe %s family=%s vantage=%s network=%s scope=node_path outcome=%s persisted=%t\n",
			run.Target, run.Family, run.Vantage.Name, run.Vantage.Network, run.Outcome, run.Persisted); err != nil {
			return err
		}
		for _, event := range run.Events {
			if _, err := fmt.Fprintf(output, "  %s: %s code=%s bytes=%d/%d duration=%s body=%s integrity=%t budget=%s at=%s\n",
				event.Stage, event.Outcome, event.ErrorCode, event.Bytes, event.ExpectedBytes, event.Duration,
				event.BodyDuration, event.Integrity, event.TimeBudget, event.ObservedAt.Format(time.RFC3339Nano)); err != nil {
				return err
			}
			if event.Certificate != nil {
				cert := event.Certificate
				if _, err := fmt.Fprintf(output, "    issuer_sha256=%s validity=%s..%s san_match=%t verified=%t alpn=%s\n",
					cert.IssuerSHA256, cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339),
					cert.SANMatch, cert.Verified, cert.ALPN); err != nil {
					return err
				}
			}
		}
	}
	if result.Diagnosis != nil {
		verdict := result.Diagnosis
		if _, err := fmt.Fprintf(output, "diagnosis: %s confidence=%s outcome=%s scope=%s/%s global=%t window=%s..%s\n",
			verdict.Verdict, verdict.Confidence, verdict.Outcome, verdict.Scope.Target, verdict.Scope.Family,
			verdict.Scope.Global, verdict.Scope.From.Format(time.RFC3339Nano), verdict.Scope.To.Format(time.RFC3339Nano)); err != nil {
			return err
		}
		for _, vantage := range verdict.Scope.Vantages {
			if _, err := fmt.Fprintf(output, "  vantage=%s network=%s kind=%s\n", vantage.Name, vantage.Network, vantage.Kind); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(output, "  missing_evidence: %v\n", verdict.MissingEvidence); err != nil {
			return err
		}
		for _, measurement := range verdict.Measurements {
			if _, err := fmt.Fprintf(output, "  %s/%s: bytes=%d body=%s bytes_per_second=%.2f\n", measurement.Vantage,
				measurement.Stage, measurement.Bytes, measurement.Duration, measurement.BytesPerSecond); err != nil {
				return err
			}
		}
	}
	if result.ExternalHTTPImported > 0 {
		if _, err := fmt.Fprintf(output, "external_http_imported: %d (not authorized ladder evidence)\n", result.ExternalHTTPImported); err != nil {
			return err
		}
	}
	if result.ErrorCode != "" {
		if _, err := fmt.Fprintf(output, "error_code: %s\n", result.ErrorCode); err != nil {
			return err
		}
	}
	return nil
}
