package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/juvenileslave/vpn/vpnctl/internal/alerts"
	"github.com/juvenileslave/vpn/vpnctl/internal/config"
	"github.com/juvenileslave/vpn/vpnctl/internal/metrics"
	"github.com/juvenileslave/vpn/vpnctl/internal/notify"
	"github.com/juvenileslave/vpn/vpnctl/internal/store"
	"github.com/juvenileslave/vpn/vpnctl/internal/telegram"
)

// Exit codes specific to metric evaluation. They are deliberately separate
// from the panel and probe codes: check reports the observed state.
const (
	exitAlertsFiring  = 4
	exitAlertsUnknown = 5
)

const (
	defaultMuteDuration = 24 * time.Hour
	maxOutboxRowsListed = 20
)

// runMetricsCommand dispatches the metrics and alerts command families from
// one switch case in Run.
func runMetricsCommand(command string, args []string, stdout, stderr io.Writer) int {
	switch command {
	case "metrics":
		return runMetrics(args, stdout, stderr)
	case "alerts":
		return runAlerts(args, stdout, stderr)
	default:
		return usageError(stderr, fmt.Sprintf("unknown command %q", command))
	}
}

func runMetrics(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return usageError(stderr, "missing metrics subcommand")
	}
	switch args[0] {
	case "check":
		return runMetricsCheck(args[1:], stdout, stderr)
	case "run":
		return runMetricsWorker(args[1:], stdout, stderr)
	default:
		return usageError(stderr, fmt.Sprintf("unknown metrics subcommand %q", args[0]))
	}
}

func runMetricsCheck(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("metrics check", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configPath := fs.String("config", "", "path to the configuration file")
	rulesPath := fs.String("rules", "", "path to the YAML rules file")
	format := fs.String("format", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
		return usageError(stderr, err.Error())
	}
	if fs.NArg() != 0 {
		return usageError(stderr, fmt.Sprintf("unexpected arguments: %q", fs.Args()))
	}
	if *configPath == "" || *rulesPath == "" {
		return usageError(stderr, "--config and --rules are required")
	}
	if *format != "text" && *format != "json" {
		return usageError(stderr, "--format must be text or json")
	}
	cfg, rules, code := loadMetricsInputs(*configPath, *rulesPath, stderr)
	if code != ExitOK {
		return code
	}
	client, err := metricsClient(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "metrics check failed: %s\n", err)
		return ExitError
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	results, err := alerts.Check(ctx, client, rules, time.Now().UTC())
	if err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Fprintln(stderr, "metrics check canceled")
			return ExitError
		}
		var verr *metrics.ValidationError
		if errors.As(err, &verr) {
			reportRulesError(stderr, *rulesPath, err)
			return ExitError
		}
		fmt.Fprintf(stderr, "metrics check failed: %s\n", err)
		return ExitError
	}

	if *format == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			fmt.Fprintf(stderr, "metrics check failed: %s\n", err)
			return ExitError
		}
	} else {
		for _, r := range results {
			writeCheckResult(stdout, r)
		}
	}
	return checkExitCode(results)
}

func writeCheckResult(w io.Writer, r alerts.CheckResult) {
	condition := r.Comparison + " " + strconv.FormatFloat(r.Threshold, 'g', -1, 64)
	switch r.State {
	case metrics.StateUnknown:
		fmt.Fprintf(w, "unknown rule=%s severity=%s reason=%s condition=%q\n",
			r.Rule, r.Severity, r.Reason, condition)
	default:
		fmt.Fprintf(w, "%s rule=%s severity=%s value=%s condition=%q labels=%s\n",
			r.State, r.Rule, r.Severity,
			strconv.FormatFloat(*r.Value, 'g', -1, 64), condition, alerts.FormatLabels(r.Labels))
	}
}

func checkExitCode(results []alerts.CheckResult) int {
	unknown := false
	for _, r := range results {
		switch r.State {
		case metrics.StateFiring:
			return exitAlertsFiring
		case metrics.StateUnknown:
			unknown = true
		}
	}
	if unknown {
		return exitAlertsUnknown
	}
	return ExitOK
}

func runMetricsWorker(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("metrics run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configPath := fs.String("config", "", "path to the configuration file")
	rulesPath := fs.String("rules", "", "path to the YAML rules file")
	if err := fs.Parse(args); err != nil {
		return usageError(stderr, err.Error())
	}
	if fs.NArg() != 0 {
		return usageError(stderr, fmt.Sprintf("unexpected arguments: %q", fs.Args()))
	}
	if *configPath == "" || *rulesPath == "" {
		return usageError(stderr, "--config and --rules are required")
	}
	cfg, rules, code := loadMetricsInputs(*configPath, *rulesPath, stderr)
	if code != ExitOK {
		return code
	}
	if cfg.Metrics == nil {
		fmt.Fprintln(stderr, "metrics run failed: metrics section is required in the configuration")
		return ExitError
	}
	if cfg.Alerts == nil {
		fmt.Fprintln(stderr, "metrics run failed: alerts section is required in the configuration")
		return ExitError
	}
	client, err := metricsClient(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "metrics run failed: %s\n", err)
		return ExitError
	}
	botToken, err := tokenFromEnv("bot token", cfg.Bot.TokenEnv)
	if err != nil {
		fmt.Fprintf(stderr, "metrics run failed: %s\n", err)
		return ExitError
	}
	var tgOpts []telegram.Option
	if cfg.Bot.APIBase != nil {
		tgOpts = append(tgOpts, telegram.WithBaseURL(cfg.Bot.APIBase))
	}
	telegramClient, err := telegram.New(botToken, &http.Client{}, tgOpts...)
	if err != nil {
		fmt.Fprintf(stderr, "metrics run failed: %s\n", err)
		return ExitError
	}
	sink, err := notify.NewAdminSink(telegramClient, cfg.Bot.Operators)
	if err != nil {
		fmt.Fprintf(stderr, "metrics run failed: %s\n", err)
		return ExitError
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	state, err := store.Open(ctx, cfg.Alerts.StateDB)
	if err != nil {
		fmt.Fprintf(stderr, "metrics run failed: open state store: %s\n", err)
		return ExitError
	}
	log := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: logLevel(cfg.LogLevel)}))
	worker, err := alerts.NewWorker(state, client, sink, rules, alerts.Config{
		Interval:     cfg.Metrics.Interval,
		Jitter:       cfg.Alerts.Jitter,
		Grace:        cfg.Alerts.Grace,
		FlapSamples:  cfg.Alerts.FlapSamples,
		Retention:    cfg.Alerts.Retention,
		OutboxMaxAge: cfg.Alerts.OutboxMaxAge,
		RetryBase:    cfg.Alerts.RetryBase,
		RetryMax:     cfg.Alerts.RetryMax,
		MaxAttempts:  cfg.Alerts.MaxAttempts,
		Scope:        cfg.Alerts.Scope,
		Log:          log,
	})
	if err != nil {
		state.Close()
		fmt.Fprintf(stderr, "metrics run failed: %s\n", err)
		return ExitError
	}

	runErr := worker.Run(ctx)
	closeErr := state.Close()
	if runErr != nil {
		fmt.Fprintf(stderr, "metrics worker stopped: %s\n", runErr)
		return ExitError
	}
	if closeErr != nil {
		fmt.Fprintf(stderr, "metrics worker stopped: close state store: %s\n", closeErr)
		return ExitError
	}
	fmt.Fprintln(stdout, "metrics worker stopped")
	return ExitOK
}

// loadMetricsInputs validates the configuration and all rules before any
// network request. It returns a non-zero exit code on failure.
func loadMetricsInputs(configPath, rulesPath string, stderr io.Writer) (config.Config, []metrics.Rule, int) {
	cfg, err := config.Load(configPath)
	if err != nil {
		reportConfigError(stderr, configPath, err)
		return config.Config{}, nil, ExitError
	}
	rules, err := alerts.LoadRulesFile(rulesPath)
	if err != nil {
		var verr *metrics.ValidationError
		if errors.As(err, &verr) {
			reportRulesError(stderr, rulesPath, err)
		} else {
			fmt.Fprintf(stderr, "rules invalid: %s\n  %s\n", rulesPath, err)
		}
		return config.Config{}, nil, ExitError
	}
	return cfg, rules, ExitOK
}

func reportRulesError(stderr io.Writer, path string, err error) {
	fmt.Fprintf(stderr, "rules invalid: %s\n", path)
	var verr *metrics.ValidationError
	if errors.As(err, &verr) {
		for _, p := range verr.Problems {
			fmt.Fprintf(stderr, "  %s\n", p)
		}
		return
	}
	fmt.Fprintf(stderr, "  %s\n", err)
}

// metricsClient builds the accepted metrics client. The bearer token is read
// only from the configured environment variable.
func metricsClient(cfg config.Config) (*metrics.Client, error) {
	if cfg.Metrics == nil {
		return nil, errors.New("metrics section is required in the configuration")
	}
	token := ""
	if cfg.Metrics.TokenEnv != "" {
		var err error
		token, err = tokenFromEnv("metrics token", cfg.Metrics.TokenEnv)
		if err != nil {
			return nil, err
		}
	}
	return metrics.NewClient(metrics.Options{
		BaseURL:     cfg.Metrics.Endpoint.String(),
		HTTPClient:  &http.Client{Timeout: cfg.Metrics.Timeout},
		Timeout:     cfg.Metrics.Timeout,
		BearerToken: token,
	})
}

func runAlerts(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return usageError(stderr, "missing alerts subcommand")
	}
	switch args[0] {
	case "list":
		return runAlertsList(args[1:], stdout, stderr)
	case "mute":
		return runAlertsMute(args[1:], stdout, stderr)
	default:
		return usageError(stderr, fmt.Sprintf("unknown alerts subcommand %q", args[0]))
	}
}

type alertStateView struct {
	Rule           string            `json:"rule"`
	State          string            `json:"state"`
	Severity       string            `json:"severity"`
	Value          float64           `json:"value"`
	Threshold      float64           `json:"threshold"`
	Labels         map[string]string `json:"labels,omitempty"`
	Since          time.Time         `json:"since"`
	LastChange     time.Time         `json:"last_change"`
	PendingState   string            `json:"pending_state,omitempty"`
	PendingSamples int               `json:"pending_samples,omitempty"`
	MissingSince   *time.Time        `json:"missing_since,omitempty"`
	Revision       int64             `json:"revision"`
}

type alertMuteView struct {
	Rule  string    `json:"rule"`
	Until time.Time `json:"until"`
}

type alertOutboxView struct {
	ID            int64     `json:"id"`
	Rule          string    `json:"rule"`
	Event         string    `json:"event"`
	Severity      string    `json:"severity"`
	Attempts      int       `json:"attempts"`
	NextAttemptAt time.Time `json:"next_attempt_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type alertsListView struct {
	States []alertStateView  `json:"states"`
	Mutes  []alertMuteView   `json:"mutes"`
	Outbox alertOutboxStatus `json:"outbox"`
}

type alertOutboxStatus struct {
	Pending int               `json:"pending"`
	Expired int               `json:"expired"`
	Rows    []alertOutboxView `json:"rows"`
}

func runAlertsList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("alerts list", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configPath := fs.String("config", "", "path to the configuration file")
	format := fs.String("format", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
		return usageError(stderr, err.Error())
	}
	if fs.NArg() != 0 {
		return usageError(stderr, fmt.Sprintf("unexpected arguments: %q", fs.Args()))
	}
	if *configPath == "" {
		return usageError(stderr, "--config is required")
	}
	if *format != "text" && *format != "json" {
		return usageError(stderr, "--format must be text or json")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		reportConfigError(stderr, *configPath, err)
		return ExitError
	}
	if cfg.Alerts == nil {
		fmt.Fprintln(stderr, "alerts list failed: alerts section is required in the configuration")
		return ExitError
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	state, err := store.Open(ctx, cfg.Alerts.StateDB)
	if err != nil {
		fmt.Fprintf(stderr, "alerts list failed: open state store: %s\n", err)
		return ExitError
	}
	defer state.Close()

	now := time.Now().UTC()
	states, err := state.ListAlertStates(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "alerts list failed: %s\n", err)
		return ExitError
	}
	mutes, err := state.ListAlertMutes(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "alerts list failed: %s\n", err)
		return ExitError
	}
	pending, expired, err := state.AlertOutboxStatus(ctx, now)
	if err != nil {
		fmt.Fprintf(stderr, "alerts list failed: %s\n", err)
		return ExitError
	}
	rows, err := state.ListOpenAlertOutbox(ctx, maxOutboxRowsListed)
	if err != nil {
		fmt.Fprintf(stderr, "alerts list failed: %s\n", err)
		return ExitError
	}

	view := alertsListView{Outbox: alertOutboxStatus{Pending: pending, Expired: expired}}
	for _, st := range states {
		v := alertStateView{
			Rule:           st.Rule,
			State:          st.State,
			Severity:       st.Severity,
			Value:          st.Value,
			Threshold:      st.Threshold,
			Labels:         st.Labels,
			Since:          st.Since,
			LastChange:     st.LastChange,
			PendingState:   st.PendingState,
			PendingSamples: st.PendingSamples,
			Revision:       st.Revision,
		}
		if !st.MissingSince.IsZero() {
			t := st.MissingSince
			v.MissingSince = &t
		}
		view.States = append(view.States, v)
	}
	for _, m := range mutes {
		if m.Until.After(now) {
			view.Mutes = append(view.Mutes, alertMuteView{Rule: m.Rule, Until: m.Until})
		}
	}
	for _, o := range rows {
		view.Outbox.Rows = append(view.Outbox.Rows, alertOutboxView{
			ID:            o.ID,
			Rule:          o.Rule,
			Event:         string(o.Event),
			Severity:      o.Severity,
			Attempts:      o.Attempts,
			NextAttemptAt: o.NextAttemptAt,
			ExpiresAt:     o.ExpiresAt,
		})
	}

	if *format == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(view); err != nil {
			fmt.Fprintf(stderr, "alerts list failed: %s\n", err)
			return ExitError
		}
		return ExitOK
	}
	for _, st := range view.States {
		pending := "-"
		if st.PendingState != "" {
			pending = fmt.Sprintf("%s/%d", st.PendingState, st.PendingSamples)
		}
		missing := "-"
		if st.MissingSince != nil {
			missing = st.MissingSince.Format(time.RFC3339)
		}
		fmt.Fprintf(stdout, "rule=%s state=%s severity=%s value=%g threshold=%g pending=%s missing_since=%s labels=%s\n",
			st.Rule, st.State, st.Severity, st.Value, st.Threshold, pending, missing, alerts.FormatLabels(st.Labels))
	}
	for _, m := range view.Mutes {
		fmt.Fprintf(stdout, "mute rule=%s until=%s\n", m.Rule, m.Until.Format(time.RFC3339))
	}
	fmt.Fprintf(stdout, "outbox pending=%d expired=%d\n", view.Outbox.Pending, view.Outbox.Expired)
	for _, o := range view.Outbox.Rows {
		fmt.Fprintf(stdout, "outbox id=%d rule=%s event=%s severity=%s attempts=%d next_attempt=%s expires=%s\n",
			o.ID, o.Rule, o.Event, o.Severity, o.Attempts,
			o.NextAttemptAt.Format(time.RFC3339), o.ExpiresAt.Format(time.RFC3339))
	}
	return ExitOK
}

func runAlertsMute(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("alerts mute", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configPath := fs.String("config", "", "path to the configuration file")
	rule := fs.String("rule", "", "rule name to mute")
	untilRaw := fs.String("until", "", "RFC3339 end of the mute window")
	if err := fs.Parse(args); err != nil {
		return usageError(stderr, err.Error())
	}
	if fs.NArg() != 0 {
		return usageError(stderr, fmt.Sprintf("unexpected arguments: %q", fs.Args()))
	}
	if *configPath == "" || *rule == "" {
		return usageError(stderr, "--config and --rule are required")
	}
	if !alerts.ValidRuleName(*rule) {
		return usageError(stderr, "--rule must be a valid metric rule name")
	}
	now := time.Now().UTC()
	until := now.Add(defaultMuteDuration)
	if *untilRaw != "" {
		parsed, err := time.Parse(time.RFC3339, *untilRaw)
		if err != nil {
			return usageError(stderr, "--until must be an RFC3339 timestamp")
		}
		until = parsed.UTC()
	}
	if !until.After(now) {
		return usageError(stderr, "--until must be in the future")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		reportConfigError(stderr, *configPath, err)
		return ExitError
	}
	if cfg.Alerts == nil {
		fmt.Fprintln(stderr, "alerts mute failed: alerts section is required in the configuration")
		return ExitError
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	state, err := store.Open(ctx, cfg.Alerts.StateDB)
	if err != nil {
		fmt.Fprintf(stderr, "alerts mute failed: open state store: %s\n", err)
		return ExitError
	}
	if err := state.SetAlertMute(ctx, *rule, until); err != nil {
		state.Close()
		fmt.Fprintf(stderr, "alerts mute failed: %s\n", err)
		return ExitError
	}
	if err := state.Close(); err != nil {
		fmt.Fprintf(stderr, "alerts mute failed: close state store: %s\n", err)
		return ExitError
	}
	fmt.Fprintf(stdout, "muted rule=%s until=%s\n", *rule, until.Format(time.RFC3339))
	return ExitOK
}
