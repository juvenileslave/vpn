// Package cli implements the vpnctl command line interface.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/juvenileslave/vpn/vpnctl/internal/bot"
	"github.com/juvenileslave/vpn/vpnctl/internal/config"
	"github.com/juvenileslave/vpn/vpnctl/internal/remnawave"
	"github.com/juvenileslave/vpn/vpnctl/internal/store"
	"github.com/juvenileslave/vpn/vpnctl/internal/telegram"
)

const usage = `usage:
  vpnctl version
  vpnctl config validate --config PATH
  vpnctl bot --config PATH
  vpnctl panel [plan|show|apply] --config PATH --bundle MANIFEST --objects PATH [--ca-file PATH] [--apply]
`

// Exit codes returned by Run.
const (
	ExitOK      = 0
	ExitError   = 1
	ExitUsage   = 2
	ExitRefused = 3
)

// Run executes vpnctl with args (without the program name) and returns the
// process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return usageError(stderr, "missing command")
	}
	switch args[0] {
	case "version":
		if len(args) != 1 {
			return usageError(stderr, "version takes no arguments")
		}
		fmt.Fprintf(stdout, "vpnctl %s\n", Version())
		return ExitOK
	case "config":
		return runConfig(args[1:], stdout, stderr)
	case "bot":
		return runBot(args[1:], stdout, stderr)
	case "panel":
		return runPanel(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return ExitOK
	default:
		return usageError(stderr, fmt.Sprintf("unknown command %q", args[0]))
	}
}

func runConfig(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return usageError(stderr, "missing config subcommand")
	}
	if args[0] != "validate" {
		return usageError(stderr, fmt.Sprintf("unknown config subcommand %q", args[0]))
	}

	fs := flag.NewFlagSet("config validate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("config", "", "path to the configuration file")
	if err := fs.Parse(args[1:]); err != nil {
		return usageError(stderr, err.Error())
	}
	if fs.NArg() != 0 {
		return usageError(stderr, fmt.Sprintf("unexpected arguments: %q", fs.Args()))
	}
	if *path == "" {
		return usageError(stderr, "--config is required")
	}

	if _, err := config.Load(*path); err != nil {
		reportConfigError(stderr, *path, err)
		return ExitError
	}
	fmt.Fprintf(stdout, "config OK: %s\n", *path)
	return ExitOK
}

func reportConfigError(stderr io.Writer, path string, err error) {
	fmt.Fprintf(stderr, "config invalid: %s\n", path)
	var verr *config.ValidationError
	if errors.As(err, &verr) {
		for _, p := range verr.Problems {
			fmt.Fprintf(stderr, "  %s\n", p)
		}
		return
	}
	fmt.Fprintf(stderr, "  %s\n", err)
}

func runBot(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("bot", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("config", "", "path to the configuration file")
	if err := fs.Parse(args); err != nil {
		return usageError(stderr, err.Error())
	}
	if fs.NArg() != 0 {
		return usageError(stderr, fmt.Sprintf("unexpected arguments: %q", fs.Args()))
	}
	if *path == "" {
		return usageError(stderr, "--config is required")
	}

	cfg, err := config.Load(*path)
	if err != nil {
		reportConfigError(stderr, *path, err)
		return ExitError
	}
	botToken, err := tokenFromEnv("bot token", cfg.Bot.TokenEnv)
	if err != nil {
		fmt.Fprintf(stderr, "bot failed: %s\n", err)
		return ExitError
	}
	panelToken, err := tokenFromEnv("panel token", cfg.Panel.TokenEnv)
	if err != nil {
		fmt.Fprintf(stderr, "bot failed: %s\n", err)
		return ExitError
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	panelHTTP := &http.Client{Timeout: 15 * time.Second}
	panelClient, err := remnawave.New(cfg.Panel.URL, panelToken, panelHTTP)
	if err != nil {
		fmt.Fprintf(stderr, "bot failed: %s\n", err)
		return ExitError
	}
	opts := []telegram.Option{}
	if cfg.Bot.APIBase != nil {
		opts = append(opts, telegram.WithBaseURL(cfg.Bot.APIBase))
	}
	telegramClient, err := telegram.New(botToken, &http.Client{}, opts...)
	if err != nil {
		fmt.Fprintf(stderr, "bot failed: %s\n", err)
		return ExitError
	}

	state, err := store.Open(ctx, cfg.Bot.StateDB)
	if err != nil {
		fmt.Fprintf(stderr, "bot failed: open state store: %s\n", err)
		return ExitError
	}
	log := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: logLevel(cfg.LogLevel)}))
	runner, err := bot.New(
		bot.Config{Operators: cfg.Bot.Operators, ChatIDs: cfg.Bot.ChatIDs},
		telegramClient, panelClient, state, bot.WithLogger(log))
	if err != nil {
		state.Close()
		fmt.Fprintf(stderr, "bot failed: %s\n", err)
		return ExitError
	}

	runErr := runner.Run(ctx)
	closeErr := state.Close()
	if runErr != nil {
		fmt.Fprintf(stderr, "bot stopped: %s\n", runErr)
		return ExitError
	}
	if closeErr != nil {
		fmt.Fprintf(stderr, "bot stopped: close state store: %s\n", closeErr)
		return ExitError
	}
	fmt.Fprintln(stdout, "bot stopped")
	return ExitOK
}

func tokenFromEnv(kind, name string) (string, error) {
	value, ok := os.LookupEnv(name)
	if !ok || value == "" {
		return "", fmt.Errorf("%s environment variable is not set", kind)
	}
	return value, nil
}

func logLevel(name string) slog.Level {
	switch name {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func usageError(stderr io.Writer, msg string) int {
	fmt.Fprintf(stderr, "vpnctl: %s\n%s", msg, usage)
	return ExitUsage
}

// Version reports the module version stamped into the binary, or "dev".
func Version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" || info.Main.Version == "(devel)" {
		return "dev"
	}
	return info.Main.Version
}
