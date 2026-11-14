package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/juvenileslave/vpn/vpnctl/internal/config"
	"github.com/juvenileslave/vpn/vpnctl/internal/panel"
	"github.com/juvenileslave/vpn/vpnctl/internal/remnawave"
)

func runPanel(args []string, stdout, stderr io.Writer) int {
	mode := "plan"
	if len(args) != 0 && len(args[0]) != 0 && args[0][0] != '-' {
		mode = args[0]
		args = args[1:]
	}
	if mode != "plan" && mode != "show" && mode != "apply" {
		return usageError(stderr, "unknown panel subcommand")
	}
	flags := flag.NewFlagSet("panel", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "strict vpnctl configuration")
	bundlePath := flags.String("bundle", "", "renderer manifest.json")
	objectPath := flags.String("objects", "", "explicit panel object declarations")
	caPath := flags.String("ca-file", "", "additional trusted CA PEM")
	apply := flags.Bool("apply", false, "explicitly request writes")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, usage)
			return ExitOK
		}
		return usageError(stderr, "invalid panel flags")
	}
	if flags.NArg() != 0 || (*apply && mode != "apply") {
		return usageError(stderr, "invalid panel arguments")
	}
	// The pinned API ignores If-Match and has no atomic precondition. Refuse
	// before any file, token, database or network I/O, not after partial writes.
	if *apply {
		return reportPanelError(stderr, panel.ErrUnsupportedAtomicWrite)
	}
	if *configPath == "" || *bundlePath == "" || *objectPath == "" {
		return usageError(stderr, "--config, --bundle and --objects are required")
	}
	bundle, err := panel.LoadBundle(*bundlePath)
	if err != nil {
		return reportPanelError(stderr, err)
	}
	objects, err := panel.LoadObjects(*objectPath)
	if err != nil {
		return reportPanelError(stderr, err)
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(stderr, "panel failed: invalid configuration")
		return ExitError
	}
	clientHTTP, err := panelHTTPClient(*caPath)
	if err != nil {
		fmt.Fprintln(stderr, "panel failed: invalid trusted CA file")
		return ExitError
	}
	token, err := tokenFromEnv("panel token", cfg.Panel.TokenEnv)
	if err != nil {
		fmt.Fprintln(stderr, "panel failed: panel token environment variable is not set")
		return ExitError
	}
	client, err := remnawave.New(cfg.Panel.URL, token, clientHTTP)
	if err != nil {
		return reportPanelError(stderr, err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return panelRead(ctx, client, bundle, objects, mode, stdout, stderr)
}

func panelRead(
	ctx context.Context,
	reader panel.Reader,
	bundle panel.Bundle,
	objects panel.Objects,
	mode string,
	stdout io.Writer,
	stderr io.Writer,
) int {
	var report panel.Report
	var err error
	if mode == "show" {
		report, err = panel.Show(ctx, reader, bundle, objects)
	} else {
		report, err = panel.Plan(ctx, reader, bundle, objects)
	}
	if len(report.Objects) != 0 {
		report.Objects = report.SortedObjects()
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if encodeErr := encoder.Encode(report); encodeErr != nil {
			fmt.Fprintln(stderr, "panel failed: output write failed")
			return ExitError
		}
	}
	if err != nil {
		return reportPanelError(stderr, err)
	}
	return ExitOK
}

func panelHTTPClient(caPath string) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if caPath != "" {
		file, err := os.Open(caPath)
		if err != nil {
			return nil, panel.ErrInvalidInput
		}
		data, readErr := io.ReadAll(io.LimitReader(file, (1<<20)+1))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || len(data) == 0 || len(data) > 1<<20 {
			return nil, panel.ErrInvalidInput
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			return nil, panel.ErrInvalidInput
		}
		if !roots.AppendCertsFromPEM(data) {
			return nil, panel.ErrInvalidInput
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Transport: transport, Timeout: 15 * time.Second}, nil
}

func reportPanelError(stderr io.Writer, err error) int {
	code := ExitError
	category := "panel read failed"
	switch {
	case errors.Is(err, panel.ErrUnsupportedAtomicWrite):
		category = "pinned API has no atomic write precondition; apply refused before I/O"
		code = ExitRefused
	case errors.Is(err, panel.ErrConflict):
		category = "ownership or current-state conflict"
		code = ExitRefused
	case errors.Is(err, panel.ErrLossyUpdate):
		category = "prospective update would lose panel settings or static clients"
		code = ExitRefused
	case errors.Is(err, panel.ErrInvalidInput):
		category = "invalid bundle or object declarations"
	case errors.Is(err, remnawave.ErrUnauthorized):
		category = "panel token rejected (HTTP 401)"
	case errors.Is(err, remnawave.ErrForbidden):
		category = "panel access forbidden (HTTP 403)"
	case errors.Is(err, remnawave.ErrNotFound):
		category = "declared panel object not found (HTTP 404)"
	case errors.Is(err, remnawave.ErrRedirect):
		category = "panel redirect refused"
	case errors.Is(err, remnawave.ErrRateLimited):
		category = "panel rate limited (HTTP 429)"
	case errors.Is(err, remnawave.ErrServer):
		category = "panel server error"
	case errors.Is(err, remnawave.ErrResponseTooLarge):
		category = "panel response exceeds size limit"
	case errors.Is(err, remnawave.ErrMalformedResponse):
		category = "malformed panel response"
	case errors.Is(err, context.Canceled):
		category = "panel read canceled"
	case errors.Is(err, context.DeadlineExceeded):
		category = "panel read timed out"
	}
	fmt.Fprintln(stderr, "panel failed: "+category)
	return code
}
