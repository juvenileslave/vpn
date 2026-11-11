// Package cli implements the vpnctl command line interface.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"runtime/debug"

	"github.com/juvenileslave/vpn/vpnctl/internal/config"
)

const usage = `usage:
  vpnctl version
  vpnctl config validate --config PATH
`

// Exit codes returned by Run.
const (
	ExitOK    = 0
	ExitError = 1
	ExitUsage = 2
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
		fmt.Fprintf(stderr, "config invalid: %s\n", *path)
		var verr *config.ValidationError
		if errors.As(err, &verr) {
			for _, p := range verr.Problems {
				fmt.Fprintf(stderr, "  %s\n", p)
			}
		} else {
			fmt.Fprintf(stderr, "  %s\n", err)
		}
		return ExitError
	}
	fmt.Fprintf(stdout, "config OK: %s\n", *path)
	return ExitOK
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
