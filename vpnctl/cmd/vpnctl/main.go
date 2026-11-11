// Command vpnctl is the vpnctl command line tool.
package main

import (
	"os"

	"github.com/juvenileslave/vpn/vpnctl/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
