//go:build unix

package main

import (
	"fmt"
	"io"

	"github.com/INFORENT-GmbH/host-agent/internal/brand"
)

// serviceCommandHelp is empty: on Linux the systemd unit ships with the
// package, so there is nothing for the agent to register.
const serviceCommandHelp = ""

func serviceCommand(b brand.Brand, _ []string, _, stderr io.Writer) int {
	_, _ = fmt.Fprintf(stderr, "the service is managed by systemd here: systemctl enable --now %s\n", b.Unit())
	return 2
}
