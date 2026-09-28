//go:build unix

package main

import (
	"context"
	"io"
	"os/signal"
	"syscall"

	"github.com/INFORENT-GmbH/host-agent/internal/brand"
)

// startAgent runs in the foreground until SIGINT or SIGTERM; systemd sends
// SIGTERM on `systemctl stop` and on the restart dpkg triggers mid-upgrade.
func startAgent(b brand.Brand, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return runAgent(ctx, b, stderr)
}
