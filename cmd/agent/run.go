package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/INFORENT-GmbH/host-agent/internal/agent"
	"github.com/INFORENT-GmbH/host-agent/internal/brand"
	"github.com/INFORENT-GmbH/host-agent/internal/buildinfo"
	"github.com/INFORENT-GmbH/host-agent/internal/config"
	"github.com/INFORENT-GmbH/host-agent/internal/logging"
)

// runAgent is what the systemd unit starts. It exits non-zero only when it
// cannot start at all; network trouble is handled inside, forever. It stops
// cleanly when ctx ends (SIGINT/SIGTERM, see main.go).
func runAgent(ctx context.Context, b brand.Brand, stderr io.Writer) int {
	cfg, err := config.Load(b.ConfigFile())
	if errors.Is(err, os.ErrNotExist) || (err == nil && !cfg.Enrolled()) {
		_, _ = fmt.Fprintf(stderr, "not enrolled: run `%s enroll -url https://<gateway> -token <token>` first\n", b.Name())
		return 1
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "config error: %v\n", err)
		return 1
	}
	level, err := logging.ParseLevel(cfg.Log.Level)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	// Where the log goes is the platform's business: the journal on Linux,
	// the Windows event log when the SCM started us (log_unix.go,
	// log_windows.go). closeLog is nil unless the destination owns a handle.
	log, closeLog := newLogger(b, level, stderr)
	if closeLog != nil {
		defer func() { _ = closeLog.Close() }()
	}
	log.Info("starting", "agent", b.Name(), "version", buildinfo.Version, "gateway", cfg.Server.URL)

	if err := agent.Run(ctx, b, cfg, log); err != nil {
		log.Error("agent stopped", "err", err)
		return 1
	}
	log.Info("stopped")
	return 0
}
