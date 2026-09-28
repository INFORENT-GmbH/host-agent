//go:build windows

package main

import (
	"io"
	"log/slog"

	"golang.org/x/sys/windows/svc"

	"github.com/INFORENT-GmbH/host-agent/internal/brand"
	"github.com/INFORENT-GmbH/host-agent/internal/logging"
)

// newLogger writes to the Windows event log when the service control manager
// started us — a service has no console, so stderr would go nowhere. Started
// by hand in a console, the agent logs there as usual, which is what makes
// `<brand>-agent run` usable for debugging.
func newLogger(b brand.Brand, level slog.Level, stderr io.Writer) (*slog.Logger, io.Closer) {
	if inService, err := svc.IsWindowsService(); err != nil || !inService {
		return logging.New(stderr, level, false), nil
	}
	log, closer, err := logging.NewEventLog(b.Name(), level)
	if err != nil {
		// Without the event log the service would run blind; stderr is not a
		// destination here, but the error must not cost us the agent.
		return logging.New(stderr, level, false), nil
	}
	return log, closer
}
