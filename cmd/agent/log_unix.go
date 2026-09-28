//go:build unix

package main

import (
	"io"
	"log/slog"

	"github.com/INFORENT-GmbH/host-agent/internal/brand"
	"github.com/INFORENT-GmbH/host-agent/internal/logging"
)

// newLogger writes to stderr, which systemd hands to the journal.
func newLogger(_ brand.Brand, level slog.Level, stderr io.Writer) (*slog.Logger, io.Closer) {
	return logging.New(stderr, level, logging.UnderJournal()), nil
}
