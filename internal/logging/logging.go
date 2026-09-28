// Package logging builds the agent's slog logger. Under systemd the output
// goes to the journal via stdout/stderr, which timestamps every line itself —
// so the time attribute is dropped there instead of printed twice.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// ParseLevel maps the config value to a slog level.
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug, nil
	case "", "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("unknown log level %q", s)
}

// New returns a text logger writing to w. underJournal drops the timestamp.
func New(w io.Writer, level slog.Level, underJournal bool) *slog.Logger {
	opts := &slog.HandlerOptions{Level: level}
	if underJournal {
		opts.ReplaceAttr = func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		}
	}
	return slog.New(slog.NewTextHandler(w, opts))
}

// UnderJournal reports whether stderr is connected to the systemd journal.
func UnderJournal() bool {
	return os.Getenv("JOURNAL_STREAM") != ""
}
