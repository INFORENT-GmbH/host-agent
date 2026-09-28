package logging

import (
	"log/slog"
	"testing"
)

// The sink handler formats every Windows event log entry, and our CI has no
// Windows runner — these tests are the only place it runs.
func TestSinkLoggerFormatsAndRoutes(t *testing.T) {
	type entry struct {
		level slog.Level
		line  string
	}
	var got []entry
	log := NewSinkLogger(func(l slog.Level, line string) {
		got = append(got, entry{l, line})
	}, slog.LevelInfo)

	log.Debug("dropped below the level")
	log.Info("starting", "agent", "acme-agent", "version", "1.5.0")
	log.With("host", "ns1").Warn("link down", "iface", "eth0")
	log.Error("agent stopped", "err", "connection refused")

	if len(got) != 3 {
		t.Fatalf("got %d entries, want 3 (debug must be dropped): %v", len(got), got)
	}
	if got[0].level != slog.LevelInfo || got[0].line != "starting agent=acme-agent version=1.5.0" {
		t.Errorf("first entry: %v %q", got[0].level, got[0].line)
	}
	// Attributes from With come before the record's own.
	if got[1].level != slog.LevelWarn || got[1].line != "link down host=ns1 iface=eth0" {
		t.Errorf("second entry: %v %q", got[1].level, got[1].line)
	}
	// A value with spaces is quoted, or the line cannot be read back.
	if got[2].level != slog.LevelError || got[2].line != `agent stopped err="connection refused"` {
		t.Errorf("third entry: %v %q", got[2].level, got[2].line)
	}
}

func TestSinkLoggerGroups(t *testing.T) {
	var lines []string
	log := NewSinkLogger(func(_ slog.Level, line string) { lines = append(lines, line) }, slog.LevelInfo)
	log.WithGroup("buffer").Info("flushed", "segments", 3)
	log.Info("sent", slog.Group("frame", "seq", 7))
	if want := "flushed buffer.segments=3"; lines[0] != want {
		t.Errorf("got %q, want %q", lines[0], want)
	}
	if want := "sent frame.seq=7"; lines[1] != want {
		t.Errorf("got %q, want %q", lines[1], want)
	}
}
