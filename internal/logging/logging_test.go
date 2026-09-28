package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	for in, want := range map[string]slog.Level{
		"":      slog.LevelInfo,
		"info":  slog.LevelInfo,
		"DEBUG": slog.LevelDebug,
		"warn":  slog.LevelWarn,
		"error": slog.LevelError,
	} {
		got, err := ParseLevel(in)
		if err != nil || got != want {
			t.Errorf("ParseLevel(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := ParseLevel("loud"); err == nil {
		t.Error("expected error for unknown level")
	}
}

func TestJournalDropsTime(t *testing.T) {
	var plain, journal bytes.Buffer
	New(&plain, slog.LevelInfo, false).Info("hello")
	New(&journal, slog.LevelInfo, true).Info("hello")
	if !strings.Contains(plain.String(), "time=") {
		t.Errorf("plain output lacks time: %q", plain.String())
	}
	if strings.Contains(journal.String(), "time=") {
		t.Errorf("journal output still has time: %q", journal.String())
	}
}

func TestLevelFilters(t *testing.T) {
	var buf bytes.Buffer
	New(&buf, slog.LevelWarn, true).Info("hidden")
	if buf.Len() != 0 {
		t.Errorf("info logged at warn level: %q", buf.String())
	}
}
