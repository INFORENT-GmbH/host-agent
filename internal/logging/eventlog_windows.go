//go:build windows

package logging

import (
	"errors"
	"io"
	"log/slog"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/eventlog"
)

// Event ids. Windows shows them in the event viewer's "Event ID" column;
// three fixed ids keep the log readable without a message DLL.
const (
	eventInfo    = 1
	eventWarning = 2
	eventError   = 3
)

// NewEventLog writes the agent's log to the Windows application event log,
// which is where a Windows administrator looks — the service has no console
// to write to, and a file in %ProgramData% would be a second place to
// remember. The source is registered on first use; that needs administrator
// rights, which the service has as LocalSystem. An already registered source
// is not an error.
func NewEventLog(source string, level slog.Level) (*slog.Logger, io.Closer, error) {
	err := eventlog.InstallAsEventCreate(source, eventlog.Info|eventlog.Warning|eventlog.Error)
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		// Registering may fail on a locked-down host; opening usually still
		// works and logs under a generic source, which beats losing the log.
		_ = err
	}
	elog, err := eventlog.Open(source)
	if err != nil {
		return nil, nil, err
	}
	sink := func(l slog.Level, line string) {
		switch {
		case l >= slog.LevelError:
			_ = elog.Error(eventError, line)
		case l >= slog.LevelWarn:
			_ = elog.Warning(eventWarning, line)
		default:
			_ = elog.Info(eventInfo, line)
		}
	}
	return NewSinkLogger(sink, level), elog, nil
}
