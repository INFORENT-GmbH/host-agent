//go:build linux

package collect

import (
	"context"
	"time"

	"golang.org/x/sys/unix"

	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

// TimeSyncState is the kernel's view of clock synchronisation.
type TimeSyncState struct {
	Synced          bool
	MaxErrorSeconds float64
	EstErrorSeconds float64
}

// TimeSync reads the kernel clock discipline via adjtimex(2) with no modes
// set (read-only, no privileges). chrony, ntpd and systemd-timesyncd all
// maintain it, so one reading covers every daemon.
func TimeSync() (TimeSyncState, error) {
	var tx unix.Timex
	state, err := unix.Adjtimex(&tx)
	if err != nil {
		return TimeSyncState{}, err
	}
	return TimeSyncState{
		Synced:          state != unix.TIME_ERROR && tx.Status&unix.STA_UNSYNC == 0,
		MaxErrorSeconds: float64(tx.Maxerror) / 1e6,
		EstErrorSeconds: float64(tx.Esterror) / 1e6,
	}, nil
}

type timeSyncCollector struct{}

func (timeSyncCollector) Name() string { return "timesync" }

func (timeSyncCollector) Collect(context.Context, time.Time) ([]protocol.Sample, error) {
	ts, err := TimeSync()
	if err != nil {
		return nil, err
	}
	return []protocol.Sample{
		sample("time.synced", boolValue(ts.Synced), nil),
		sample("time.max_error_seconds", ts.MaxErrorSeconds, nil),
		sample("time.est_error_seconds", ts.EstErrorSeconds, nil),
	}, nil
}
