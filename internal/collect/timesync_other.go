//go:build !linux

package collect

import (
	"context"
	"errors"
	"time"

	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

// TimeSyncState is the kernel's view of clock synchronisation.
type TimeSyncState struct {
	Synced          bool
	MaxErrorSeconds float64
	EstErrorSeconds float64
}

// TimeSync is not implemented outside Linux yet.
func TimeSync() (TimeSyncState, error) {
	return TimeSyncState{}, errors.ErrUnsupported
}

type timeSyncCollector struct{}

func (timeSyncCollector) Name() string { return "timesync" }

func (timeSyncCollector) Collect(context.Context, time.Time) ([]protocol.Sample, error) {
	return nil, nil
}
