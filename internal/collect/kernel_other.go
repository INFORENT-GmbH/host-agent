//go:build !linux

package collect

import (
	"context"
	"time"

	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

// kernelCollector reads Linux /proc counters; elsewhere it reports nothing.
type kernelCollector struct{}

func (kernelCollector) Name() string { return "kernel" }

func (kernelCollector) Collect(context.Context, time.Time) ([]protocol.Sample, error) {
	return nil, nil
}
