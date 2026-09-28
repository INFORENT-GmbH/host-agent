package collect

import (
	"context"
	"time"

	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"

	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

type memoryCollector struct{}

func (memoryCollector) Name() string { return "memory" }

// Collect reports "available" (what the kernel could hand out without
// swapping), not "free" — free memory is near zero on any healthy Linux box.
func (memoryCollector) Collect(ctx context.Context, _ time.Time) ([]protocol.Sample, error) {
	vm, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		return nil, err
	}
	out := []protocol.Sample{
		sample("mem.total_bytes", float64(vm.Total), nil),
		sample("mem.available_bytes", float64(vm.Available), nil),
	}
	if vm.Total > 0 {
		out = append(out, sample("mem.used_percent", 100*float64(vm.Total-vm.Available)/float64(vm.Total), nil))
	}
	sw, err := mem.SwapMemoryWithContext(ctx)
	if err != nil {
		return out, err
	}
	return append(out,
		sample("swap.total_bytes", float64(sw.Total), nil),
		sample("swap.used_bytes", float64(sw.Used), nil),
	), nil
}

type systemCollector struct{}

func (systemCollector) Name() string { return "system" }

func (systemCollector) Collect(ctx context.Context, _ time.Time) ([]protocol.Sample, error) {
	up, err := host.UptimeWithContext(ctx)
	if err != nil {
		return nil, err
	}
	boot, err := host.BootTimeWithContext(ctx)
	if err != nil {
		return nil, err
	}
	return []protocol.Sample{
		sample("system.uptime_seconds", float64(up), nil),
		sample("system.boot_time_seconds", float64(boot), nil),
	}, nil
}
