package checks

import (
	"context"
	"errors"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"

	"github.com/INFORENT-GmbH/host-agent/internal/collect"
	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

// ---------------------------------------------------------------- cpu.load

type loadCheck struct{}

func (loadCheck) Plugin() string { return "cpu.load" }

func (loadCheck) Discover(context.Context) ([]protocol.DiscoveredItem, error) {
	return []protocol.DiscoveredItem{{Plugin: "cpu.load", Description: "CPU load"}}, nil
}

// Run reports the core count with the load so the gateway can judge load
// per core without a second lookup.
func (loadCheck) Run(ctx context.Context, _ time.Time) ([]protocol.CheckResult, error) {
	avg, err := load.AvgWithContext(ctx)
	if err != nil {
		return []protocol.CheckResult{unknown("cpu.load", "", err)}, nil
	}
	cores, err := cpu.CountsWithContext(ctx, true)
	if err != nil {
		return []protocol.CheckResult{unknown("cpu.load", "", err)}, nil
	}
	return one("cpu.load", "", map[string]float64{
		"load1": avg.Load1, "load5": avg.Load5, "load15": avg.Load15, "cpus": float64(cores),
	}), nil
}

// ---------------------------------------------------------------- cpu.util

type cpuUtilCheck struct {
	prev *cpu.TimesStat
}

func (*cpuUtilCheck) Plugin() string { return "cpu.util" }

func (*cpuUtilCheck) Discover(context.Context) ([]protocol.DiscoveredItem, error) {
	return []protocol.DiscoveredItem{{Plugin: "cpu.util", Description: "CPU utilization"}}, nil
}

func (c *cpuUtilCheck) Run(ctx context.Context, _ time.Time) ([]protocol.CheckResult, error) {
	t, err := cpu.TimesWithContext(ctx, false)
	if err != nil || len(t) != 1 {
		if err == nil {
			err = errors.New("no total CPU times")
		}
		return []protocol.CheckResult{unknown("cpu.util", "", err)}, nil
	}
	cur := t[0]
	defer func() { c.prev = &cur }()
	if c.prev == nil {
		return nil, nil
	}
	u, ok := collect.CPUUsageBetween(*c.prev, cur)
	if !ok {
		return nil, nil
	}
	return one("cpu.util", "", map[string]float64{
		"util_percent": u.Busy, "iowait_percent": u.Iowait, "steal_percent": u.Steal,
	}), nil
}

// ---------------------------------------------------------------- mem

type memCheck struct{}

func (memCheck) Plugin() string { return "mem" }

func (memCheck) Discover(context.Context) ([]protocol.DiscoveredItem, error) {
	return []protocol.DiscoveredItem{{Plugin: "mem", Description: "Memory"}}, nil
}

func (memCheck) Run(ctx context.Context, _ time.Time) ([]protocol.CheckResult, error) {
	vm, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		return []protocol.CheckResult{unknown("mem", "", err)}, nil
	}
	sw, err := mem.SwapMemoryWithContext(ctx)
	if err != nil {
		return []protocol.CheckResult{unknown("mem", "", err)}, nil
	}
	return one("mem", "", map[string]float64{
		"total_bytes":      float64(vm.Total),
		"available_bytes":  float64(vm.Available),
		"swap_total_bytes": float64(sw.Total),
		"swap_used_bytes":  float64(sw.Used),
	}), nil
}

// ---------------------------------------------------------------- uptime

type uptimeCheck struct{}

func (uptimeCheck) Plugin() string { return "uptime" }

func (uptimeCheck) Discover(context.Context) ([]protocol.DiscoveredItem, error) {
	return []protocol.DiscoveredItem{{Plugin: "uptime", Description: "Uptime"}}, nil
}

func (uptimeCheck) Run(ctx context.Context, _ time.Time) ([]protocol.CheckResult, error) {
	up, err := host.UptimeWithContext(ctx)
	if err != nil {
		return []protocol.CheckResult{unknown("uptime", "", err)}, nil
	}
	return one("uptime", "", map[string]float64{"uptime_seconds": float64(up)}), nil
}

// ---------------------------------------------------------------- timesync

type timeSyncCheck struct{}

func (timeSyncCheck) Plugin() string { return "timesync" }

func (timeSyncCheck) Discover(context.Context) ([]protocol.DiscoveredItem, error) {
	if _, err := collect.TimeSync(); errors.Is(err, errors.ErrUnsupported) {
		return nil, nil
	}
	return []protocol.DiscoveredItem{{Plugin: "timesync", Description: "Time synchronization"}}, nil
}

func (timeSyncCheck) Run(context.Context, time.Time) ([]protocol.CheckResult, error) {
	ts, err := collect.TimeSync()
	if errors.Is(err, errors.ErrUnsupported) {
		return nil, nil
	}
	if err != nil {
		return []protocol.CheckResult{unknown("timesync", "", err)}, nil
	}
	return one("timesync", "", map[string]float64{
		"synced":            boolValue(ts.Synced),
		"max_error_seconds": ts.MaxErrorSeconds,
		"est_error_seconds": ts.EstErrorSeconds,
	}), nil
}
