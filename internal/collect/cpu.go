package collect

import (
	"context"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/load"

	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

// cpuCollector reports utilisation per core and in total. Guest time is
// already contained in user time on Linux and therefore not added again.
type cpuCollector struct {
	prev map[string]cpu.TimesStat
}

func (c *cpuCollector) Name() string { return "cpu" }

func (c *cpuCollector) Collect(ctx context.Context, _ time.Time) ([]protocol.Sample, error) {
	perCore, err := cpu.TimesWithContext(ctx, true)
	if err != nil {
		return nil, err
	}
	total, err := cpu.TimesWithContext(ctx, false)
	if err != nil {
		return nil, err
	}
	cur := make(map[string]cpu.TimesStat, len(perCore)+1)
	for _, t := range perCore {
		cur[strings.TrimPrefix(t.CPU, "cpu")] = t
	}
	if len(total) == 1 {
		cur["total"] = total[0]
	}

	out := []protocol.Sample{sample("cpu.count", float64(len(perCore)), nil)}
	for id, now := range cur {
		before, ok := c.prev[id]
		if !ok {
			continue
		}
		p, ok := CPUUsageBetween(before, now)
		if !ok {
			continue
		}
		labels := map[string]string{"cpu": id}
		out = append(out, sample("cpu.util_percent", p.Busy, labels))
		if id == "total" {
			out = append(out,
				sample("cpu.iowait_percent", p.Iowait, labels),
				sample("cpu.steal_percent", p.Steal, labels),
			)
		}
	}
	c.prev = cur
	return out, nil
}

// CPUUsage is the share of CPU time between two readings, in percent.
type CPUUsage struct{ Busy, Iowait, Steal float64 }

func cpuTotal(t cpu.TimesStat) float64 {
	return t.User + t.Nice + t.System + t.Idle + t.Iowait + t.Irq + t.Softirq + t.Steal
}

// CPUUsageBetween compares two readings of the same CPU.
func CPUUsageBetween(before, now cpu.TimesStat) (CPUUsage, bool) {
	dt := cpuTotal(now) - cpuTotal(before)
	if dt <= 0 {
		return CPUUsage{}, false
	}
	idle := (now.Idle + now.Iowait) - (before.Idle + before.Iowait)
	pct := func(v float64) float64 { return clamp(100 * v / dt) }
	return CPUUsage{
		Busy:   pct(dt - idle),
		Iowait: pct(now.Iowait - before.Iowait),
		Steal:  pct(now.Steal - before.Steal),
	}, true
}

func clamp(v float64) float64 {
	switch {
	case v < 0:
		return 0
	case v > 100:
		return 100
	}
	return v
}

type loadCollector struct{}

func (loadCollector) Name() string { return "load" }

func (loadCollector) Collect(ctx context.Context, _ time.Time) ([]protocol.Sample, error) {
	avg, err := load.AvgWithContext(ctx)
	if err != nil {
		return nil, err
	}
	return []protocol.Sample{
		sample("load.1", avg.Load1, nil),
		sample("load.5", avg.Load5, nil),
		sample("load.15", avg.Load15, nil),
	}, nil
}
