package collect

import (
	"context"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/disk"

	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

// diskIOCollector reports throughput of whole block devices. Partitions and
// device-mapper volumes are left out: their I/O is already counted on the
// disk underneath, and summing both would double it.
type diskIOCollector struct {
	sysBlock string // /sys/block, overridable in tests
	prev     map[string]disk.IOCountersStat
	prevAt   time.Time
}

func (c *diskIOCollector) Name() string { return "diskio" }

func (c *diskIOCollector) Collect(ctx context.Context, now time.Time) ([]protocol.Sample, error) {
	counters, err := disk.IOCountersWithContext(ctx)
	if err != nil {
		return nil, err
	}
	elapsed := now.Sub(c.prevAt)
	var out []protocol.Sample
	cur := make(map[string]disk.IOCountersStat, len(counters))
	for name, s := range counters {
		if !c.wholeDisk(name) {
			continue
		}
		cur[name] = s
		before, ok := c.prev[name]
		if !ok {
			continue
		}
		labels := map[string]string{"device": name}
		for _, m := range []struct {
			metric    string
			prev, cur uint64
		}{
			{"disk.read_bytes_per_sec", before.ReadBytes, s.ReadBytes},
			{"disk.write_bytes_per_sec", before.WriteBytes, s.WriteBytes},
			{"disk.read_ops_per_sec", before.ReadCount, s.ReadCount},
			{"disk.write_ops_per_sec", before.WriteCount, s.WriteCount},
		} {
			if v, ok := counterRate(m.prev, m.cur, elapsed); ok {
				out = append(out, sample(m.metric, v, labels))
			}
		}
		// IoTime counts milliseconds the device was busy.
		if v, ok := counterRate(before.IoTime, s.IoTime, elapsed); ok {
			out = append(out, sample("disk.util_percent", clamp(v/10), labels))
		}
	}
	c.prev, c.prevAt = cur, now
	return out, nil
}

func (c *diskIOCollector) wholeDisk(name string) bool {
	for _, prefix := range []string{"loop", "ram", "zram", "dm-", "sr", "fd"} {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}
	return isWholeDisk(c.sysBlock, name)
}
