package checks

import (
	"context"
	"time"

	"github.com/shirou/gopsutil/v4/net"

	"github.com/INFORENT-GmbH/host-agent/internal/collect"
	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

// ---------------------------------------------------------------- df

type dfCheck struct{}

func (dfCheck) Plugin() string { return "df" }

// Discover returns the mounts the filesystem collector monitors; a mount
// whose statfs failed right now is simply not rediscovered this round, and
// the gateway keeps it until the agent stops reporting it for good.
func (dfCheck) Discover(ctx context.Context) ([]protocol.DiscoveredItem, error) {
	fss, err := collect.Filesystems(ctx)
	items := make([]protocol.DiscoveredItem, 0, len(fss))
	for _, fs := range fss {
		items = append(items, protocol.DiscoveredItem{Plugin: "df", Item: fs.Mount, Description: "Filesystem " + fs.Mount})
	}
	return items, err
}

func (dfCheck) Run(ctx context.Context, _ time.Time) ([]protocol.CheckResult, error) {
	fss, err := collect.Filesystems(ctx)
	out := make([]protocol.CheckResult, 0, len(fss))
	for _, fs := range fss {
		v := map[string]float64{
			"size_bytes":  float64(fs.Usage.Total),
			"used_bytes":  float64(fs.Usage.Used),
			"avail_bytes": float64(fs.Usage.Free),
		}
		if fs.Usage.InodesTotal > 0 {
			v["inodes_total"] = float64(fs.Usage.InodesTotal)
			v["inodes_used"] = float64(fs.Usage.InodesUsed)
		}
		out = append(out, protocol.CheckResult{Plugin: "df", Item: fs.Mount, Values: v})
	}
	return out, err
}

// ---------------------------------------------------------------- if

type ifCheck struct {
	sysNet string // /sys/class/net, overridable in tests
	prev   map[string]net.IOCountersStat
	prevAt time.Time
}

func (*ifCheck) Plugin() string { return "if" }

// Discover follows Checkmk: only interfaces that are up at discovery time
// become services, so an unused port does not start out critical.
func (c *ifCheck) Discover(ctx context.Context) ([]protocol.DiscoveredItem, error) {
	counters, err := net.IOCountersWithContext(ctx, true)
	if err != nil {
		return nil, err
	}
	var items []protocol.DiscoveredItem
	for _, s := range counters {
		if collect.SkipInterface(s.Name) {
			continue
		}
		if up, known := collect.LinkUp(c.sysNet, s.Name); known && up {
			items = append(items, protocol.DiscoveredItem{Plugin: "if", Item: s.Name, Description: "Interface " + s.Name})
		}
	}
	return items, nil
}

func (c *ifCheck) Run(ctx context.Context, now time.Time) ([]protocol.CheckResult, error) {
	counters, err := net.IOCountersWithContext(ctx, true)
	if err != nil {
		return nil, err
	}
	elapsed := now.Sub(c.prevAt)
	cur := make(map[string]net.IOCountersStat, len(counters))
	var out []protocol.CheckResult
	for _, s := range counters {
		if collect.SkipInterface(s.Name) {
			continue
		}
		cur[s.Name] = s
		v := map[string]float64{}
		if up, known := collect.LinkUp(c.sysNet, s.Name); known {
			v["link_up"] = boolValue(up)
		}
		if speed, ok := linkSpeedMbps(c.sysNet, s.Name); ok {
			v["speed_mbps"] = speed
		}
		if before, ok := c.prev[s.Name]; ok && elapsed > 0 {
			for key, pair := range map[string][2]uint64{
				"rx_bytes_per_sec":  {before.BytesRecv, s.BytesRecv},
				"tx_bytes_per_sec":  {before.BytesSent, s.BytesSent},
				"rx_errors_per_sec": {before.Errin, s.Errin},
				"tx_errors_per_sec": {before.Errout, s.Errout},
				"rx_drops_per_sec":  {before.Dropin, s.Dropin},
				"tx_drops_per_sec":  {before.Dropout, s.Dropout},
			} {
				if pair[1] >= pair[0] {
					v[key] = float64(pair[1]-pair[0]) / elapsed.Seconds()
				}
			}
		}
		if len(v) > 0 {
			out = append(out, protocol.CheckResult{Plugin: "if", Item: s.Name, Values: v})
		}
	}
	c.prev, c.prevAt = cur, now
	return out, nil
}

// linkSpeedMbps is the negotiated speed of an interface, where the platform
// can say (speed_linux.go, speed_windows.go). Virtual devices have none, and
// a missing value is reported as such rather than as zero — zero would look
// like a dead link to a rule.
