package collect

import (
	"context"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/net"

	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

// skipIfacePrefixes are per-container or per-VM interfaces that come and go
// with workloads (Docker veth pairs, Proxmox tap/firewall bridges) and would
// flood the series list. Physical NICs and host bridges such as vmbr0 carry
// the aggregate traffic; Docker's NAT bridges (docker0, br-*) are left out
// with the containers behind them.
var skipIfacePrefixes = []string{"lo", "veth", "tap", "fwbr", "fwpr", "fwln", "docker", "br-", "virbr", "cali", "flannel", "cni"}

type networkCollector struct {
	sysNet string // /sys/class/net, overridable in tests
	prev   map[string]net.IOCountersStat
	prevAt time.Time
}

func (c *networkCollector) Name() string { return "network" }

func (c *networkCollector) Collect(ctx context.Context, now time.Time) ([]protocol.Sample, error) {
	counters, err := net.IOCountersWithContext(ctx, true)
	if err != nil {
		return nil, err
	}
	elapsed := now.Sub(c.prevAt)
	var out []protocol.Sample
	cur := make(map[string]net.IOCountersStat, len(counters))
	for _, s := range counters {
		if SkipInterface(s.Name) {
			continue
		}
		cur[s.Name] = s
		labels := map[string]string{"iface": s.Name}
		if up, ok := LinkUp(c.sysNet, s.Name); ok {
			out = append(out, sample("net.link_up", boolValue(up), labels))
		}
		before, ok := c.prev[s.Name]
		if !ok {
			continue
		}
		for _, m := range []struct {
			metric    string
			prev, cur uint64
		}{
			{"net.rx_bytes_per_sec", before.BytesRecv, s.BytesRecv},
			{"net.tx_bytes_per_sec", before.BytesSent, s.BytesSent},
			{"net.rx_errors_per_sec", before.Errin, s.Errin},
			{"net.tx_errors_per_sec", before.Errout, s.Errout},
			{"net.rx_drops_per_sec", before.Dropin, s.Dropin},
			{"net.tx_drops_per_sec", before.Dropout, s.Dropout},
		} {
			if v, ok := counterRate(m.prev, m.cur, elapsed); ok {
				out = append(out, sample(m.metric, v, labels))
			}
		}
	}
	c.prev, c.prevAt = cur, now
	return out, nil
}

// SkipInterface reports whether iface is a workload interface that neither
// metrics nor checks cover.
func SkipInterface(name string) bool {
	for _, prefix := range skipIfacePrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// LinkUp reports whether an interface carries a link. The second result is
// false when the state is unknown — common for tun devices and some virtual
// NICs — or unreadable. Where the answer comes from is platform-specific
// (linkstate_linux.go, linkstate_windows.go); sysNet only means anything on
// Linux, where tests point it at a fake sysfs.
func LinkUp(sysNet, iface string) (up bool, known bool) {
	return linkUp(sysNet, iface)
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
