//go:build windows

package collect

import (
	"slices"
	"strings"

	"github.com/shirou/gopsutil/v4/net"
)

// linkUp asks the interface list for the operational state; Windows has no
// sysfs, so sysNet is ignored. gopsutil maps the adapter's own status onto
// the "up" flag, which is what the Linux branch reads from operstate.
func linkUp(_, iface string) (up bool, known bool) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false, false
	}
	for _, i := range ifaces {
		if !strings.EqualFold(i.Name, iface) {
			continue
		}
		return slices.Contains(i.Flags, "up"), true
	}
	return false, false
}

// isWholeDisk is true for everything Windows reports: the counters come from
// the physical drives, not from volumes, so there are no partitions to sort
// out the way /sys/block does on Linux.
func isWholeDisk(_, _ string) bool { return true }
