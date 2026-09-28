//go:build linux

package checks

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// linkSpeedMbps reads /sys/class/net/<iface>/speed; virtual devices report
// -1 or refuse the read, which yields no value.
func linkSpeedMbps(sysNet, iface string) (float64, bool) {
	root := sysNet
	if root == "" {
		root = "/sys/class/net"
	}
	b, err := os.ReadFile(filepath.Join(root, filepath.Base(iface), "speed")) // #nosec G304 -- sysfs path, iface from kernel
	if err != nil {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || n <= 0 {
		return 0, false
	}
	return float64(n), true
}
