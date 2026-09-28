//go:build linux

package collect

import (
	"os"
	"path/filepath"
	"strings"
)

// linkUp reads <sysNet>/<iface>/operstate (sysNet "" = /sys/class/net).
func linkUp(sysNet, iface string) (up bool, known bool) {
	root := sysNet
	if root == "" {
		root = "/sys/class/net"
	}
	b, err := os.ReadFile(filepath.Join(root, filepath.Base(iface), "operstate")) // #nosec G304 -- sysfs path, iface from kernel
	if err != nil {
		return false, false
	}
	switch strings.TrimSpace(string(b)) {
	case "up":
		return true, true
	case "down", "lowerlayerdown", "notpresent", "dormant":
		return false, true
	}
	return false, false
}

// isWholeDisk reports whether name is a whole device rather than a
// partition: partitions are not listed in /sys/block, only whole devices are.
func isWholeDisk(sysBlock, name string) bool {
	root := sysBlock
	if root == "" {
		root = "/sys/block"
	}
	_, err := os.Stat(filepath.Join(root, name))
	return err == nil
}
