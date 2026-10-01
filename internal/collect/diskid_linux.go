//go:build linux

package collect

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

// diskIDs names the physical disks a filesystem lives on, as their stable
// /dev/disk/by-id names — through partitions, LVM, dm-crypt and md RAID.
// "sdb" says nothing outside the host (the kernel numbers disks in probe
// order); the by-id name carries the serial or the hypervisor's drive id,
// so the portal can tell which attached disk a mount fills.
//
// Result: the ids of every disk underneath, sorted, comma-separated, cut at
// the label limit on a name boundary. "" when the device is no block device
// (zfs datasets, btrfs subvolume paths) or udev keeps no by-id links.
type diskIDResolver struct {
	dev, sysClass, sysBlock string // "" = /dev, /sys/class/block, /sys/block
	byDisk                  map[string][]string
}

func newDiskIDResolver() *diskIDResolver { return &diskIDResolver{} }

func (r *diskIDResolver) root(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// load maps whole-disk kernel names to their by-id link names. wwn- names
// are left out: they duplicate the serial-based name of the same disk.
func (r *diskIDResolver) load() {
	r.byDisk = map[string][]string{}
	dir := filepath.Join(r.root(r.dev, "/dev"), "disk", "by-id")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "wwn-") || strings.HasPrefix(name, "nvme-eui.") {
			continue
		}
		target, err := os.Readlink(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		kname := filepath.Base(target)
		if !isWholeDisk(r.sysBlock, kname) {
			continue // a partition link (…-part1)
		}
		r.byDisk[kname] = append(r.byDisk[kname], name)
	}
}

// resolve returns the label value for a mount's device path.
func (r *diskIDResolver) resolve(device string) string {
	if !strings.HasPrefix(device, "/dev/") {
		return ""
	}
	if r.byDisk == nil {
		r.load()
	}
	real, err := filepath.EvalSymlinks(device)
	if err != nil {
		real = device // tests hand in plain names
	}
	var ids []string
	for _, disk := range r.disksUnder(filepath.Base(real), 0) {
		ids = append(ids, r.byDisk[disk]...)
	}
	slices.Sort(ids)
	ids = slices.Compact(ids)
	out := ""
	for _, id := range ids {
		next := id
		if out != "" {
			next = out + "," + id
		}
		if len(next) > protocol.MaxLabelValue {
			break
		}
		out = next
	}
	return out
}

// disksUnder walks from a block device down to the whole disks carrying it:
// a partition to its parent, a dm/md device to its slaves.
func (r *diskIDResolver) disksUnder(name string, depth int) []string {
	if depth > 8 || name == "" || name == "." || name == "/" {
		return nil
	}
	sysClass := r.root(r.sysClass, "/sys/class/block")
	if _, err := os.Stat(filepath.Join(sysClass, name, "partition")); err == nil {
		// /sys/class/block/sda1 → …/block/sda/sda1: the parent is the directory above.
		real, err := filepath.EvalSymlinks(filepath.Join(sysClass, name))
		if err != nil {
			return nil
		}
		return r.disksUnder(filepath.Base(filepath.Dir(real)), depth+1)
	}
	slaves, _ := os.ReadDir(filepath.Join(sysClass, name, "slaves"))
	if len(slaves) > 0 {
		var out []string
		for _, s := range slaves {
			out = append(out, r.disksUnder(s.Name(), depth+1)...)
		}
		return out
	}
	if isWholeDisk(r.sysBlock, name) {
		return []string{name}
	}
	return nil
}
