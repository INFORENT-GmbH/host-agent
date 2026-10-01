//go:build linux

package collect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeBlockTree builds /dev/disk/by-id, /sys/block and /sys/class/block for:
// sda (sda1, sda2), sdb (whole-disk filesystem), sdc+sdd under md0, and
// dm-0 (LVM) on sda2.
func fakeBlockTree(t *testing.T) *diskIDResolver {
	t.Helper()
	root := t.TempDir()
	dev := filepath.Join(root, "dev")
	byID := filepath.Join(dev, "disk", "by-id")
	sysBlock := filepath.Join(root, "sys", "block")
	sysClass := filepath.Join(root, "sys", "class", "block")
	devices := filepath.Join(root, "sys", "devices")
	for _, d := range []string{byID, sysBlock, sysClass} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	mkdir := func(p string) {
		if err := os.MkdirAll(p, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	link := func(target, name string) {
		if err := os.Symlink(target, name); err != nil {
			t.Fatal(err)
		}
	}
	touch := func(p string) {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, disk := range []string{"sda", "sdb", "sdc", "sdd", "md0", "dm-0"} {
		mkdir(filepath.Join(devices, disk))
		link(filepath.Join(devices, disk), filepath.Join(sysBlock, disk))
		link(filepath.Join(devices, disk), filepath.Join(sysClass, disk))
	}
	for _, part := range []string{"sda1", "sda2"} {
		p := filepath.Join(devices, "sda", part)
		mkdir(p)
		touch(filepath.Join(p, "partition"))
		link(p, filepath.Join(sysClass, part))
	}
	for holder, slaves := range map[string][]string{"md0": {"sdc", "sdd"}, "dm-0": {"sda2"}} {
		mkdir(filepath.Join(devices, holder, "slaves"))
		for _, s := range slaves {
			link(filepath.Join(sysClass, s), filepath.Join(devices, holder, "slaves", s))
		}
	}
	for name, target := range map[string]string{
		"scsi-0QEMU_QEMU_HARDDISK_drive-scsi0":       "../../sda",
		"scsi-0QEMU_QEMU_HARDDISK_drive-scsi0-part1": "../../sda1",
		"scsi-0QEMU_QEMU_HARDDISK_drive-scsi1":       "../../sdb",
		"wwn-0x5000c500a1b2c3d4":                     "../../sdb",
		"ata-DISK_C":                                 "../../sdc",
		"ata-DISK_D":                                 "../../sdd",
		"md-uuid-1234":                               "../../md0",
		"dm-name-vg-root":                            "../../dm-0",
	} {
		link(target, filepath.Join(byID, name))
	}
	return &diskIDResolver{dev: dev, sysClass: sysClass, sysBlock: sysBlock}
}

func TestDiskIDs(t *testing.T) {
	r := fakeBlockTree(t)
	for device, want := range map[string]string{
		"/dev/sda1": "scsi-0QEMU_QEMU_HARDDISK_drive-scsi0",
		"/dev/sdb":  "scsi-0QEMU_QEMU_HARDDISK_drive-scsi1", // wwn- left out
		"/dev/md0":  "ata-DISK_C,ata-DISK_D",
		"/dev/dm-0": "scsi-0QEMU_QEMU_HARDDISK_drive-scsi0", // LVM on sda2
		"tank/data": "",                                     // zfs dataset
		"/dev/sdx":  "",                                     // unknown device
	} {
		if got := r.resolve(device); got != want {
			t.Errorf("resolve(%q) = %q, want %q", device, got, want)
		}
	}
}

func TestDiskIDsCappedAtLabelLimit(t *testing.T) {
	r := fakeBlockTree(t)
	r.byDisk = map[string][]string{"sdb": {strings.Repeat("a", 200), strings.Repeat("b", 100)}}
	if got := r.resolve("/dev/sdb"); got != strings.Repeat("a", 200) {
		t.Errorf("got %d chars, want the first id only", len(got))
	}
}
