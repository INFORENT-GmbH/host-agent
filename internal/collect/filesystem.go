package collect

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/disk"

	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

// skipFstypes are pseudo, image and container filesystems. Network
// filesystems are skipped as well: statfs on a dead NFS server blocks
// uninterruptibly and would stall the whole collection tick — they get their
// own check with a timeout later.
var skipFstypes = map[string]bool{
	"autofs": true, "binfmt_misc": true, "bpf": true, "cgroup": true, "cgroup2": true,
	"configfs": true, "debugfs": true, "devpts": true, "devtmpfs": true, "efivarfs": true,
	"fusectl": true, "hugetlbfs": true, "iso9660": true, "mqueue": true, "nsfs": true,
	"overlay": true, "proc": true, "pstore": true, "ramfs": true, "rpc_pipefs": true,
	"securityfs": true, "squashfs": true, "sysfs": true, "tmpfs": true, "tracefs": true,
	"nfs": true, "nfs4": true, "cifs": true, "smb3": true, "fuse.sshfs": true,
	"glusterfs": true, "ceph": true, "fuse.cephfs": true, "9p": true, "virtiofs": true,
}

// skipMountPrefixes are container and runtime internals.
var skipMountPrefixes = []string{"/var/lib/docker/", "/var/lib/containers/", "/run/", "/snap/", "/proc/", "/sys/"}

type filesystemCollector struct{}

func (filesystemCollector) Name() string { return "filesystem" }

func (filesystemCollector) Collect(ctx context.Context, _ time.Time) ([]protocol.Sample, error) {
	fss, err := Filesystems(ctx)
	// A fresh resolver per tick: a disk attached at runtime shows up with
	// its id on the next collection, not after an agent restart.
	ids := newDiskIDResolver()
	var out []protocol.Sample
	for _, fs := range fss {
		labels := map[string]string{"mount": fs.Mount, "fstype": fs.Fstype, "device": fs.Device}
		if id := ids.resolve(fs.Device); id != "" {
			labels["disk_id"] = id
		}
		out = append(out,
			sample("fs.size_bytes", float64(fs.Usage.Total), labels),
			sample("fs.used_bytes", float64(fs.Usage.Used), labels),
			sample("fs.avail_bytes", float64(fs.Usage.Free), labels),
		)
		// Some filesystems (btrfs, zfs) report no fixed inode table.
		if fs.Usage.InodesTotal > 0 {
			out = append(out,
				sample("fs.inodes_total", float64(fs.Usage.InodesTotal), labels),
				sample("fs.inodes_used", float64(fs.Usage.InodesUsed), labels),
			)
		}
	}
	return out, err
}

// Filesystem is one monitored mount with its usage.
type Filesystem struct {
	Mount, Fstype, Device string
	Usage                 disk.UsageStat
}

// Filesystems returns the mounts worth monitoring (see selectMounts) with
// their usage. Mounts whose statfs failed are left out and reported in err.
func Filesystems(ctx context.Context) ([]Filesystem, error) {
	parts, err := disk.PartitionsWithContext(ctx, false)
	if err != nil {
		return nil, err
	}
	var (
		out  []Filesystem
		errs []error
	)
	for _, p := range selectMounts(parts) {
		u, err := disk.UsageWithContext(ctx, p.Mountpoint)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p.Mountpoint, err))
			continue
		}
		out = append(out, Filesystem{Mount: p.Mountpoint, Fstype: p.Fstype, Device: p.Device, Usage: *u})
	}
	return out, errors.Join(errs...)
}

// selectMounts drops pseudo filesystems and keeps one mount per device —
// bind mounts and btrfs subvolumes would otherwise report the same space
// several times. The shortest mount point wins ("/" before "/srv/bind").
func selectMounts(parts []disk.PartitionStat) []disk.PartitionStat {
	byDevice := map[string]disk.PartitionStat{}
	for _, p := range parts {
		if skipFstypes[p.Fstype] || p.Mountpoint == "" || len(p.Mountpoint) > protocol.MaxLabelValue {
			continue
		}
		if skippedMount(p.Mountpoint) {
			continue
		}
		key := p.Device
		if key == "" || key == "none" {
			key = p.Mountpoint
		}
		if prev, ok := byDevice[key]; !ok || len(p.Mountpoint) < len(prev.Mountpoint) {
			byDevice[key] = p
		}
	}
	out := make([]disk.PartitionStat, 0, len(byDevice))
	for _, p := range byDevice {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Mountpoint < out[j].Mountpoint })
	return out
}

func skippedMount(mount string) bool {
	for _, prefix := range skipMountPrefixes {
		if strings.HasPrefix(mount+"/", prefix) {
			return true
		}
	}
	return false
}
