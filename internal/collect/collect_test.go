package collect

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"

	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

func TestCounterRate(t *testing.T) {
	if v, ok := counterRate(100, 300, 2*time.Second); !ok || v != 100 {
		t.Errorf("got %v, %v", v, ok)
	}
	if _, ok := counterRate(300, 100, time.Second); ok {
		t.Error("counter reset must yield no value")
	}
	if _, ok := counterRate(100, 200, 0); ok {
		t.Error("zero elapsed must yield no value")
	}
}

func TestCPUPercents(t *testing.T) {
	before := cpu.TimesStat{User: 100, System: 50, Idle: 800, Iowait: 50}
	now := cpu.TimesStat{User: 150, System: 70, Idle: 900, Iowait: 60, Steal: 20}
	// dt = 200; idle+iowait delta = 110 → busy 90 = 45 %
	p, ok := CPUUsageBetween(before, now)
	if !ok {
		t.Fatal("no result")
	}
	if p.Busy != 45 || p.Iowait != 5 || p.Steal != 10 {
		t.Errorf("got %+v", p)
	}
	if _, ok := CPUUsageBetween(now, now); ok {
		t.Error("no elapsed CPU time must yield no value")
	}
}

func TestSelectMounts(t *testing.T) {
	parts := []disk.PartitionStat{
		{Device: "/dev/sda1", Mountpoint: "/", Fstype: "ext4"},
		{Device: "/dev/sda1", Mountpoint: "/srv/bind", Fstype: "ext4"},
		{Device: "/dev/sdb1", Mountpoint: "/var", Fstype: "xfs"},
		{Device: "tank/data", Mountpoint: "/tank/data", Fstype: "zfs"},
		{Device: "tmpfs", Mountpoint: "/run", Fstype: "tmpfs"},
		{Device: "overlay", Mountpoint: "/var/lib/docker/overlay2/x/merged", Fstype: "overlay"},
		{Device: "/dev/loop3", Mountpoint: "/snap/core/1", Fstype: "squashfs"},
		{Device: "srv:/export", Mountpoint: "/mnt/nfs", Fstype: "nfs4"},
		{Device: "/dev/sdc1", Mountpoint: "/var/lib/docker/volumes", Fstype: "ext4"},
	}
	var got []string
	for _, p := range selectMounts(parts) {
		got = append(got, p.Mountpoint)
	}
	want := []string{"/", "/tank/data", "/var"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestWholeDisk(t *testing.T) {
	sys := t.TempDir()
	for _, d := range []string{"sda", "nvme0n1", "md0", "loop0", "dm-0"} {
		if err := os.Mkdir(filepath.Join(sys, d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	c := &diskIOCollector{sysBlock: sys}
	for name, want := range map[string]bool{
		"sda": true, "nvme0n1": true, "md0": true,
		"sda1": false, "nvme0n1p1": false, "loop0": false, "dm-0": false,
	} {
		if got := c.wholeDisk(name); got != want {
			t.Errorf("wholeDisk(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestOperState(t *testing.T) {
	sys := t.TempDir()
	for iface, state := range map[string]string{"eth0": "up\n", "eth1": "down\n", "tun0": "unknown\n"} {
		dir := filepath.Join(sys, iface)
		if err := os.Mkdir(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "operstate"), []byte(state), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if up, ok := LinkUp(sys, "eth0"); !ok || !up {
		t.Error("eth0 should be up")
	}
	if up, ok := LinkUp(sys, "eth1"); !ok || up {
		t.Error("eth1 should be down")
	}
	if _, ok := LinkUp(sys, "tun0"); ok {
		t.Error("unknown state must not be reported")
	}
	if _, ok := LinkUp(sys, "missing"); ok {
		t.Error("missing interface must not be reported")
	}
}

func TestSkipIface(t *testing.T) {
	for name, want := range map[string]bool{
		"lo": true, "veth12ab": true, "tap100i0": true, "fwbr100i0": true, "docker0": true, "br-1a2b": true,
		"eth0": false, "eno1": false, "vmbr0": false, "bond0": false, "wg0": false,
	} {
		if got := SkipInterface(name); got != want {
			t.Errorf("SkipInterface(%q) = %v, want %v", name, got, want)
		}
	}
}

type fakeCollector struct {
	name string
	err  error
}

func (f fakeCollector) Name() string { return f.name }

func (f fakeCollector) Collect(context.Context, time.Time) ([]protocol.Sample, error) {
	return []protocol.Sample{sample("fake."+f.name, 1, nil)}, f.err
}

func TestRunDisabledAndErrors(t *testing.T) {
	boom := errors.New("boom")
	cs := []Collector{fakeCollector{name: "a"}, fakeCollector{name: "b", err: boom}, fakeCollector{name: "c"}}
	samples, err := Run(context.Background(), cs, []string{"c"}, time.Now())
	if !errors.Is(err, boom) || !strings.Contains(err.Error(), "b: boom") {
		t.Errorf("err = %v", err)
	}
	var names []string
	for _, s := range samples {
		names = append(names, s.Name)
	}
	// A failing collector's partial samples are kept; disabled ones never run.
	if !slices.Equal(names, []string{"fake.a", "fake.b"}) {
		t.Errorf("samples %v", names)
	}
}

// TestCollectLive runs the real collectors on the test machine and checks
// that the result is a valid protocol message.
func TestCollectLive(t *testing.T) {
	cs := Default()
	ctx := context.Background()
	start := time.Now()
	if _, err := Run(ctx, cs, nil, start); err != nil {
		t.Logf("first run: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	samples, err := Run(ctx, cs, nil, time.Now())
	if err != nil {
		t.Logf("second run: %v", err)
	}
	msg := &protocol.Metrics{Time: time.Now().UnixMilli(), Series: samples}
	if err := msg.Validate(); err != nil {
		t.Fatalf("collected metrics are not a valid message: %v", err)
	}
	have := map[string]bool{}
	for _, s := range samples {
		have[s.Name] = true
	}
	for _, name := range []string{"cpu.count", "cpu.util_percent", "load.1", "mem.total_bytes", "system.uptime_seconds", "time.synced"} {
		if !have[name] {
			t.Errorf("missing %s", name)
		}
	}
}
