//go:build linux

package collect

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestKernelCollector(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"pressure/cpu":    "some avg10=1.50 avg60=0.80 avg300=0.10 total=1\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
		"pressure/memory": "some avg10=12.25 avg60=3.00 avg300=1.00 total=9\nfull avg10=4.50 avg60=1.00 avg300=0.20 total=5\n",
		"vmstat":          "nr_free_pages 1234\noom_kill 3\n",
		"stat":            "cpu  1 2 3\nprocs_running 4\nprocs_blocked 2\n",
		"sys/fs/file-nr":  "18386\t0\t9223372036854775807\n",
		"net/sockstat":    "sockets: used 2271\nTCP: inuse 238 orphan 0 tw 85 alloc 491 mem 0\nUDP: inuse 38 mem 1814\n",
	}
	for rel, body := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s, err := kernelCollector{root: root}.Collect(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, x := range s {
		got[x.Name] = x.Value
	}
	want := map[string]float64{
		"pressure.cpu_some_percent":    1.5,
		"pressure.memory_some_percent": 12.25,
		"pressure.memory_full_percent": 4.5,
		"mem.oom_kills":                3,
		"system.procs_running":         4,
		"system.procs_blocked":         2,
		"system.fds_open":              18386,
		"net.tcp_inuse":                238,
		"net.tcp_timewait":             85,
	}
	if len(got) != len(want) {
		t.Errorf("got %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
	// No io pressure file (old kernel): no io samples, no cpu_full ever.
	if _, ok := got["pressure.io_some_percent"]; ok {
		t.Error("io pressure without a source")
	}
}

func TestKernelCollectorNothingReadable(t *testing.T) {
	if _, err := (kernelCollector{root: t.TempDir()}).Collect(context.Background(), time.Now()); err == nil {
		t.Error("want an error when no counter is readable")
	}
}

func TestKernelCollectorLive(t *testing.T) {
	s, err := kernelCollector{}.Collect(context.Background(), time.Now())
	if err != nil || len(s) == 0 {
		t.Fatalf("got %d samples, %v", len(s), err)
	}
}
