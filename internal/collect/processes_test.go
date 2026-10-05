package collect

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shirou/gopsutil/v4/mem"
)

func TestProcessSamplesTopN(t *testing.T) {
	got := processSamples(map[string]procUsage{
		"postgres": {Bytes: 300, Count: 8},
		"php-fpm":  {Bytes: 500, Count: 12},
		"sshd":     {Bytes: 10, Count: 2},
		"bash":     {Bytes: 300, Count: 1},
		"kthread":  {Bytes: 0, Count: 40},
	}, 3)
	var names []string
	for _, s := range got {
		if s.Name == "proc.mem_bytes" {
			names = append(names, s.Labels["name"])
		}
	}
	// Largest first, ties by name, empty usage never reported.
	if strings.Join(names, ",") != "php-fpm,bash,postgres" {
		t.Errorf("order %v", names)
	}
	if len(got) != 6 || got[1].Name != "proc.count" || got[1].Value != 12 {
		t.Errorf("samples %+v", got)
	}
}

func TestProcessName(t *testing.T) {
	cases := map[string]string{
		"nginx":                 "nginx",
		"  java ":               "java",
		"bad\x00\x1bname":       "bad??name",
		"a\xff\xfeb":            "a?b",
		"":                      "?",
		strings.Repeat("x", 99): strings.Repeat("x", maxProcessName),
	}
	for in, want := range cases {
		if got := processName(in); got != want {
			t.Errorf("processName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestProcessesCollectorThrottles(t *testing.T) {
	scans := 0
	c := &processesCollector{scan: func(context.Context) (procScan, error) {
		scans++
		return procScan{ByName: map[string]procUsage{"a": {Bytes: 1, Count: 1}}, Total: 1, Zombies: -1}, nil
	}}
	t0 := time.Unix(1_000_000, 0)
	for _, at := range []time.Duration{0, 10 * time.Second, 20 * time.Second, 30 * time.Second, 31 * time.Second} {
		s, err := c.Collect(context.Background(), t0.Add(at))
		if err != nil {
			t.Fatal(err)
		}
		if (at == 0 || at == 30*time.Second) != (len(s) > 0) {
			t.Errorf("at %v: %d samples", at, len(s))
		}
	}
	if scans != 2 {
		t.Errorf("scans = %d", scans)
	}
	// A clock that jumped back must not silence the collector.
	if s, _ := c.Collect(context.Background(), t0); len(s) == 0 {
		t.Error("no scan after the clock went backwards")
	}
}

func TestProcessesCollectorErrorRetries(t *testing.T) {
	fail := true
	c := &processesCollector{scan: func(context.Context) (procScan, error) {
		if fail {
			return procScan{}, errors.New("boom")
		}
		return procScan{ByName: map[string]procUsage{"a": {Bytes: 1, Count: 1}}, Total: 3, Zombies: 1}, nil
	}}
	t0 := time.Unix(1_000_000, 0)
	if _, err := c.Collect(context.Background(), t0); err == nil {
		t.Fatal("want error")
	}
	fail = false
	// The failed scan must not start the 30 s pause.
	s, err := c.Collect(context.Background(), t0.Add(10*time.Second))
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	got := map[string]float64{}
	for _, x := range s {
		if x.Labels == nil {
			got[x.Name] = x.Value
		}
	}
	if got["proc.total"] != 3 || got["proc.zombies"] != 1 {
		t.Errorf("totals %v", got)
	}
}

func TestProcessesCollectorUnsupported(t *testing.T) {
	c := &processesCollector{scan: func(context.Context) (procScan, error) {
		return procScan{}, errors.ErrUnsupported
	}}
	if s, err := c.Collect(context.Background(), time.Now()); err != nil || s != nil {
		t.Errorf("got %v, %v", s, err)
	}
}

func TestProcessesCollectorNoZombiesOnWindows(t *testing.T) {
	c := &processesCollector{scan: func(context.Context) (procScan, error) {
		return procScan{ByName: map[string]procUsage{}, Total: 5, Zombies: -1}, nil
	}}
	s, _ := c.Collect(context.Background(), time.Now())
	for _, x := range s {
		if x.Name == "proc.zombies" {
			t.Error("zombies reported without a zombie state")
		}
	}
}

func TestMemorySamplesBreakdown(t *testing.T) {
	vm := &mem.VirtualMemoryStat{Total: 1000, Available: 600, Free: 100, Buffers: 50, Cached: 450, Shared: 20}
	names := func(breakdown bool) map[string]float64 {
		out := map[string]float64{}
		for _, s := range memorySamples(vm, breakdown) {
			out[s.Name] = s.Value
		}
		return out
	}
	plain := names(false)
	if _, ok := plain["mem.free_bytes"]; ok || plain["mem.used_percent"] != 40 {
		t.Errorf("plain %v", plain)
	}
	full := names(true)
	if full["mem.free_bytes"] != 100 || full["mem.cached_bytes"] != 450 || full["mem.buffers_bytes"] != 50 || full["mem.shared_bytes"] != 20 {
		t.Errorf("breakdown %v", full)
	}
}
