//go:build linux

package collect

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

// kernelCollector reads the kernel's own counters of contention — the values
// that answer "why is this machine slow" when CPU and memory look fine:
//
//   - pressure.* — Pressure Stall Information (kernel 4.20+, avg10): the
//     share of time tasks waited for CPU, memory or I/O. "some" = at least
//     one task stalled, "full" = all non-idle tasks stalled at once.
//   - mem.oom_kills — processes the OOM killer ended since boot (4.13+).
//   - system.procs_running / procs_blocked — runnable tasks and tasks in
//     uninterruptible sleep (usually waiting for I/O).
//   - system.fds_open — file handles allocated system-wide.
//   - net.tcp_inuse / net.tcp_timewait — TCP sockets in use and in TIME_WAIT.
//
// Every source is optional: a file the kernel lacks just yields no sample.
type kernelCollector struct {
	root string // "" = /proc; tests point it at a fixture tree
}

func (kernelCollector) Name() string { return "kernel" }

func (c kernelCollector) Collect(context.Context, time.Time) ([]protocol.Sample, error) {
	root := c.root
	if root == "" {
		root = "/proc"
	}
	read := func(rel string) []byte {
		b, err := os.ReadFile(filepath.Join(root, rel)) // #nosec G304 -- fixed paths under /proc
		if err != nil {
			return nil
		}
		return b
	}
	var out []protocol.Sample
	for _, res := range []string{"cpu", "memory", "io"} {
		some, full, ok := parsePressure(read("pressure/" + res))
		if !ok {
			continue
		}
		out = append(out, sample("pressure."+res+"_some_percent", some, nil))
		// The system-wide "full" line of cpu is always zero (or absent).
		if res != "cpu" {
			out = append(out, sample("pressure."+res+"_full_percent", full, nil))
		}
	}
	if v, ok := keyValue(read("vmstat"), "oom_kill"); ok {
		out = append(out, sample("mem.oom_kills", v, nil))
	}
	stat := read("stat")
	if v, ok := keyValue(stat, "procs_running"); ok {
		out = append(out, sample("system.procs_running", v, nil))
	}
	if v, ok := keyValue(stat, "procs_blocked"); ok {
		out = append(out, sample("system.procs_blocked", v, nil))
	}
	if f := strings.Fields(string(read("sys/fs/file-nr"))); len(f) > 0 {
		if v, err := strconv.ParseFloat(f[0], 64); err == nil {
			out = append(out, sample("system.fds_open", v, nil))
		}
	}
	if inuse, tw, ok := parseSockstat(read("net/sockstat")); ok {
		out = append(out,
			sample("net.tcp_inuse", inuse, nil),
			sample("net.tcp_timewait", tw, nil),
		)
	}
	if len(out) == 0 {
		return nil, errors.New("no kernel counters readable")
	}
	return out, nil
}

// parsePressure reads avg10 of the "some" and "full" lines of a PSI file.
func parsePressure(data []byte) (some, full float64, ok bool) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		v, found := strings.CutPrefix(fields[1], "avg10=")
		if !found {
			continue
		}
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "some":
			some, ok = f, true
		case "full":
			full = f
		}
	}
	return some, full, ok
}

// keyValue finds "key value" in a /proc file with one pair per line.
func keyValue(data []byte, key string) (float64, bool) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 2 && f[0] == key {
			v, err := strconv.ParseFloat(f[1], 64)
			return v, err == nil
		}
	}
	return 0, false
}

// parseSockstat reads "TCP: inuse N orphan N tw N alloc N mem N".
func parseSockstat(data []byte) (inuse, tw float64, ok bool) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 || f[0] != "TCP:" {
			continue
		}
		var haveInuse, haveTw bool
		for i := 1; i+1 < len(f); i += 2 {
			v, err := strconv.ParseFloat(f[i+1], 64)
			if err != nil {
				continue
			}
			switch f[i] {
			case "inuse":
				inuse, haveInuse = v, true
			case "tw":
				tw, haveTw = v, true
			}
		}
		return inuse, tw, haveInuse && haveTw
	}
	return 0, 0, false
}
