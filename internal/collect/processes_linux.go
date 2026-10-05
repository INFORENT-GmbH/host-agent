//go:build linux

package collect

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func scanProcesses(ctx context.Context) (procScan, error) {
	return scanProcDir(ctx, "/proc")
}

// scanProcDir reads Name and RssAnon from every <pid>/status under root.
// Processes that exit mid-scan are skipped; kernel threads carry no RssAnon
// and count only towards Total/Zombies.
func scanProcDir(ctx context.Context, root string) (procScan, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return procScan{}, err
	}
	out := procScan{ByName: map[string]procUsage{}}
	for _, e := range entries {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		if !e.IsDir() || !isPID(e.Name()) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, e.Name(), "status")) // #nosec G304 -- numeric pid under /proc
		if err != nil {
			continue
		}
		st := parseProcStatus(data)
		if !st.valid {
			continue
		}
		out.Total++
		if st.zombie {
			out.Zombies++
		}
		if !st.user {
			continue
		}
		u := out.ByName[st.name]
		u.Bytes += st.anon
		u.Count++
		out.ByName[st.name] = u
	}
	return out, nil
}

func isPID(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

type procStatus struct {
	name   string
	anon   uint64 // private resident memory in bytes
	valid  bool   // had a Name line
	user   bool   // has an address space (RssAnon parsed) — not a kernel thread
	zombie bool
}

func parseProcStatus(data []byte) procStatus {
	var st procStatus
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		key, val, found := strings.Cut(sc.Text(), ":")
		if !found {
			continue
		}
		switch key {
		case "Name":
			st.name, st.valid = processName(strings.TrimSpace(val)), true
		case "State":
			st.zombie = strings.HasPrefix(strings.TrimSpace(val), "Z")
		case "RssAnon":
			fields := strings.Fields(val)
			if len(fields) == 0 {
				continue
			}
			if kb, err := strconv.ParseUint(fields[0], 10, 64); err == nil {
				st.anon, st.user = kb*1024, true
			}
		}
	}
	return st
}
