//go:build windows

package collect

import (
	"context"

	"github.com/shirou/gopsutil/v4/process"
)

// scanProcesses sums the working set per image name. Processes the agent may
// not open (protected system processes) are skipped.
func scanProcesses(ctx context.Context) (procScan, error) {
	procs, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return procScan{}, err
	}
	out := procScan{ByName: map[string]procUsage{}, Total: len(procs), Zombies: -1}
	for _, p := range procs {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		name, err := p.NameWithContext(ctx)
		if err != nil {
			continue
		}
		mi, err := p.MemoryInfoWithContext(ctx)
		if err != nil || mi == nil {
			continue
		}
		key := processName(name)
		u := out.ByName[key]
		u.Bytes += mi.RSS
		u.Count++
		out.ByName[key] = u
	}
	return out, nil
}
