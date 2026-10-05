package collect

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

// TopProcesses is how many process names the processes collector reports.
// Every name is a series in the time-series store, so the list stays short.
const TopProcesses = 10

// processInterval spaces the scans out: walking every process costs more than
// the other collectors together, and the portal only shows the current list.
// Ticks in between report nothing for this collector.
const processInterval = 30 * time.Second

// maxProcessName bounds the label value; Linux names are 15 bytes anyway,
// Windows image names can be longer.
const maxProcessName = 64

// procUsage is the memory of all processes sharing one name.
type procUsage struct {
	Bytes uint64
	Count int
}

// procScan is one walk over the process table. Zombies is -1 where the
// platform has no such state (Windows).
type procScan struct {
	ByName  map[string]procUsage
	Total   int
	Zombies int
}

// processesCollector reports the processes holding the most memory, summed
// per process name (all php-fpm workers are one line). Only the name is
// reported — never the command line, which may carry passwords.
//
// Alongside: proc.total (all processes) and, on Linux, proc.zombies.
//
// Linux counts private memory (RssAnon): shared memory and mapped files
// would be counted once per process otherwise, and they show up in
// mem.shared_bytes / mem.cached_bytes already. Windows counts the working
// set.
type processesCollector struct {
	last time.Time
	scan func(context.Context) (procScan, error)
}

func (*processesCollector) Name() string { return "processes" }

func (c *processesCollector) Collect(ctx context.Context, now time.Time) ([]protocol.Sample, error) {
	if !c.last.IsZero() && now.Sub(c.last) < processInterval && now.After(c.last) {
		return nil, nil
	}
	scan := c.scan
	if scan == nil {
		scan = scanProcesses
	}
	res, err := scan(ctx)
	if err != nil && res.Total == 0 {
		if errors.Is(err, errors.ErrUnsupported) {
			return nil, nil
		}
		return nil, err
	}
	c.last = now
	out := append(processSamples(res.ByName, TopProcesses), sample("proc.total", float64(res.Total), nil))
	if res.Zombies >= 0 {
		out = append(out, sample("proc.zombies", float64(res.Zombies), nil))
	}
	return out, err
}

// processSamples picks the n largest names (ties by name, for stable dumps).
func processSamples(byName map[string]procUsage, n int) []protocol.Sample {
	type entry struct {
		name string
		procUsage
	}
	list := make([]entry, 0, len(byName))
	for name, u := range byName {
		if u.Bytes > 0 {
			list = append(list, entry{name, u})
		}
	}
	slices.SortFunc(list, func(a, b entry) int {
		if a.Bytes != b.Bytes {
			if a.Bytes > b.Bytes {
				return -1
			}
			return 1
		}
		return strings.Compare(a.name, b.name)
	})
	if len(list) > n {
		list = list[:n]
	}
	out := make([]protocol.Sample, 0, 2*len(list))
	for _, e := range list {
		labels := map[string]string{"name": e.name}
		out = append(out,
			sample("proc.mem_bytes", float64(e.Bytes), labels),
			sample("proc.count", float64(e.Count), labels),
		)
	}
	return out
}

// processName makes a process name safe as a label value: valid UTF-8, no
// control characters, trimmed, bounded. A process can name itself anything.
func processName(raw string) string {
	s := strings.ToValidUTF8(raw, "?")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > maxProcessName {
		s = string([]rune(s)[:maxProcessName])
	}
	if s == "" {
		return "?"
	}
	return s
}
