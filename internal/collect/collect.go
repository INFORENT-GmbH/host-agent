// Package collect gathers the host's metrics. Collectors return raw values
// only; judging them (thresholds, states) is the gateway's job.
//
// Rate metrics (CPU utilisation, disk and network throughput) are computed
// from the difference to the previous call, so a collector's first call after
// start returns no rates — callers simply get fewer samples once.
package collect

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

// Collector produces samples. Implementations keep the counters they need
// for rates and are not safe for concurrent use.
type Collector interface {
	Name() string
	Collect(ctx context.Context, now time.Time) ([]protocol.Sample, error)
}

// Default returns every built-in collector in a stable order.
func Default() []Collector {
	return []Collector{
		&cpuCollector{},
		loadCollector{},
		memoryCollector{},
		filesystemCollector{},
		&diskIOCollector{},
		&networkCollector{},
		systemCollector{},
		timeSyncCollector{},
	}
}

// Names lists the collector names, e.g. for config validation and dump.
func Names(cs []Collector) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.Name()
	}
	return out
}

// Run calls every collector not in disabled. A failing collector does not
// stop the others; its error is returned joined with the rest.
func Run(ctx context.Context, cs []Collector, disabled []string, now time.Time) ([]protocol.Sample, error) {
	var (
		samples []protocol.Sample
		errs    []error
	)
	for _, c := range cs {
		if slices.Contains(disabled, c.Name()) {
			continue
		}
		s, err := c.Collect(ctx, now)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", c.Name(), err))
		}
		samples = append(samples, s...)
	}
	// Collectors iterate maps; a stable order keeps dumps diffable.
	slices.SortStableFunc(samples, func(a, b protocol.Sample) int {
		if c := strings.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		return strings.Compare(labelKey(a.Labels), labelKey(b.Labels))
	})
	return samples, errors.Join(errs...)
}

func labelKey(l map[string]string) string {
	keys := slices.Sorted(maps.Keys(l))
	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.WriteString(l[k])
		sb.WriteByte(0)
	}
	return sb.String()
}

func sample(name string, value float64, labels map[string]string) protocol.Sample {
	return protocol.Sample{Name: name, Labels: labels, Value: value}
}

// counterRate turns two readings of a monotonically increasing counter into
// a per-second rate. A counter that went backwards (reset, wrap, device
// replaced) yields no value rather than a huge negative spike.
func counterRate(prev, cur uint64, elapsed time.Duration) (float64, bool) {
	if elapsed <= 0 || cur < prev {
		return 0, false
	}
	return float64(cur-prev) / elapsed.Seconds(), true
}
