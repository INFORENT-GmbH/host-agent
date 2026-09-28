// Package checks discovers the services a host offers and produces their
// raw check data. Like the collectors, checks do not judge: they report
// values, and the gateway applies thresholds from its rules. The one
// exception is a check that cannot measure at all — it reports state
// UNKNOWN with the reason, because there is no value to judge.
package checks

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

// Check is one plugin. Implementations may keep state between runs (rates)
// and are not safe for concurrent use.
type Check interface {
	Plugin() string
	// Discover lists the items that exist right now. A check that does not
	// apply to this host (no apt, no systemd) returns no items and no error.
	Discover(ctx context.Context) ([]protocol.DiscoveredItem, error)
	// Run returns results for the current items. Rate-based checks return
	// nothing on their first run.
	Run(ctx context.Context, now time.Time) ([]protocol.CheckResult, error)
}

// Discover runs every check's discovery; one failing check does not hide
// the others.
func Discover(ctx context.Context, cs []Check) ([]protocol.DiscoveredItem, error) {
	var (
		items []protocol.DiscoveredItem
		errs  []error
	)
	for _, c := range cs {
		it, err := c.Discover(ctx)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", c.Plugin(), err))
		}
		items = append(items, it...)
	}
	slices.SortFunc(items, func(a, b protocol.DiscoveredItem) int {
		return cmp.Or(strings.Compare(a.Plugin, b.Plugin), strings.Compare(a.Item, b.Item))
	})
	return items, errors.Join(errs...)
}

// Run runs every check.
func Run(ctx context.Context, cs []Check, now time.Time) ([]protocol.CheckResult, error) {
	var (
		results []protocol.CheckResult
		errs    []error
	)
	for _, c := range cs {
		r, err := c.Run(ctx, now)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", c.Plugin(), err))
		}
		results = append(results, r...)
	}
	slices.SortFunc(results, func(a, b protocol.CheckResult) int {
		return cmp.Or(strings.Compare(a.Plugin, b.Plugin), strings.Compare(a.Item, b.Item))
	})
	return results, errors.Join(errs...)
}

// unknown reports a check that could not measure.
func unknown(plugin, item string, err error) protocol.CheckResult {
	s := protocol.StateUnknown
	return protocol.CheckResult{Plugin: plugin, Item: item, State: &s, Summary: Summary(err.Error())}
}

// Summary makes s fit protocol limits: control characters other than
// newline/tab become spaces, and it is cut to MaxSummary runes.
func Summary(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return ' '
		}
		return r
	}, s)
	if utf8.RuneCountInString(s) <= protocol.MaxSummary {
		return s
	}
	r := []rune(s)
	return string(r[:protocol.MaxSummary-1]) + "…"
}

// listSummary renders "prefix: a, b, c (+N more)" within the summary limit.
func listSummary(prefix string, names []string) string {
	var sb strings.Builder
	sb.WriteString(prefix)
	for i, n := range names {
		sep := ", "
		if i == 0 {
			sep = ": "
		}
		more := fmt.Sprintf(" (+%d more)", len(names)-i)
		if utf8.RuneCountInString(sb.String())+len(sep)+utf8.RuneCountInString(n)+len(more) > protocol.MaxSummary {
			sb.WriteString(more)
			break
		}
		sb.WriteString(sep)
		sb.WriteString(n)
	}
	return Summary(sb.String())
}

func one(plugin, item string, values map[string]float64) []protocol.CheckResult {
	return []protocol.CheckResult{{Plugin: plugin, Item: item, Values: values}}
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
