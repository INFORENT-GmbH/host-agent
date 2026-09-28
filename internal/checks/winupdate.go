package checks

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

// The Windows counterpart of the apt check: how many updates are waiting,
// and how many of them are security updates. Same two rules as apt —
//
//   - the agent never triggers a metadata refresh of its own. The Windows
//     Update client keeps a local cache and refreshes it on its own schedule;
//     the search below reads that cache (Online = false), so the check has no
//     network traffic and no side effects.
//   - the result is cached for an hour, errors are not, because the search
//     costs real CPU while the list of pending updates changes at most daily.
//
// The judgement is here and runs in the Linux tests; the COM call to Windows
// Update is in winupdate_windows.go.

// winUpdate is one pending update, reduced to what the judgement needs.
type winUpdate struct {
	Title string
	// Severity is MsrcSeverity: "Critical", "Important", "Moderate", "Low"
	// or empty. Microsoft only fills it for security updates, which is
	// precisely the distinction apt draws from the archive origin.
	Severity string
	// Downloaded updates are staged and install faster; useful to tell a
	// host that is merely waiting for its window from one that has not even
	// fetched anything.
	Downloaded bool
}

type winUpdateCheck struct {
	// search is replaced in tests.
	search func(ctx context.Context) ([]winUpdate, error)

	cached   *protocol.CheckResult
	cachedAt time.Time
}

func (*winUpdateCheck) Plugin() string { return "winupdate" }

func (c *winUpdateCheck) pending(ctx context.Context) ([]winUpdate, error) {
	if c.search != nil {
		return c.search(ctx)
	}
	return searchPendingUpdates(ctx)
}

func (c *winUpdateCheck) Discover(ctx context.Context) ([]protocol.DiscoveredItem, error) {
	if _, err := c.pending(ctx); errors.Is(err, errors.ErrUnsupported) {
		return nil, nil
	}
	return []protocol.DiscoveredItem{{Plugin: "winupdate", Description: "Windows updates"}}, nil
}

func (c *winUpdateCheck) Run(ctx context.Context, now time.Time) ([]protocol.CheckResult, error) {
	if c.cached != nil && now.Sub(c.cachedAt) < aptCacheTTL {
		return []protocol.CheckResult{*c.cached}, nil
	}
	updates, err := c.pending(ctx)
	if errors.Is(err, errors.ErrUnsupported) {
		return nil, nil
	}
	if err != nil {
		// Not cached: the next run tries again.
		return []protocol.CheckResult{unknown("winupdate", "", err)}, nil
	}
	r := evaluateUpdates(updates)
	c.cached, c.cachedAt = &r, now
	return []protocol.CheckResult{r}, nil
}

// evaluateUpdates counts what is waiting. A security update is one Microsoft
// rated Critical or Important — the two ratings that carry a patch-now
// expectation; Moderate and Low are counted as ordinary updates.
func evaluateUpdates(updates []winUpdate) protocol.CheckResult {
	var security, downloaded []string
	titles := make([]string, 0, len(updates))
	for _, u := range updates {
		titles = append(titles, u.Title)
		if isSecuritySeverity(u.Severity) {
			security = append(security, u.Title)
		}
		if u.Downloaded {
			downloaded = append(downloaded, u.Title)
		}
	}
	r := protocol.CheckResult{
		Plugin: "winupdate",
		Values: map[string]float64{
			"updates":          float64(len(titles)),
			"security_updates": float64(len(security)),
			"downloaded":       float64(len(downloaded)),
		},
	}
	switch {
	case len(security) > 0:
		r.Summary = listSummary(fmt.Sprintf("%d updates, %d security", len(titles), len(security)), security)
	case len(titles) > 0:
		r.Summary = listSummary(fmt.Sprintf("%d updates", len(titles)), titles)
	}
	return r
}

func isSecuritySeverity(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "important":
		return true
	}
	return false
}
