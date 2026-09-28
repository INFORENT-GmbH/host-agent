package checks

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	sdbus "github.com/coreos/go-systemd/v22/dbus"

	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

// systemdCheck reports failed units overall ("systemd") and every enabled
// service on its own ("systemd.service"). It talks to systemd over D-Bus —
// a stable API, unlike parsing systemctl output.
type systemdCheck struct {
	// runDir is /run/systemd/system; its presence means systemd is PID 1.
	runDir string
	// list is replaced in tests.
	list func(ctx context.Context) ([]sdbus.UnitStatus, map[string]bool, error)

	// enabled is cached: asking systemd for unit files makes it scan every
	// unit directory (~1 s on a desktop-sized system), while enabling or
	// disabling a service is rare. Unit states are fetched on every run.
	enabled   map[string]bool
	enabledAt time.Time
}

const enabledCacheTTL = 10 * time.Minute

func (*systemdCheck) Plugin() string { return "systemd" }

func (c *systemdCheck) applies() bool {
	dir := c.runDir
	if dir == "" {
		dir = "/run/systemd/system"
	}
	_, err := os.Stat(dir)
	return err == nil
}

func (c *systemdCheck) units(ctx context.Context) ([]sdbus.UnitStatus, map[string]bool, error) {
	if c.list != nil {
		return c.list(ctx)
	}
	conn, err := sdbus.NewSystemConnectionContext(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()
	units, err := conn.ListUnitsContext(ctx)
	if err != nil {
		return nil, nil, err
	}
	if c.enabled == nil || time.Since(c.enabledAt) > enabledCacheTTL {
		enabled, err := enabledServices(ctx, conn)
		if err != nil {
			return nil, nil, err
		}
		c.enabled, c.enabledAt = enabled, time.Now()
	}
	return units, c.enabled, nil
}

func (c *systemdCheck) Discover(ctx context.Context) ([]protocol.DiscoveredItem, error) {
	if !c.applies() {
		return nil, nil
	}
	units, enabled, err := c.units(ctx)
	if err != nil {
		return nil, err
	}
	_, _, items := evaluateUnits(units, enabled)
	return items, nil
}

func (c *systemdCheck) Run(ctx context.Context, _ time.Time) ([]protocol.CheckResult, error) {
	if !c.applies() {
		return nil, nil
	}
	units, enabled, err := c.units(ctx)
	if err != nil {
		return []protocol.CheckResult{unknown("systemd", "", err)}, nil
	}
	summary, perUnit, _ := evaluateUnits(units, enabled)
	return append([]protocol.CheckResult{summary}, perUnit...), nil
}

// evaluateUnits is the pure part: the overall result, one result per
// enabled service, and the discovery items (summary + enabled services that
// are active now — a disabled-by-intent service stays out).
func evaluateUnits(units []sdbus.UnitStatus, enabled map[string]bool) (protocol.CheckResult, []protocol.CheckResult, []protocol.DiscoveredItem) {
	var failed []string
	var perUnit []protocol.CheckResult
	items := []protocol.DiscoveredItem{{Plugin: "systemd", Description: "Systemd units"}}
	for _, u := range units {
		if u.ActiveState == "failed" {
			failed = append(failed, u.Name)
		}
		if !strings.HasSuffix(u.Name, ".service") || !enabled[u.Name] {
			continue
		}
		perUnit = append(perUnit, protocol.CheckResult{
			Plugin:  "systemd.service",
			Item:    u.Name,
			Summary: Summary(u.ActiveState + " (" + u.SubState + ")"),
			Values: map[string]float64{
				"active": boolValue(u.ActiveState == "active"),
				"failed": boolValue(u.ActiveState == "failed"),
			},
		})
		if u.ActiveState == "active" {
			items = append(items, protocol.DiscoveredItem{Plugin: "systemd.service", Item: u.Name, Description: "Service " + u.Name})
		}
	}
	slices.Sort(failed)
	summary := protocol.CheckResult{
		Plugin: "systemd",
		Values: map[string]float64{"failed_units": float64(len(failed))},
	}
	if len(failed) > 0 {
		summary.Summary = listSummary("failed", failed)
	}
	return summary, perUnit, items
}

func enabledServices(ctx context.Context, conn *sdbus.Conn) (map[string]bool, error) {
	files, err := conn.ListUnitFilesByPatternsContext(ctx, []string{"enabled"}, []string{"*.service"})
	if err != nil {
		return nil, err
	}
	enabled := make(map[string]bool, len(files))
	for _, f := range files {
		name := filepath.Base(f.Path)
		// Template units (foo@.service) are not runnable by themselves.
		if !strings.HasSuffix(name, "@.service") {
			enabled[name] = true
		}
	}
	return enabled, nil
}
