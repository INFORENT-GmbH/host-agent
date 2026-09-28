package checks

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

// The Windows counterpart of the systemd check: the overall picture under
// "services", every automatically started service on its own under
// "services.service". Discovery follows the same rule as systemd's — a
// service is worth watching when it is meant to start by itself AND runs
// right now, so a service an administrator deliberately disabled stays out.
//
// The judgement lives in this untagged file so the tests cover it on Linux as
// well; only the enumeration is Windows-only (services_windows.go).

// Service start types and states, as the Windows service control manager
// reports them. Repeated here rather than imported from x/sys/windows so
// this file — and its tests — build on every platform.
const (
	serviceStartAuto     = 2 // SERVICE_AUTO_START
	serviceStateStopped  = 1 // SERVICE_STOPPED
	serviceStateRunning  = 4 // SERVICE_RUNNING
	serviceStatePaused   = 7 // SERVICE_PAUSED
	serviceNoExitCode    = 0
	serviceExitCodeInSvc = 1066 // ERROR_SERVICE_SPECIFIC_ERROR
)

// winService is one entry of the service control manager's list.
type winService struct {
	Name        string
	DisplayName string
	StartType   uint32
	State       uint32
	// ExitCode is Win32ExitCode; 1066 means the service reported its own
	// error code, which the SCM keeps in ServiceSpecificExitCode.
	ExitCode         uint32
	SpecificExitCode uint32
	// DelayedAutoStart services still count as automatic — they are simply
	// started late, and a boot-time snapshot would otherwise call them failed.
	DelayedAutoStart bool
}

type servicesCheck struct {
	// list is replaced in tests; the default enumerates the real SCM.
	list func(ctx context.Context) ([]winService, error)
}

func (*servicesCheck) Plugin() string { return "services" }

func (c *servicesCheck) services(ctx context.Context) ([]winService, error) {
	if c.list != nil {
		return c.list(ctx)
	}
	return listServices(ctx)
}

func (c *servicesCheck) Discover(ctx context.Context) ([]protocol.DiscoveredItem, error) {
	svcs, err := c.services(ctx)
	if errors.Is(err, errors.ErrUnsupported) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_, _, items := evaluateServices(svcs)
	return items, nil
}

func (c *servicesCheck) Run(ctx context.Context, _ time.Time) ([]protocol.CheckResult, error) {
	svcs, err := c.services(ctx)
	if errors.Is(err, errors.ErrUnsupported) {
		return nil, nil
	}
	if err != nil {
		return []protocol.CheckResult{unknown("services", "", err)}, nil
	}
	summary, per, _ := evaluateServices(svcs)
	return append([]protocol.CheckResult{summary}, per...), nil
}

// evaluateServices is the pure part. "Failed" means: meant to start by
// itself, but not running — plus the exit code the SCM kept, because a
// service that stopped with an error is the interesting case, and Windows
// reports that only here.
func evaluateServices(svcs []winService) (protocol.CheckResult, []protocol.CheckResult, []protocol.DiscoveredItem) {
	var failed []string
	var per []protocol.CheckResult
	items := []protocol.DiscoveredItem{{Plugin: "services", Description: "Windows services"}}
	for _, s := range svcs {
		if s.StartType != serviceStartAuto {
			continue
		}
		running := s.State == serviceStateRunning
		if !running {
			failed = append(failed, s.Name)
		}
		per = append(per, protocol.CheckResult{
			Plugin:  "services.service",
			Item:    s.Name,
			Summary: Summary(serviceSummary(s)),
			Values: map[string]float64{
				"running":   boolValue(running),
				"failed":    boolValue(!running),
				"exit_code": float64(serviceExitCode(s)),
				// Delayed-start services are stopped for the first minutes
				// after a boot by design. They stay in the set — a delayed
				// service that never comes up is exactly what should be
				// noticed — but the gateway can grace them by this value
				// instead of guessing from the name.
				"delayed": boolValue(s.DelayedAutoStart),
			},
		})
		if running {
			desc := "Service " + s.Name
			if s.DisplayName != "" && !strings.EqualFold(s.DisplayName, s.Name) {
				desc = "Service " + s.DisplayName + " (" + s.Name + ")"
			}
			items = append(items, protocol.DiscoveredItem{Plugin: "services.service", Item: s.Name, Description: desc})
		}
	}
	slices.Sort(failed)
	summary := protocol.CheckResult{
		Plugin: "services",
		Values: map[string]float64{"failed_services": float64(len(failed))},
	}
	if len(failed) > 0 {
		summary.Summary = listSummary("not running", failed)
	}
	return summary, per, items
}

// serviceExitCode unwraps the SCM's two-step exit code: Win32ExitCode 1066
// means "the service has its own code", which then sits in
// ServiceSpecificExitCode.
func serviceExitCode(s winService) uint32 {
	if s.ExitCode == serviceExitCodeInSvc {
		return s.SpecificExitCode
	}
	return s.ExitCode
}

func serviceSummary(s winService) string {
	state := serviceStateName(s.State)
	if code := serviceExitCode(s); code != serviceNoExitCode {
		return state + ", exit code " + itoa(code)
	}
	return state
}

func itoa(v uint32) string { return strconv.FormatUint(uint64(v), 10) }

func serviceStateName(state uint32) string {
	switch state {
	case serviceStateStopped:
		return "stopped"
	case serviceStateRunning:
		return "running"
	case serviceStatePaused:
		return "paused"
	case 2:
		return "starting"
	case 3:
		return "stopping"
	case 5:
		return "continuing"
	case 6:
		return "pausing"
	}
	return "unknown state"
}
