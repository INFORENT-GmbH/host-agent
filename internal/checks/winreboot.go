package checks

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

// The Windows counterpart of the reboot check. Windows has no single "is a
// restart pending" API — the answer is assembled from the four places that
// set a flag, which is also what every administrator script does. The
// judgement is here, untagged and tested on Linux; only the registry reads
// are Windows-only (winreboot_windows.go).

// rebootSignals is what the registry says. Each field is one reason.
type rebootSignals struct {
	// ComponentBasedServicing: a servicing operation (feature, update) asked
	// for a restart.
	ComponentBasedServicing bool
	// WindowsUpdate: Windows Update installed something that needs one.
	WindowsUpdate bool
	// FileRename: files are queued to be moved on the next boot, which is how
	// installers replace locked files.
	FileRename bool
	// ComputerRename: the host was renamed and still answers to the old name.
	ComputerRename bool
}

type winRebootCheck struct {
	// signals is replaced in tests.
	signals func() (rebootSignals, error)
}

func (*winRebootCheck) Plugin() string { return "winreboot" }

func (c *winRebootCheck) read() (rebootSignals, error) {
	if c.signals != nil {
		return c.signals()
	}
	return readRebootSignals()
}

func (c *winRebootCheck) Discover(context.Context) ([]protocol.DiscoveredItem, error) {
	if _, err := c.read(); errors.Is(err, errors.ErrUnsupported) {
		return nil, nil
	}
	return []protocol.DiscoveredItem{{Plugin: "winreboot", Description: "Reboot required"}}, nil
}

func (c *winRebootCheck) Run(context.Context, time.Time) ([]protocol.CheckResult, error) {
	s, err := c.read()
	if errors.Is(err, errors.ErrUnsupported) {
		return nil, nil
	}
	if err != nil {
		return []protocol.CheckResult{unknown("winreboot", "", err)}, nil
	}
	return []protocol.CheckResult{evaluateRebootSignals(s)}, nil
}

// evaluateRebootSignals reports one value per reason next to the verdict, so
// a rule can act on "Windows Update wants a restart" without the summary
// text — and so the summary can say WHY, which is what decides whether an
// administrator reboots now or tonight.
func evaluateRebootSignals(s rebootSignals) protocol.CheckResult {
	var reasons []string
	if s.ComponentBasedServicing {
		reasons = append(reasons, "servicing")
	}
	if s.WindowsUpdate {
		reasons = append(reasons, "Windows Update")
	}
	if s.FileRename {
		reasons = append(reasons, "pending file renames")
	}
	if s.ComputerRename {
		reasons = append(reasons, "computer rename")
	}
	r := protocol.CheckResult{
		Plugin: "winreboot",
		Values: map[string]float64{
			"reboot_required": boolValue(len(reasons) > 0),
			"servicing":       boolValue(s.ComponentBasedServicing),
			"windows_update":  boolValue(s.WindowsUpdate),
			"file_rename":     boolValue(s.FileRename),
			"computer_rename": boolValue(s.ComputerRename),
		},
	}
	if len(reasons) > 0 {
		r.Summary = Summary("reboot required: " + strings.Join(reasons, ", "))
	}
	return r
}
