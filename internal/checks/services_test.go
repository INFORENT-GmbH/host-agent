package checks

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

func sampleServices() []winService {
	return []winService{
		{Name: "W32Time", DisplayName: "Windows Time", StartType: serviceStartAuto, State: serviceStateRunning},
		{Name: "Spooler", DisplayName: "Print Spooler", StartType: serviceStartAuto, State: serviceStateStopped,
			ExitCode: serviceExitCodeInSvc, SpecificExitCode: 7},
		{Name: "acme-agent", DisplayName: "acme-agent", StartType: serviceStartAuto, State: serviceStateRunning},
		// Manual and disabled services are none of our business.
		{Name: "Fax", DisplayName: "Fax", StartType: 3, State: serviceStateStopped},
		{Name: "WSearch", DisplayName: "Windows Search", StartType: 4, State: serviceStateStopped},
		// Delayed start, still stopped: stays in the set, flagged as delayed.
		{Name: "Sense", DisplayName: "Defender ATP", StartType: serviceStartAuto, State: serviceStateStopped, DelayedAutoStart: true},
	}
}

func TestEvaluateServices(t *testing.T) {
	summary, per, items := evaluateServices(sampleServices())

	if got := summary.Values["failed_services"]; got != 2 {
		t.Errorf("failed_services = %v, want 2 (Spooler and Sense)", got)
	}
	if summary.Summary != "not running: Sense, Spooler" {
		t.Errorf("summary = %q", summary.Summary)
	}
	if len(per) != 4 {
		t.Fatalf("got %d per-service results, want 4 — manual and disabled services must be skipped", len(per))
	}

	byItem := map[string]protocol.CheckResult{}
	for _, r := range per {
		if r.Plugin != "services.service" {
			t.Errorf("plugin = %q", r.Plugin)
		}
		byItem[r.Item] = r
	}
	if got := byItem["Spooler"]; got.Values["running"] != 0 || got.Values["failed"] != 1 {
		t.Errorf("Spooler: %v", got.Values)
	}
	// Win32ExitCode 1066 only says "look at the service's own code".
	if got := byItem["Spooler"].Values["exit_code"]; got != 7 {
		t.Errorf("Spooler exit_code = %v, want the service-specific 7", got)
	}
	if got := byItem["Spooler"].Summary; got != "stopped, exit code 7" {
		t.Errorf("Spooler summary = %q", got)
	}
	if got := byItem["Sense"].Values["delayed"]; got != 1 {
		t.Errorf("Sense delayed = %v, want 1", got)
	}
	if got := byItem["W32Time"].Values["delayed"]; got != 0 {
		t.Errorf("W32Time delayed = %v, want 0", got)
	}

	// Discovery takes the summary plus the automatic services running now —
	// a stopped one must not be picked up, or every host would start with
	// failing services it never had.
	if len(items) != 3 {
		t.Fatalf("got %d discovery items, want 3: %v", len(items), items)
	}
	if items[0].Plugin != "services" || items[0].Item != "" {
		t.Errorf("first item should be the summary, got %+v", items[0])
	}
	if items[1].Item != "W32Time" || items[1].Description != "Service Windows Time (W32Time)" {
		t.Errorf("second item = %+v", items[1])
	}
	// Display name equal to the service name must not be repeated.
	if items[2].Description != "Service acme-agent" {
		t.Errorf("third item description = %q", items[2].Description)
	}
}

// Off Windows the check must vanish rather than report an error — the same
// contract timesync follows.
func TestServicesCheckIsSilentWhereUnsupported(t *testing.T) {
	c := &servicesCheck{list: func(context.Context) ([]winService, error) {
		return nil, errors.ErrUnsupported
	}}
	items, err := c.Discover(context.Background())
	if err != nil || items != nil {
		t.Fatalf("Discover = %v, %v", items, err)
	}
	res, err := c.Run(context.Background(), time.Now())
	if err != nil || res != nil {
		t.Fatalf("Run = %v, %v", res, err)
	}
}

// A service control manager that cannot be reached is UNKNOWN with a reason,
// not a silent gap.
func TestServicesCheckReportsUnknown(t *testing.T) {
	c := &servicesCheck{list: func(context.Context) ([]winService, error) {
		return nil, errors.New("access denied")
	}}
	res, err := c.Run(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("Run returned %v", err)
	}
	if len(res) != 1 || res[0].State == nil || *res[0].State != protocol.StateUnknown {
		t.Fatalf("want one UNKNOWN result, got %+v", res)
	}
}
