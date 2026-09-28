package checks

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Windows Update and the pending-restart registry cannot be read on our CI,
// so their judgement is tested here with the values Windows produces.
func TestEvaluateUpdates(t *testing.T) {
	r := evaluateUpdates([]winUpdate{
		{Title: "2026-09 Cumulative Update for Windows Server 2022", Severity: "Critical", Downloaded: true},
		{Title: "Security Intelligence Update for Defender", Severity: "Important"},
		{Title: "Update for .NET Framework", Severity: "Moderate"},
		{Title: "Driver update for Contoso NIC"},
	})
	if got := r.Values["updates"]; got != 4 {
		t.Errorf("updates = %v, want 4", got)
	}
	// Moderate and an unrated driver update are ordinary updates: only
	// Critical and Important carry a patch-now expectation.
	if got := r.Values["security_updates"]; got != 2 {
		t.Errorf("security_updates = %v, want 2", got)
	}
	if got := r.Values["downloaded"]; got != 1 {
		t.Errorf("downloaded = %v, want 1", got)
	}
	if want := "4 updates, 2 security"; len(r.Summary) < len(want) || r.Summary[:len(want)] != want {
		t.Errorf("summary = %q", r.Summary)
	}
}

func TestEvaluateUpdatesQuietWhenNothingPending(t *testing.T) {
	r := evaluateUpdates(nil)
	if r.Summary != "" || r.Values["updates"] != 0 {
		t.Errorf("got %+v, want an empty summary and zero updates", r)
	}
}

// The search is expensive, so a successful result is cached for an hour and
// an error is not — the same contract the apt check follows.
func TestWinUpdateCheckCaches(t *testing.T) {
	calls := 0
	c := &winUpdateCheck{search: func(context.Context) ([]winUpdate, error) {
		calls++
		return []winUpdate{{Title: "an update"}}, nil
	}}
	now := time.Now()
	if _, err := c.Run(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Run(context.Background(), now.Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("searched %d times within the hour, want 1", calls)
	}
	if _, err := c.Run(context.Background(), now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("searched %d times after the hour, want 2", calls)
	}
}

func TestWinUpdateCheckDoesNotCacheFailures(t *testing.T) {
	calls := 0
	c := &winUpdateCheck{search: func(context.Context) ([]winUpdate, error) {
		calls++
		return nil, errors.New("the update data store is corrupt")
	}}
	now := time.Now()
	for i := 0; i < 2; i++ {
		res, err := c.Run(context.Background(), now)
		if err != nil {
			t.Fatal(err)
		}
		if len(res) != 1 || res[0].State == nil {
			t.Fatalf("want one UNKNOWN result, got %+v", res)
		}
	}
	if calls != 2 {
		t.Fatalf("searched %d times, want 2 — a failure must not be cached", calls)
	}
}

func TestEvaluateRebootSignals(t *testing.T) {
	quiet := evaluateRebootSignals(rebootSignals{})
	if quiet.Values["reboot_required"] != 0 || quiet.Summary != "" {
		t.Errorf("no signal should mean no reboot: %+v", quiet)
	}

	r := evaluateRebootSignals(rebootSignals{WindowsUpdate: true, FileRename: true})
	if r.Values["reboot_required"] != 1 {
		t.Errorf("reboot_required = %v", r.Values["reboot_required"])
	}
	if r.Values["windows_update"] != 1 || r.Values["file_rename"] != 1 {
		t.Errorf("per-reason values wrong: %v", r.Values)
	}
	if r.Values["servicing"] != 0 || r.Values["computer_rename"] != 0 {
		t.Errorf("unset reasons must be 0: %v", r.Values)
	}
	// The summary has to say why — that is what decides between rebooting
	// now and rebooting tonight.
	if r.Summary != "reboot required: Windows Update, pending file renames" {
		t.Errorf("summary = %q", r.Summary)
	}
}

func TestWinRebootCheckIsSilentWhereUnsupported(t *testing.T) {
	c := &winRebootCheck{signals: func() (rebootSignals, error) {
		return rebootSignals{}, errors.ErrUnsupported
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
