package checks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	sdbus "github.com/coreos/go-systemd/v22/dbus"

	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

const aptOutput = `Inst base-files [13.8] (13.8+deb13u1 Debian:13.1/stable [amd64])
Conf base-files (13.8+deb13u1 Debian:13.1/stable [amd64])
Inst libssl3t64 [3.5.1-1] (3.5.1-1+deb13u1 Debian-Security:13/stable-security [amd64]) []
Inst openssl [3.5.1-1] (3.5.1-1+deb13u1 Debian:13.1/stable, Debian-Security:13/stable-security [amd64])
Inst linux-image-amd64 (6.12.43-1 Debian:13.1/stable [amd64])
Inst libc6 [2.41-12] (2.41-12ubuntu1 Ubuntu:26.04/resolute-security [amd64])
`

func TestEvaluateApt(t *testing.T) {
	r := evaluateApt([]byte(aptOutput))
	if r.Values["updates"] != 5 || r.Values["security_updates"] != 3 {
		t.Errorf("values %v", r.Values)
	}
	if !strings.HasPrefix(r.Summary, "5 updates, 3 security: libssl3t64, openssl, libc6") {
		t.Errorf("summary %q", r.Summary)
	}
	if empty := evaluateApt(nil); empty.Values["updates"] != 0 || empty.Summary != "" {
		t.Errorf("no updates: %+v", empty)
	}
}

func TestAptCachesOnlySuccess(t *testing.T) {
	calls := 0
	fail := true
	c := &aptCheck{
		lookPath: func(string) (string, error) { return "/usr/bin/apt-get", nil },
		simulate: func(context.Context) ([]byte, error) {
			calls++
			if fail {
				return nil, errors.New("dpkg was interrupted")
			}
			return []byte(aptOutput), nil
		},
	}
	now := time.Now()
	r, _ := c.Run(context.Background(), now)
	if len(r) != 1 || r[0].State == nil || *r[0].State != protocol.StateUnknown {
		t.Fatalf("failure must report UNKNOWN: %+v", r)
	}
	fail = false
	_, _ = c.Run(context.Background(), now.Add(time.Minute))
	_, _ = c.Run(context.Background(), now.Add(2*time.Minute))
	if calls != 2 {
		t.Errorf("calls = %d, want 2 (failure not cached, success cached)", calls)
	}
	_, _ = c.Run(context.Background(), now.Add(2*time.Minute+aptCacheTTL))
	if calls != 3 {
		t.Errorf("calls = %d after TTL, want 3", calls)
	}
}

func TestAptNotApplicable(t *testing.T) {
	c := &aptCheck{lookPath: func(string) (string, error) { return "", errors.New("not found") }}
	items, err := c.Discover(context.Background())
	if err != nil || len(items) != 0 {
		t.Errorf("discover = %v, %v", items, err)
	}
	if r, _ := c.Run(context.Background(), time.Now()); len(r) != 0 {
		t.Errorf("run = %v", r)
	}
}

func TestEvaluateUnits(t *testing.T) {
	units := []sdbus.UnitStatus{
		{Name: "nginx.service", ActiveState: "active", SubState: "running"},
		{Name: "backup.service", ActiveState: "failed", SubState: "failed"},
		{Name: "old.service", ActiveState: "inactive", SubState: "dead"},
		{Name: "tmp.mount", ActiveState: "failed", SubState: "failed"},
		{Name: "manual.service", ActiveState: "active", SubState: "running"},
	}
	enabled := map[string]bool{"nginx.service": true, "backup.service": true, "old.service": true}
	summary, perUnit, items := evaluateUnits(units, enabled)
	if summary.Values["failed_units"] != 2 || summary.Summary != "failed: backup.service, tmp.mount" {
		t.Errorf("summary %+v", summary)
	}
	if len(perUnit) != 3 {
		t.Errorf("per unit %+v", perUnit)
	}
	var got []string
	for _, it := range items {
		got = append(got, it.Plugin+"/"+it.Item)
	}
	// Enabled AND active: backup (failed) and old (inactive) are not discovered,
	// manual (active, not enabled) neither.
	if strings.Join(got, " ") != "systemd/ systemd.service/nginx.service" {
		t.Errorf("items %v", got)
	}
}

func TestSystemdNotApplicable(t *testing.T) {
	c := &systemdCheck{runDir: filepath.Join(t.TempDir(), "missing")}
	if items, err := c.Discover(context.Background()); err != nil || len(items) != 0 {
		t.Errorf("discover = %v, %v", items, err)
	}
}

func TestSystemdErrorIsUnknown(t *testing.T) {
	c := &systemdCheck{
		runDir: t.TempDir(),
		list: func(context.Context) ([]sdbus.UnitStatus, map[string]bool, error) {
			return nil, nil, errors.New("bus unavailable")
		},
	}
	r, _ := c.Run(context.Background(), time.Now())
	if len(r) != 1 || r[0].State == nil || *r[0].State != protocol.StateUnknown {
		t.Errorf("got %+v", r)
	}
}

func TestReboot(t *testing.T) {
	root := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(root, "boot"), 0o750))
	must(os.MkdirAll(filepath.Join(root, "run"), 0o750))
	old := filepath.Join(root, "boot", "vmlinuz-6.12.40-amd64")
	cur := filepath.Join(root, "boot", "vmlinuz-6.12.43-amd64")
	must(os.WriteFile(old, nil, 0o600))
	must(os.WriteFile(cur, nil, 0o600))
	must(os.Chtimes(old, time.Now().Add(-48*time.Hour), time.Now().Add(-48*time.Hour)))

	c := rebootCheck{root: root, release: func() string { return "6.12.43-amd64" }}
	r, _ := c.Run(context.Background(), time.Now())
	if r[0].Values["reboot_required"] != 0 || r[0].Summary != "" {
		t.Errorf("up to date: %+v", r[0])
	}

	c.release = func() string { return "6.12.40-amd64" }
	r, _ = c.Run(context.Background(), time.Now())
	if r[0].Values["kernel_outdated"] != 1 || r[0].Values["reboot_required"] != 1 || !strings.Contains(r[0].Summary, "6.12.43-amd64") {
		t.Errorf("outdated kernel: %+v", r[0])
	}

	c.release = func() string { return "6.12.43-amd64" }
	must(os.WriteFile(filepath.Join(root, "run", "reboot-required"), nil, 0o600))
	must(os.WriteFile(filepath.Join(root, "run", "reboot-required.pkgs"), []byte("libc6\ndbus\nlibc6\n"), 0o600))
	r, _ = c.Run(context.Background(), time.Now())
	if r[0].Values["reboot_required"] != 1 || r[0].Values["kernel_outdated"] != 0 || r[0].Summary != "required by: libc6, dbus" {
		t.Errorf("flag: %+v", r[0])
	}
}

func TestSummaryLimits(t *testing.T) {
	long := strings.Repeat("x", protocol.MaxSummary+50)
	if n := utf8.RuneCountInString(Summary(long)); n != protocol.MaxSummary {
		t.Errorf("length %d", n)
	}
	if got := Summary("a\x07b\nc"); got != "a b\nc" {
		t.Errorf("control chars: %q", got)
	}
	names := make([]string, 200)
	for i := range names {
		names[i] = "package-with-a-long-name"
	}
	s := listSummary("200 updates", names)
	if utf8.RuneCountInString(s) > protocol.MaxSummary || !strings.Contains(s, "more)") {
		t.Errorf("list summary %q", s)
	}
}

// TestLive runs discovery and two check rounds on the test machine and
// validates the resulting messages. apt is left out: its simulation takes
// seconds and depends on the machine's package state; evaluateApt is
// covered above.
func TestLive(t *testing.T) {
	ctx := context.Background()
	var cs []Check
	for _, c := range Default() {
		if c.Plugin() != "apt" {
			cs = append(cs, c)
		}
	}
	items, err := Discover(ctx, cs)
	if err != nil {
		t.Logf("discover: %v", err)
	}
	if err := (&protocol.Discovery{Time: 1, Items: items}).Validate(); err != nil {
		t.Fatalf("discovery invalid: %v", err)
	}
	if _, err := Run(ctx, cs, time.Now()); err != nil {
		t.Logf("first run: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	results, err := Run(ctx, cs, time.Now())
	if err != nil {
		t.Logf("second run: %v", err)
	}
	if err := (&protocol.Checks{Time: 1, Results: results}).Validate(); err != nil {
		t.Fatalf("checks invalid: %v", err)
	}
	have := map[string]bool{}
	for _, r := range results {
		have[r.Plugin] = true
	}
	for _, p := range []string{"cpu.load", "cpu.util", "mem", "uptime", "df", "reboot"} {
		if !have[p] {
			t.Errorf("missing %s result", p)
		}
	}
}
