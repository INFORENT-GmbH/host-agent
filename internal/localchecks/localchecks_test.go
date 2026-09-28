package localchecks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

func state(r protocol.CheckResult) string {
	if r.State == nil {
		return "P"
	}
	return strconv.Itoa(int(*r.State))
}

func TestParseLocalLine(t *testing.T) {
	cases := []struct {
		line    string
		item    string
		state   string
		summary string
		perf    int
		wantErr bool
	}{
		{line: "0 Backup - all fine", item: "Backup", state: "0", summary: "all fine"},
		{line: `2 "Backup nightly" age=93600;86400;90000 too old\nsee log`, item: "Backup nightly", state: "2", summary: "too old\nsee log", perf: 1},
		{line: "P Queue queue=17;50;100;0|rate=3.5 17 items", item: "Queue", state: "P", summary: "17 items", perf: 2},
		{line: "1 Disk_temp temp=48C;45;55 warm", item: "Disk_temp", state: "1", summary: "warm", perf: 1},
		{line: "0 NoDetail -", item: "NoDetail", state: "0"},
		{line: "P NoMetrics - text", wantErr: true},
		{line: "5 Bad - state", wantErr: true},
		{line: `0 "Unterminated - x`, wantErr: true},
		{line: "0 Bad value=abc text", wantErr: true},
		{line: "0 Bad value=NaN text", wantErr: true},
		{line: "0", wantErr: true},
	}
	for _, c := range cases {
		r, err := ParseLocalLine(c.line)
		if c.wantErr {
			if err == nil {
				t.Errorf("%q: expected error, got %+v", c.line, r)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", c.line, err)
			continue
		}
		if r.Plugin != "local" || r.Item != c.item || state(r) != c.state || r.Summary != c.summary || len(r.Perf) != c.perf {
			t.Errorf("%q: got item=%q state=%s summary=%q perf=%d", c.line, r.Item, state(r), r.Summary, len(r.Perf))
		}
	}
}

func TestPerfSpecLevels(t *testing.T) {
	p, err := parsePerfSpec("temp", "48C;45;55;0;100")
	if err != nil {
		t.Fatal(err)
	}
	if p.Value != 48 || p.Unit != "C" || *p.Warn != 45 || *p.Crit != 55 || *p.Min != 0 || *p.Max != 100 {
		t.Errorf("got %+v", p)
	}
	// Range levels cannot be expressed and are dropped, not misread.
	p, err = parsePerfSpec("x", "5;10:20;@30:40")
	if err != nil {
		t.Fatal(err)
	}
	if p.Warn != nil || p.Crit != nil {
		t.Errorf("range levels kept: %+v", p)
	}
}

func TestParseNagiosOutput(t *testing.T) {
	out := []byte("DISK OK - free space: / 3326 MB (56%) | /=2643MB;5948;5958;0;5968 'inode ratio'=12%\nline two | extra=1\n")
	r := ParseNagiosOutput("Disk_root", out, 0)
	if r.Plugin != "mrpe" || r.Item != "Disk_root" || *r.State != protocol.StateOK {
		t.Errorf("got %+v", r)
	}
	if r.Summary != "DISK OK - free space: / 3326 MB (56%)\nline two" {
		t.Errorf("summary %q", r.Summary)
	}
	if len(r.Perf) != 3 || r.Perf[0].Name != "/" || r.Perf[0].Unit != "MB" || r.Perf[1].Name != "inode ratio" || r.Perf[2].Name != "extra" {
		t.Errorf("perf %+v", r.Perf)
	}
	if r := ParseNagiosOutput("x", []byte("weird"), 127); *r.State != protocol.StateUnknown {
		t.Errorf("exit 127 must be UNKNOWN, got %v", *r.State)
	}
}

func TestParseMRPE(t *testing.T) {
	entries, err := parseMRPE(`
# comment
Disk_root /usr/lib/nagios/plugins/check_disk -w 10% -c 5% -p /
Slow (interval=600:appendage=yes) /usr/local/bin/check_slow --deep
broken
`)
	if err == nil {
		t.Error("broken line must be reported")
	}
	if len(entries) != 2 {
		t.Fatalf("entries %+v", entries)
	}
	if entries[0].Name != "Disk_root" || entries[0].Interval != 0 || !strings.HasSuffix(entries[0].Command, "-p /") {
		t.Errorf("entry 0 %+v", entries[0])
	}
	if entries[1].Name != "Slow" || entries[1].Interval != 10*time.Minute || entries[1].Command != "/usr/local/bin/check_slow --deep" {
		t.Errorf("entry 1 %+v", entries[1])
	}
}

func TestRunCommandTimeoutKillsGroup(t *testing.T) {
	start := time.Now()
	_, _, err := runCommand(context.Background(), 200*time.Millisecond, "/bin/sh", "-c", "sleep 30 & sleep 30; wait")
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err = %v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %v — child processes kept the command alive", d)
	}
}

func TestRunCommandOutputLimit(t *testing.T) {
	out, code, err := runCommand(context.Background(), 10*time.Second, "/bin/sh", "-c", "head -c 3000000 /dev/zero; exit 2")
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != maxOutput || code != 2 {
		t.Errorf("len %d code %d", len(out), code)
	}
}

// setup builds a local dir and an mrpe.cfg in a scratch directory with
// secure permissions (0755 dirs are fine: not group/other writable).
func setup(t *testing.T) (*Check, string) {
	t.Helper()
	base := t.TempDir()
	if err := os.Chmod(base, 0o755); err != nil { // #nosec G302 -- test fixture mirrors real permissions
		t.Fatal(err)
	}
	local := filepath.Join(base, "local")
	mkdir(t, local)
	return &Check{
		LocalDirs: []string{local, filepath.Join(base, "missing")},
		MRPEFiles: []string{filepath.Join(base, "mrpe.cfg")},
		Timeout:   5 * time.Second,
	}, base
}

func mkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
}

func script(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func byItem(rs []protocol.CheckResult) map[string]protocol.CheckResult {
	m := map[string]protocol.CheckResult{}
	for _, r := range rs {
		m[r.Plugin+"/"+r.Item] = r
	}
	return m
}

func TestRunScriptsAndMRPE(t *testing.T) {
	c, base := setup(t)
	local := c.LocalDirs[0]
	script(t, filepath.Join(local, "a"), `echo '0 "Service A" - fine'
echo 'P Queue q=70;50;100 seventy'
echo 'garbage line'
`, 0o700)
	script(t, filepath.Join(local, "b"), `echo '2 "Service A" - duplicate'`, 0o700)
	script(t, filepath.Join(local, "not-exec"), `echo '0 Hidden - x'`, 0o600)
	script(t, filepath.Join(local, "old.dpkg-old"), `echo '0 Old - x'`, 0o700)
	if err := os.WriteFile(filepath.Join(base, "mrpe.cfg"), []byte("Ping /bin/sh -c 'echo \"PING OK | rta=1.5ms;100;200\"; exit 1'\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	results, err := c.Run(context.Background(), time.Now())
	if err == nil || !strings.Contains(err.Error(), "invalid state") || !strings.Contains(err.Error(), "duplicate service") {
		t.Errorf("err = %v", err)
	}
	got := byItem(results)
	if len(got) != 3 {
		t.Fatalf("results %+v", results)
	}
	if r := got["local/Service A"]; state(r) != "0" || r.Summary != "fine" {
		t.Errorf("Service A %+v (first occurrence must win)", r)
	}
	if r := got["local/Queue"]; state(r) != "P" || len(r.Perf) != 1 {
		t.Errorf("Queue %+v", r)
	}
	if r := got["mrpe/Ping"]; state(r) != "1" || r.Summary != "PING OK" || len(r.Perf) != 1 {
		t.Errorf("Ping %+v", r)
	}
	if err := (&protocol.Checks{Time: 1, Results: results}).Validate(); err != nil {
		t.Errorf("results are not a valid message: %v", err)
	}

	items, _ := c.Discover(context.Background())
	if len(items) != 3 {
		t.Errorf("discover %+v", items)
	}
}

func TestIntervalSubdirIsCached(t *testing.T) {
	c, base := setup(t)
	sub := filepath.Join(c.LocalDirs[0], "300")
	mkdir(t, sub)
	counter := filepath.Join(base, "count")
	script(t, filepath.Join(sub, "slow"), `echo x >> `+counter+`
echo "0 Slow - runs $(wc -l < `+counter+`)"
`, 0o700)
	now := time.Now()
	for _, at := range []time.Time{now, now.Add(time.Minute), now.Add(4 * time.Minute), now.Add(6 * time.Minute)} {
		if _, err := c.Run(context.Background(), at); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(counter) // #nosec G304 -- test file
	if n := strings.Count(string(b), "x"); n != 2 {
		t.Errorf("script ran %d times in 6 minutes with a 300 s interval, want 2", n)
	}
}

func TestInsecureScriptRefused(t *testing.T) {
	c, _ := setup(t)
	path := filepath.Join(c.LocalDirs[0], "evil")
	script(t, path, `echo '0 Evil - x'`, 0o777) // #nosec G302 -- the insecure mode under test
	results, err := c.Run(context.Background(), time.Now())
	if !errors.Is(err, ErrInsecure) || len(results) != 0 {
		t.Errorf("results %+v, err %v", results, err)
	}
}

func TestInsecureDirectoryInChainRefused(t *testing.T) {
	c, _ := setup(t)
	sub := filepath.Join(c.LocalDirs[0], "60")
	mkdir(t, sub)
	script(t, filepath.Join(sub, "check"), `echo '0 Sub - x'`, 0o700)
	if err := os.Chmod(c.LocalDirs[0], 0o777); err != nil { // #nosec G302 -- the insecure mode under test
		t.Fatal(err)
	}
	if _, err := c.Run(context.Background(), time.Now()); !errors.Is(err, ErrInsecure) {
		t.Errorf("writable base dir not detected: %v", err)
	}
}

func TestInsecureMRPERefused(t *testing.T) {
	c, _ := setup(t)
	if err := os.WriteFile(c.MRPEFiles[0], []byte("X /bin/true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(c.MRPEFiles[0], 0o666); err != nil { // #nosec G302 -- the insecure mode under test
		t.Fatal(err)
	}
	results, err := c.Run(context.Background(), time.Now())
	if !errors.Is(err, ErrInsecure) || len(results) != 0 {
		t.Errorf("results %+v, err %v", results, err)
	}
}

func TestSanitizeKeepsMessageValid(t *testing.T) {
	r := sanitize(protocol.CheckResult{
		Plugin: "local",
		Item:   "bell\x07" + strings.Repeat("x", 300),
		Perf:   []protocol.Perf{{Name: "n\x1b", Unit: strings.Repeat("ü", 20), Value: 1}},
	})
	s := protocol.StateOK
	r.State = &s
	if err := (&protocol.Checks{Time: 1, Results: []protocol.CheckResult{r}}).Validate(); err != nil {
		t.Errorf("sanitized result invalid: %v", err)
	}
}

// The Windows branch decides by extension what Unix decides by the execute
// bit; without a Windows runner this test is the only thing that checks it.
func TestIsWindowsScript(t *testing.T) {
	for name, want := range map[string]bool{
		`C:\ProgramData\checkmk\agent\local\disk.bat`: true,
		`disk.CMD`:      true,
		`collect.ps1`:   true,
		`helper.exe`:    true,
		`legacy.sh`:     false,
		`notes.txt`:     false,
		`archive.ps1.d`: false,
		`noextension`:   false,
	} {
		if got := isWindowsScript(name); got != want {
			t.Errorf("isWindowsScript(%q) = %v, want %v", name, got, want)
		}
	}
}
