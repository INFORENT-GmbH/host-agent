package update

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/INFORENT-GmbH/host-agent/internal/brand"
	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

type recorder struct {
	mu  sync.Mutex
	got []*protocol.UpdateResult
}

func (r *recorder) report(res *protocol.UpdateResult) {
	if err := res.Validate(); err != nil {
		panic(err)
	}
	r.mu.Lock()
	r.got = append(r.got, res)
	r.mu.Unlock()
}

func (r *recorder) wait(t *testing.T) *protocol.UpdateResult {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		r.mu.Lock()
		if len(r.got) > 0 {
			res := r.got[0]
			r.mu.Unlock()
			return res
		}
		r.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("no update_result")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.got)
}

func newManager(t *testing.T, version string) (*Manager, *recorder) {
	t.Helper()
	root := t.TempDir()
	b, err := brand.New("acme", root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(b.StateDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	m := New(b, version, "", rec.report, slog.New(slog.DiscardHandler))
	m.restartGrace = 50 * time.Millisecond
	return m, rec
}

func TestHandleRunsSystemdRunAndReportsAptFailure(t *testing.T) {
	m, rec := newManager(t, "1.0.0")
	var gotName string
	var gotArgs []string
	m.runCmd = func(_ context.Context, name string, args ...string) ([]byte, error) {
		gotName, gotArgs = name, args
		return []byte("E: Version '1.0.1' for 'acme-agent' was not found\r\n"), errors.New("exit status 100")
	}
	m.Handle(context.Background(), "1.0.1")
	res := rec.wait(t)
	if res.OK || res.Version != "1.0.1" || !strings.Contains(res.Error, "not found") || strings.ContainsRune(res.Error, '\r') {
		t.Errorf("result %+v", res)
	}
	if gotName != "systemd-run" {
		t.Fatalf("ran %q", gotName)
	}
	joined := strings.Join(gotArgs, " ")
	for _, want := range []string{
		"--unit=acme-agent-update", "--collect", "--wait",
		"apt-get -y install --only-upgrade acme-agent=1.0.1",
		"sources.list.d/acme-agent.list",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("args lack %q: %s", want, joined)
		}
	}
	if _, ok := m.readPending(); ok {
		t.Error("pending file survived a failed update")
	}
}

func TestHandleReportsMissingRestart(t *testing.T) {
	m, rec := newManager(t, "1.0.0")
	m.runCmd = func(context.Context, string, ...string) ([]byte, error) { return nil, nil }
	m.Handle(context.Background(), "1.0.1")
	res := rec.wait(t)
	if res.OK || !strings.Contains(res.Error, "not restarted") {
		t.Errorf("result %+v", res)
	}
}

func TestHandleDevBuildRefuses(t *testing.T) {
	m, rec := newManager(t, "dev")
	m.runCmd = func(context.Context, string, ...string) ([]byte, error) {
		t.Error("dev build ran a command")
		return nil, nil
	}
	m.Handle(context.Background(), "1.0.1")
	if res := rec.wait(t); res.OK || !strings.Contains(res.Error, "dev build") {
		t.Errorf("result %+v", res)
	}
}

func TestHandleSameVersionIsOk(t *testing.T) {
	m, rec := newManager(t, "1.0.1")
	m.runCmd = func(context.Context, string, ...string) ([]byte, error) {
		t.Error("same version ran a command")
		return nil, nil
	}
	m.Handle(context.Background(), "1.0.1")
	if res := rec.wait(t); !res.OK || res.Version != "1.0.1" {
		t.Errorf("result %+v", res)
	}
}

func TestHandleIgnoresSecondUpdateWhileRunning(t *testing.T) {
	m, rec := newManager(t, "1.0.0")
	release := make(chan struct{})
	m.runCmd = func(context.Context, string, ...string) ([]byte, error) {
		<-release
		return nil, errors.New("exit status 100")
	}
	m.Handle(context.Background(), "1.0.1")
	m.Handle(context.Background(), "1.0.2") // ignored: one is in flight
	close(release)
	res := rec.wait(t)
	if res.Version != "1.0.1" {
		t.Errorf("result %+v", res)
	}
	time.Sleep(50 * time.Millisecond)
	if n := rec.count(); n != 1 {
		t.Errorf("%d results for one running update", n)
	}
}

// The happy path: apt succeeded, dpkg restarted the service, and the new
// build finds the pending file.
func TestReportPendingAfterSuccessfulUpdate(t *testing.T) {
	m, rec := newManager(t, "1.0.1")
	if err := m.writePending(pending{Version: "1.0.1", StartedAt: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	m.ReportPending(context.Background())
	if res := rec.wait(t); !res.OK || res.Version != "1.0.1" {
		t.Errorf("result %+v", res)
	}
	if _, ok := m.readPending(); ok {
		t.Error("pending file survived the success report")
	}
}

func TestReportPendingStaleIsFailure(t *testing.T) {
	m, rec := newManager(t, "1.0.0")
	if err := m.writePending(pending{Version: "1.0.1", StartedAt: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	m.ReportPending(context.Background())
	if res := rec.wait(t); res.OK || !strings.Contains(res.Error, "still runs 1.0.0") {
		t.Errorf("result %+v", res)
	}
}

// A fresh pending file on a restarted old build: wait out the deadline, then
// fail — unless the update finishes first (then this process is gone).
func TestReportPendingFreshFailsAfterDeadline(t *testing.T) {
	m, rec := newManager(t, "1.0.0")
	m.runTimeout = 100 * time.Millisecond
	if err := m.writePending(pending{Version: "1.0.1", StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	m.ReportPending(context.Background())
	if n := rec.count(); n != 0 {
		t.Fatalf("reported before the deadline: %d", n)
	}
	if res := rec.wait(t); res.OK || res.Version != "1.0.1" {
		t.Errorf("result %+v", res)
	}
}

func TestReportPendingGarbageIsDropped(t *testing.T) {
	m, rec := newManager(t, "1.0.0")
	if err := os.WriteFile(m.pendingPath(), []byte("{half a rec"), 0o600); err != nil {
		t.Fatal(err)
	}
	m.ReportPending(context.Background())
	time.Sleep(50 * time.Millisecond)
	if n := rec.count(); n != 0 {
		t.Errorf("%d results from a garbage pending file", n)
	}
	if _, err := os.Stat(m.pendingPath()); !os.IsNotExist(err) {
		t.Error("garbage pending file kept")
	}
}

func TestOneLineTruncatesFromTheTail(t *testing.T) {
	long := strings.Repeat("x", 600) + " the actual error"
	got := oneLine(long)
	if len([]rune(got)) != protocol.MaxSummary || !strings.HasSuffix(got, "the actual error") || !strings.HasPrefix(got, "…") {
		t.Errorf("oneLine kept %d runes, tail %q", len([]rune(got)), got[len(got)-20:])
	}
}
