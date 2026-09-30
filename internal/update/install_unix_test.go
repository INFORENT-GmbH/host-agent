//go:build unix

package update

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

// dpkg restarts the service mid-upgrade and systemd terminates the
// `systemd-run --wait` client with us. That exit is no apt verdict: no
// failure report, and the pending file stays for the restarted agent.
func TestHandleClientKilledBySignalLeavesPending(t *testing.T) {
	m, rec := newManager(t, "1.0.0")
	m.runCmd = func(ctx context.Context, _ string, _ ...string) ([]byte, error) {
		return exec.CommandContext(ctx, "/bin/sh", "-c", "kill -TERM $$").CombinedOutput()
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.Handle(ctx, "1.0.1")
	time.Sleep(200 * time.Millisecond)
	cancel() // the service stop reaches us, too
	time.Sleep(50 * time.Millisecond)
	if n := rec.count(); n != 0 {
		t.Errorf("%d results for a restart-killed client: %+v", n, rec.got[0])
	}
	if p, ok := m.readPending(); !ok || p.Version != "1.0.1" {
		t.Error("pending file lost — the restarted agent could not report the success")
	}
}

// Killed but never restarted: the deadline still turns it into a failure.
func TestHandleClientKilledWithoutRestartFailsAtDeadline(t *testing.T) {
	m, rec := newManager(t, "1.0.0")
	m.runTimeout = 300 * time.Millisecond
	m.runCmd = func(ctx context.Context, _ string, _ ...string) ([]byte, error) {
		return exec.CommandContext(ctx, "/bin/sh", "-c", "kill -TERM $$").CombinedOutput()
	}
	m.Handle(context.Background(), "1.0.1")
	if res := rec.wait(t); res.OK || res.Version != "1.0.1" {
		t.Errorf("result %+v", res)
	}
}
