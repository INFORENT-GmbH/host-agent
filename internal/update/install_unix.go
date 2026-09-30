//go:build unix

package update

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
)

// run installs via apt in a transient systemd unit, then waits for dpkg to
// restart the service. If apt succeeds this process dies inside waitForRestart
// (the happy path); an apt failure is reported by the still-running old agent.
//
// The `systemd-run --wait` client is our child and lives in the agent's
// cgroup, so when dpkg restarts the service systemd terminates it together
// with us — usually before our own context sees the signal. Its exit then
// says nothing about apt (the transient unit runs on outside our cgroup), so
// it must not become a failure report: that is what counted every successful
// upgrade up to 1.10.0 as "signal: terminated" and halted the rollout. Leave
// the pending file for the restarted agent and settle it by deadline if no
// restart comes.
func (m *Manager) run(ctx context.Context, version string) {
	defer m.setIdle()
	rctx, cancel := context.WithTimeout(ctx, m.runTimeout)
	defer cancel()
	out, err := m.runCmd(rctx, "systemd-run",
		"--unit="+m.b.Name()+"-update", "--collect", "--wait",
		"/bin/sh", "-ec", m.script(version))
	if err != nil && rctx.Err() == nil && killedBySignal(err) {
		m.log.Info("update client stopped by a signal, leaving the result to the restarted agent", "version", version, "err", err)
		if p, ok := m.readPending(); ok && p.Version == version {
			m.settleByDeadline(ctx, p)
		}
		return
	}
	if err != nil {
		m.clearPending()
		m.fail(version, oneLine(fmt.Sprintf("%v: %s", err, out)))
		return
	}
	m.waitForRestart(ctx, version)
}

// script is the transient unit's command: refresh only our apt source, then
// upgrade to exactly the requested version. The version was validated against
// the protocol's strict pattern before it gets anywhere near this line.
func (m *Manager) script(version string) string {
	list := m.b.AptSourceFile()
	return fmt.Sprintf(
		"if [ -f %[1]q ]; then apt-get update -o Dir::Etc::SourceList=%[1]q -o Dir::Etc::SourceParts=- -o APT::Get::List-Cleanup=0; else apt-get update; fi\n"+
			"exec apt-get -y install --only-upgrade %[2]s=%[3]s",
		list, m.b.Name(), version)
}

// killedBySignal: the command did not exit on its own but was terminated —
// the service stop during the upgrade, not apt's verdict.
func killedBySignal(err error) bool {
	var ee *exec.ExitError
	return errors.As(err, &ee) && !ee.Exited()
}
