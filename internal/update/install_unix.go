//go:build unix

package update

import (
	"context"
	"fmt"
)

// run installs via apt in a transient systemd unit, then waits for dpkg to
// restart the service. If apt succeeds this process dies inside waitForRestart
// (the happy path); an apt failure is reported by the still-running old agent.
func (m *Manager) run(ctx context.Context, version string) {
	defer m.setIdle()
	rctx, cancel := context.WithTimeout(ctx, m.runTimeout)
	defer cancel()
	out, err := m.runCmd(rctx, "systemd-run",
		"--unit="+m.b.Name()+"-update", "--collect", "--wait",
		"/bin/sh", "-ec", m.script(version))
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
