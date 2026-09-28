//go:build windows

package update

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// run performs the Windows self-update: fetch the per-version manifest and the
// MSI it names over TLS from the brand's own host, verify the MSI against the
// manifest's SHA-256, then hand it to a DETACHED msiexec.
//
// Detached is essential and the whole reason this differs from Linux. Windows
// Installer stops this very service (the MSI's ServiceControl table) to replace
// the binary, then starts it again. If msiexec were a child bound to our
// context, the service stop would cancel that context and kill the installer
// mid-flight. So msiexec is launched breakaway, and we then wait exactly like
// Linux: the service stop cancels our context, we return leaving the pending
// file, and the restarted agent reports success from it. If the stop never
// comes within the grace period, the install did not take — say so.
func (m *Manager) run(ctx context.Context, version string) {
	defer m.setIdle()

	if !validPackageBase(m.packageBase) {
		m.clearPending()
		m.fail(version, "self-update is not configured: server.package_base is empty or not https")
		return
	}
	// Windows Installer will not put an older version over a newer one (the
	// MSI says so itself). Catch it here so the operator gets the reason and
	// the remedy instead of a bare msiexec exit code.
	if isDowngrade(m.version, version) {
		m.clearPending()
		m.fail(version, "Windows does not install "+version+" over the running "+m.version+
			"; uninstall the agent first (install.ps1 -Uninstall), then install the older version")
		return
	}
	fctx, cancel := context.WithTimeout(ctx, m.runTimeout)
	defer cancel()

	man, err := m.httpGet(fctx, manifestURL(m.packageBase, version))
	if err != nil {
		m.clearPending()
		m.fail(version, "fetching the update manifest: "+oneLine(err.Error()))
		return
	}
	mf, err := parseManifest(man, version)
	if err != nil {
		m.clearPending()
		m.fail(version, err.Error())
		return
	}
	body, err := m.httpGet(fctx, msiURL(m.packageBase, mf))
	if err != nil {
		m.clearPending()
		m.fail(version, "downloading the installer: "+oneLine(err.Error()))
		return
	}
	if err := verifyMSI(body, mf); err != nil {
		m.clearPending()
		m.fail(version, "verifying the installer: "+err.Error())
		return
	}

	// The MSI goes to the state directory, not %TEMP%: it must outlive this
	// process, which msiexec is about to kill, and the state directory is
	// already locked to privileged accounts (internal/winsec).
	msiPath := filepath.Join(m.b.StateDir(), "update-"+version+".msi")
	logPath := filepath.Join(m.b.StateDir(), "update-"+version+".log")
	if err := os.WriteFile(msiPath, body, 0o600); err != nil { // #nosec G306 -- privileged state dir
		m.clearPending()
		m.fail(version, "saving the installer: "+err.Error())
		return
	}

	// /qn silent, /norestart so a pending-reboot MSI never reboots the host on
	// its own; /l*v leaves a verbose log for the acceptance run's post-mortem.
	cmd := exec.Command("msiexec", "/i", msiPath, "/qn", "/norestart", "/l*v", logPath) // #nosec G204 -- state-dir paths, validated version
	// Detach: a new process group that breaks away from our job object, so the
	// installer survives the service stop it is about to trigger.
	cmd.SysProcAttr = &windows.SysProcAttr{
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.CREATE_BREAKAWAY_FROM_JOB | 0x00000008, // DETACHED_PROCESS
	}
	if err := cmd.Start(); err != nil {
		m.clearPending()
		m.fail(version, "starting msiexec: "+err.Error())
		return
	}
	// Do not Wait: msiexec will stop this service, and a Wait would block the
	// stop the SCM needs to deliver. Release the handle and let it run.
	_ = cmd.Process.Release()

	m.waitForRestart(ctx, version)
}
