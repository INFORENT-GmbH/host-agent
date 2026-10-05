//go:build windows

package update

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/INFORENT-GmbH/host-agent/internal/winsec"
	"golang.org/x/sys/windows"
)

// run performs the Windows self-update: fetch the per-version manifest, its
// detached signature and the MSI it names over TLS from the brand's own host,
// verify the signature against the compiled-in release keys (signature.go)
// and the MSI against the manifest's SHA-256, then hand it to a DETACHED
// msiexec.
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

	manURL := manifestURL(m.packageBase, version)
	man, err := m.httpGet(fctx, manURL)
	if err != nil {
		m.clearPending()
		m.fail(version, "fetching the update manifest: "+oneLine(err.Error()))
		return
	}
	sig, err := m.httpGet(fctx, signatureURL(manURL))
	if err != nil {
		m.clearPending()
		m.fail(version, "fetching the manifest signature: "+oneLine(err.Error()))
		return
	}
	ring, err := releaseKeys()
	if err == nil {
		err = verifyManifestSignature(ring, man, sig)
	}
	if err != nil {
		m.clearPending()
		m.fail(version, oneLine(err.Error()))
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
	// process, which msiexec is about to kill. msiexec runs it as LocalSystem,
	// so the directory is checked right here — owner and DACL privileged, a
	// plain directory and not a junction (winsec.CheckDir) — and the file gets
	// an unpredictable name, so nobody can stage or swap it between our write
	// and msiexec's read. Installers of earlier runs are removed first.
	stateDir := m.b.StateDir()
	if err := winsec.CheckDir(stateDir); err != nil {
		m.clearPending()
		m.fail(version, "state directory: "+oneLine(err.Error()))
		return
	}
	removeOldInstallers(stateDir)
	msiPath, err := writeInstaller(stateDir, version, body)
	if err != nil {
		m.clearPending()
		m.fail(version, "saving the installer: "+oneLine(err.Error()))
		return
	}
	logPath := filepath.Join(stateDir, "update-"+version+".log")
	sysDir, err := windows.GetSystemDirectory()
	if err != nil {
		m.clearPending()
		m.fail(version, "locating msiexec: "+err.Error())
		return
	}

	// /qn silent, /norestart so a pending-reboot MSI never reboots the host on
	// its own; /l*v leaves a verbose log for the acceptance run's post-mortem.
	cmd := exec.Command(filepath.Join(sysDir, "msiexec.exe"), "/i", msiPath, "/qn", "/norestart", "/l*v", logPath) // #nosec G204 -- state-dir paths, validated version
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

// writeInstaller stores the verified MSI under a random name in the state
// directory. CreateTemp opens it exclusively (CREATE_NEW), so a name planted
// in advance makes the write fail instead of being followed.
func writeInstaller(dir, version string, body []byte) (string, error) {
	f, err := os.CreateTemp(dir, "update-"+version+"-*.msi")
	if err != nil {
		return "", err
	}
	if _, err := f.Write(body); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// removeOldInstallers deletes the MSIs earlier updates left behind; their
// logs (one per version) stay for the post-mortem. Best effort: a leftover file costs disk
// space, not safety.
func removeOldInstallers(dir string) {
	old, _ := filepath.Glob(filepath.Join(dir, "update-*.msi"))
	for _, p := range old {
		_ = os.Remove(p)
	}
}
