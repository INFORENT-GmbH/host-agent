//go:build windows

package localchecks

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// checkmkBase is where Checkmk's Windows agent keeps everything.
func checkmkBase(root string) string {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	return filepath.Join(root, programData, "checkmk", "agent")
}

// checkmkPaths mirrors that layout, so an existing Checkmk installation's
// scripts are picked up unchanged, the same way the Unix branch reads
// /usr/lib/check_mk_agent/local. The MRPE file sits in the agent's config
// directory — Checkmk's Windows agent configures MRPE inside its YAML
// instead of a separate file, so this location is ours, chosen to sit where
// an administrator would look for it.
func checkmkPaths(root string) (localDir, mrpeFile string) {
	base := checkmkBase(root)
	return filepath.Join(base, "local"), filepath.Join(base, "config", "mrpe.cfg")
}

// checkmkEnv are the variables Checkmk's Windows agent exports. Scripts
// carried over from a Checkmk installation read them, and a plugin that
// keeps state between runs needs MK_STATEDIR to exist.
func checkmkEnv() []string {
	base := checkmkBase("")
	return []string{
		"MK_CONFDIR=" + filepath.Join(base, "config"),
		"MK_LOCALDIR=" + filepath.Join(base, "local"),
		"MK_STATEDIR=" + filepath.Join(base, "state"),
		"MK_LOGDIR=" + filepath.Join(base, "log"),
		"MK_SPOOLDIR=" + filepath.Join(base, "spool"),
		"MK_TEMPDIR=" + filepath.Join(base, "tmp"),
		"MK_INSTALLDIR=" + filepath.Join(base, "install"),
	}
}

// runningPrivileged is the Windows counterpart of "am I root": the service
// runs as LocalSystem, whose token is elevated. os.Geteuid() must not be
// used here — it returns -1 on Windows, which would silently switch the
// security check off.
func runningPrivileged() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}
