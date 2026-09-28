//go:build unix

package localchecks

import (
	"os"
	"path/filepath"
)

// Checkmk's own locations, read so existing installations migrate without
// touching a single script.
const (
	CheckmkLocalDir = "/usr/lib/check_mk_agent/local"
	CheckmkMRPEFile = "/etc/check_mk/mrpe.cfg"
)

func checkmkPaths(root string) (localDir, mrpeFile string) {
	return filepath.Join("/", root, CheckmkLocalDir), filepath.Join("/", root, CheckmkMRPEFile)
}

// checkmkEnv are the variables Checkmk's Linux agent exports; old scripts
// read them instead of hard-coding paths.
func checkmkEnv() []string {
	return []string{
		"MK_CONFDIR=/etc/check_mk",
		"MK_LIBDIR=/usr/lib/check_mk_agent",
		"MK_VARDIR=/var/lib/check_mk_agent",
	}
}

// runningPrivileged decides whether the agent may insist that scripts are
// owned by a privileged account: an unprivileged agent cannot demand it.
func runningPrivileged() bool { return os.Geteuid() == 0 }
