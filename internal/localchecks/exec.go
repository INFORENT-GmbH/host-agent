package localchecks

import (
	"errors"
	"io"
	"path/filepath"
	"slices"
	"strings"
)

// maxOutput caps what one script may print; anything longer is cut.
const maxOutput = 1 << 20

// ErrInsecure means a script, its directory or mrpe.cfg could be modified by
// someone other than a privileged account. The agent runs these scripts with
// full privileges, so it would otherwise execute code any local user can
// plant. What "privileged" means is platform-specific: root and the mode bits
// on Unix (exec_unix.go), owner and DACL on Windows (exec_windows.go).
var ErrInsecure = errors.New("insecure local check")

type limitedWriter struct {
	w    io.Writer
	left int
}

// Write discards what exceeds the limit but reports success, so the script
// is not killed by SIGPIPE halfway through.
func (l *limitedWriter) Write(p []byte) (int, error) {
	n := len(p)
	if l.left <= 0 {
		return n, nil
	}
	if len(p) > l.left {
		p = p[:l.left]
	}
	l.left -= len(p)
	if _, err := l.w.Write(p); err != nil {
		return 0, err
	}
	return n, nil
}

// windowsScriptExtensions are the suffixes Windows can start directly.
// .ps1 is in the list because Checkmk's Windows agent runs PowerShell local
// checks; .sh is not, because a Windows host without a shell would fail
// every run of a script that was copied over from a Linux installation.
var windowsScriptExtensions = []string{".bat", ".cmd", ".exe", ".ps1"}

// isWindowsScript replaces the executable bit, which Windows does not have.
// Untagged so the Linux tests cover it — there is no Windows runner.
func isWindowsScript(name string) bool {
	return slices.Contains(windowsScriptExtensions, strings.ToLower(filepath.Ext(name)))
}
