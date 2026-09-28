//go:build windows

package brand

import (
	"os"
	"path/filepath"
)

// ConfigDir holds agent.conf below %ProgramData%, e.g.
// C:\ProgramData\acme-agent. Windows has no /etc: ProgramData is the
// per-machine location for application data, and it is the directory the
// installer locks down (see internal/winsec — its inherited ACL would
// otherwise let every local account read the host token).
func (b Brand) ConfigDir() string { return b.path(windowsBase(os.Getenv("ProgramData"), b.Name())) }

// StateDir holds the send buffer and runtime state, below the config
// directory rather than in a second tree: Windows has no /var/lib, and one
// directory per brand keeps uninstalling simple.
func (b Brand) StateDir() string { return filepath.Join(b.ConfigDir(), "state") }

// AptSourceFile has no Windows meaning — there is no apt. The self-update
// fetches the MSI named in the brand's release manifest instead; an empty
// path makes the Linux update path fail loudly rather than act on a
// nonsensical file.
func (b Brand) AptSourceFile() string { return "" }

// path prefixes the test root. Unlike the Unix version it must not put a
// separator in front: a Windows path already starts with its drive letter.
func (b Brand) path(parts ...string) string {
	return filepath.Join(append([]string{b.Root}, parts...)...)
}
