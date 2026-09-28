//go:build unix

package config

import (
	"fmt"
	"os"
	"syscall"
)

// checkFileSecurity refuses a config file that others may read or write, and
// one not owned by root while running as root: an unprivileged user who owns
// the file could otherwise hand the root agent a gateway URL and token of
// their choosing.
func checkFileSecurity(path string, info os.FileInfo) error {
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%w: %s has mode %04o, want 0600", ErrInsecure, path, perm)
	}
	if os.Geteuid() != 0 {
		return nil
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: cannot determine owner of %s", ErrInsecure, path)
	}
	if st.Uid != 0 {
		return fmt.Errorf("%w: %s is owned by uid %d, want root", ErrInsecure, path, st.Uid)
	}
	return nil
}
