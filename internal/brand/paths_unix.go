//go:build unix

package brand

import "path/filepath"

// ConfigDir holds agent.conf and nothing else.
func (b Brand) ConfigDir() string { return b.path("/etc", b.Name()) }

// StateDir holds the send buffer and runtime state.
func (b Brand) StateDir() string { return b.path("/var/lib", b.Name()) }

// AptSourceFile is the apt source list our packages install; the self-update
// refreshes only this list before upgrading.
func (b Brand) AptSourceFile() string {
	return b.path("/etc/apt/sources.list.d", b.Name()+".list")
}

func (b Brand) path(parts ...string) string {
	return filepath.Join(append([]string{"/", b.Root}, parts...)...)
}
