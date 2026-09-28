// Package brand derives the reseller brand and every on-disk location from the
// name the binary was installed under. One build serves all brands: the
// package for brand "acme" installs /usr/bin/acme-agent, and that binary then
// reads /etc/acme-agent/agent.conf, keeps state in /var/lib/acme-agent and
// runs as acme-agent.service.
package brand

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// keyRE is the portal's brand_key rule (BRAND_KEY_RE in
// api/src/settings/brands.ts): 3-24 chars, a-z/0-9/hyphen, starts with a
// letter, no hyphen at the end. Keep both in step.
var keyRE = regexp.MustCompile(`^[a-z][a-z0-9-]{1,22}[a-z0-9]$`)

const binarySuffix = "-agent"

// ErrNotBranded means the executable name does not follow <key>-agent.
var ErrNotBranded = errors.New("executable name is not <brand>-agent")

// Brand is one reseller brand and the paths its agent uses.
type Brand struct {
	Key string
	// Root prefixes every absolute path. Empty in production; tests and local
	// development point it at a scratch directory.
	Root string
}

// New validates key and returns the brand rooted at root.
func New(key, root string) (Brand, error) {
	if !keyRE.MatchString(key) {
		return Brand{}, fmt.Errorf("invalid brand key %q", key)
	}
	return Brand{Key: key, Root: root}, nil
}

// FromExecutable derives the brand from a program path such as
// /usr/bin/acme-agent.
func FromExecutable(path, root string) (Brand, error) {
	base := filepath.Base(path)
	if !strings.HasSuffix(base, binarySuffix) {
		return Brand{}, fmt.Errorf("%w: %q", ErrNotBranded, base)
	}
	return New(strings.TrimSuffix(base, binarySuffix), root)
}

// Name is the package, binary and unit base name, e.g. "acme-agent".
func (b Brand) Name() string { return b.Key + binarySuffix }

// Unit is the systemd unit name. On Windows the service is registered under
// Name() instead; nothing reads Unit there.
func (b Brand) Unit() string { return b.Name() + ".service" }

// ConfigFile is the TOML configuration including the host token.
func (b Brand) ConfigFile() string { return filepath.Join(b.ConfigDir(), "agent.conf") }

// PollerUser is the unprivileged satellite poller account, e.g.
// "_acme-poller". The 24-char key cap exists so this always fits the
// 32-char Linux limit for user names.
func (b Brand) PollerUser() string { return "_" + b.Key + "-poller" }

// windowsBase is where a brand keeps everything on Windows: one directory
// below %ProgramData%, with the state in a subdirectory. Pure so the Linux
// tests cover it — paths_windows.go only supplies %ProgramData%.
func windowsBase(programData, name string) string {
	if strings.TrimSpace(programData) == "" {
		programData = `C:\ProgramData`
	}
	return filepath.Join(programData, name)
}
