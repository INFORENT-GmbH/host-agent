//go:build windows

package agent

import (
	"fmt"
	"os"

	"github.com/INFORENT-GmbH/host-agent/internal/brand"
	"github.com/INFORENT-GmbH/host-agent/internal/winsec"
)

// prepareStateDir refuses to run on a state directory someone else could
// write to. Below %ProgramData% any local user may create directories, so one
// planted there before the agent was installed keeps its owner — and the
// agent, running as LocalSystem, would keep its send buffer and stage the
// self-update's MSI in it. The configuration directory above it is checked
// too: whoever controls it can replace the state directory at will. The
// installer secures the configuration directory (Protect-ConfigDir), and a
// state directory the agent creates below it inherits that ACL.
func prepareStateDir(b brand.Brand) error {
	if err := winsec.CheckDir(b.ConfigDir()); err != nil {
		return fmt.Errorf("configuration directory: %w", err)
	}
	if err := os.MkdirAll(b.StateDir(), 0o700); err != nil {
		return fmt.Errorf("state directory: %w", err)
	}
	if err := winsec.CheckDir(b.StateDir()); err != nil {
		return fmt.Errorf("state directory: %w — remove it and reinstall the agent", err)
	}
	return nil
}
