//go:build !windows

package agent

import "github.com/INFORENT-GmbH/host-agent/internal/brand"

// prepareStateDir has nothing to check on Unix: the state directory lives
// below /var/lib, which only root can write, and the package creates it.
func prepareStateDir(brand.Brand) error { return nil }
