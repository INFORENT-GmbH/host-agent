//go:build windows

package config

import (
	"fmt"
	"os"

	"github.com/INFORENT-GmbH/host-agent/internal/winsec"
)

// checkFileSecurity judges agent.conf — which carries the host token — by
// its owner and DACL; the rule itself lives in internal/winsec, where the
// Linux tests cover it. The FileInfo is unused: Go reports a meaningless
// 0666 for every readable file on Windows.
func checkFileSecurity(path string, _ os.FileInfo) error {
	if err := winsec.CheckPath(path); err != nil {
		return fmt.Errorf("%w: %v", ErrInsecure, err)
	}
	return nil
}
