//go:build !linux && !windows

package collect

import (
	"context"
	"errors"
)

// scanProcesses has no implementation here; the collector reports nothing.
func scanProcesses(context.Context) (procScan, error) {
	return procScan{}, errors.ErrUnsupported
}
