//go:build !windows

package checks

import (
	"context"
	"errors"
)

// listServices exists so services.go — and with it the tests for the Windows
// judgement — build everywhere. Off Windows the check disables itself, the
// same way timesync does where the platform cannot answer.
func listServices(context.Context) ([]winService, error) {
	return nil, errors.ErrUnsupported
}
