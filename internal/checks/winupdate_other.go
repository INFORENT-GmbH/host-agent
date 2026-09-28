//go:build !windows

package checks

import (
	"context"
	"errors"
)

func searchPendingUpdates(context.Context) ([]winUpdate, error) {
	return nil, errors.ErrUnsupported
}
