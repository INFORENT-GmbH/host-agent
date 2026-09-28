//go:build !windows

package checks

import "errors"

func readRebootSignals() (rebootSignals, error) { return rebootSignals{}, errors.ErrUnsupported }
