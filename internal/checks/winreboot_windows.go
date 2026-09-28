//go:build windows

package checks

import (
	"errors"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// The four places Windows records a pending restart. There is no API that
// answers the question; these keys are what Microsoft's own documentation
// and every administrator script look at.
const (
	cbsRebootKey     = `SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`
	wuRebootKey      = `SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`
	sessionMgrKey    = `SYSTEM\CurrentControlSet\Control\Session Manager`
	computerNameKey  = `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`
	activeComputerNK = `SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName`
)

func readRebootSignals() (rebootSignals, error) {
	s := rebootSignals{
		ComponentBasedServicing: keyExists(cbsRebootKey),
		WindowsUpdate:           keyExists(wuRebootKey),
	}
	// PendingFileRenameOperations exists but empty means nothing is queued —
	// treating the mere presence of the value as a pending reboot would flag
	// a large share of healthy hosts forever.
	if names, err := multiStringValue(sessionMgrKey, "PendingFileRenameOperations"); err == nil {
		for _, n := range names {
			if strings.TrimSpace(n) != "" {
				s.FileRename = true
				break
			}
		}
	}
	active, err1 := stringValue(activeComputerNK, "ComputerName")
	pending, err2 := stringValue(computerNameKey, "ComputerName")
	if err1 == nil && err2 == nil {
		s.ComputerRename = !strings.EqualFold(active, pending)
	}
	return s, nil
}

func keyExists(path string) bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	_ = k.Close()
	return true
}

func stringValue(path, name string) (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer func() { _ = k.Close() }()
	v, _, err := k.GetStringValue(name)
	return v, err
}

func multiStringValue(path, name string) ([]string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	defer func() { _ = k.Close() }()
	v, _, err := k.GetStringsValue(name)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, nil
	}
	return v, err
}
