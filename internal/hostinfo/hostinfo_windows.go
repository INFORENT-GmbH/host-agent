//go:build windows

package hostinfo

import (
	"errors"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// currentVersionKey holds the product name and the display version; the
// build number comes from RtlGetVersion instead, because the registry's
// CurrentBuild is a string and lies on older builds.
const currentVersionKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`

// cryptographyKey holds MachineGuid, written once when Windows is installed.
const cryptographyKey = `SOFTWARE\Microsoft\Cryptography`

// osInfo reads the product name from the registry and the NT version from
// RtlGetVersion. root is ignored: Windows has no prefixable system paths,
// and the values come from the registry, not from files.
func osInfo(string) (name, version, kernel string) {
	v := windows.RtlGetVersion()
	kernel = windowsKernel(v.MajorVersion, v.MinorVersion, v.BuildNumber)

	k, err := registry.OpenKey(registry.LOCAL_MACHINE, currentVersionKey, registry.QUERY_VALUE)
	if err != nil {
		// Without the registry we still know the NT version.
		return "", "", kernel
	}
	defer func() { _ = k.Close() }()
	product, _, _ := k.GetStringValue("ProductName")
	display, _, _ := k.GetStringValue("DisplayVersion")
	release, _, _ := k.GetStringValue("ReleaseId")
	name, version = windowsOSName(product, display, release, v.BuildNumber)
	return name, version, kernel
}

// machineID is the installation's MachineGuid. It is the Windows counterpart
// of /etc/machine-id: written by setup, stable across reboots, and — like
// machine-id — shared by every clone of an image that was not sysprepped.
// The gateway's MACHINE_ID_IN_USE guard covers that case.
func machineID(string) (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, cryptographyKey, registry.QUERY_VALUE)
	if err != nil {
		return "", errors.New("opening " + cryptographyKey + ": " + err.Error())
	}
	defer func() { _ = k.Close() }()
	raw, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		return "", errors.New("reading MachineGuid: " + err.Error())
	}
	id, ok := normalizeMachineID(raw)
	if !ok {
		return "", errors.New("MachineGuid is not a GUID: " + raw)
	}
	return id, nil
}
