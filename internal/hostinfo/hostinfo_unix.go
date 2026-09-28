//go:build unix

package hostinfo

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// osInfo names the distribution from os-release(5) and the running kernel
// from uname(2).
func osInfo(root string) (name, version, kernel string) {
	osr := osRelease(root)
	var uts unix.Utsname
	if err := unix.Uname(&uts); err == nil {
		kernel = unix.ByteSliceToString(uts.Release[:])
	}
	return osr["NAME"], osr["VERSION_ID"], kernel
}

// machineID is systemd's /etc/machine-id: stable across reboots and
// re-enrolls, unique per installation — the gateway uses it to recognise a
// reinstalled agent on the same host.
func machineID(root string) (string, error) {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		b, err := os.ReadFile(joinRoot(root, p)) // #nosec G304 -- fixed system paths
		if err != nil {
			continue
		}
		if id, ok := normalizeMachineID(string(b)); ok {
			return id, nil
		}
	}
	return "", errors.New("no valid machine-id in /etc/machine-id or /var/lib/dbus/machine-id")
}
