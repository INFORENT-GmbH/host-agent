// Package hostinfo identifies the host for the hello message.
//
// Everything platform-specific sits in hostinfo_unix.go and
// hostinfo_windows.go behind the two functions osInfo and machineID; the
// parsing each of them needs stays here, untagged, so the Windows logic is
// covered by the tests on Linux as well.
package hostinfo

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

// Info is what the gateway learns about the host on every connect.
type Info struct {
	Hostname  string
	MachineID string
	OS        protocol.OSInfo
}

// machineIDRE is the gateway's shape for hosts.machine_id: 32 lowercase hex
// digits. Linux gets that from /etc/machine-id, Windows from the registry's
// MachineGuid once the hyphens are gone.
var machineIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Gather reads host identity. root prefixes system paths (tests only, and
// only where the platform has such paths).
func Gather(root string) (Info, error) {
	host, err := os.Hostname()
	if err != nil {
		return Info{}, fmt.Errorf("hostname: %w", err)
	}
	id, err := machineID(root)
	if err != nil {
		return Info{}, err
	}
	name, version, kernel := osInfo(root)
	if name == "" {
		name = runtime.GOOS
	}
	return Info{
		Hostname:  host,
		MachineID: id,
		OS: protocol.OSInfo{
			Name:    name,
			Version: version,
			Kernel:  kernel,
			Arch:    runtime.GOARCH,
		},
	}, nil
}

// normalizeMachineID turns a raw identifier into the gateway's shape, or
// reports false. It accepts the hyphenated, upper-case form Windows keeps in
// HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid as well as the bare 32
// hex digits systemd writes to /etc/machine-id.
func normalizeMachineID(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "-", "")
	if !machineIDRE.MatchString(s) {
		return "", false
	}
	return s, true
}

// osRelease parses os-release(5); missing files yield an empty map.
func osRelease(root string) map[string]string {
	out := map[string]string{}
	for _, p := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		b, err := os.ReadFile(joinRoot(root, p)) // #nosec G304 -- fixed system paths
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
			if !ok || strings.HasPrefix(k, "#") {
				continue
			}
			out[k] = unquote(v)
		}
		return out
	}
	return out
}

func unquote(v string) string {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		v = v[1 : len(v)-1]
	}
	return strings.NewReplacer(`\"`, `"`, `\$`, `$`, "\\`", "`", `\\`, `\`).Replace(v)
}

// joinRoot prefixes an absolute system path with the test root.
func joinRoot(root, p string) string { return filepath.Join("/", root, p) }

// windowsKernel renders the NT version as the closest analogue to a kernel
// release, e.g. "10.0.17763" for Windows Server 2019.
func windowsKernel(major, minor, build uint32) string {
	return fmt.Sprintf("%d.%d.%d", major, minor, build)
}

// windowsOSName cleans up what the registry reports. Two quirks:
// CurrentVersion\ProductName still says "Windows 10" on Windows 11 (Microsoft
// never updated the value; the build number is the only honest signal, 22000
// is the first Windows 11 build), and DisplayVersion ("22H2") only exists
// from build 19042 on — older systems carry ReleaseId instead, and Server
// editions neither, which leaves the build number as the version.
func windowsOSName(productName, displayVersion, releaseID string, build uint32) (name, version string) {
	name = strings.TrimSpace(productName)
	if build >= 22000 && strings.HasPrefix(name, "Windows 10") {
		name = "Windows 11" + strings.TrimPrefix(name, "Windows 10")
	}
	switch {
	case strings.TrimSpace(displayVersion) != "":
		version = strings.TrimSpace(displayVersion)
	case strings.TrimSpace(releaseID) != "":
		version = strings.TrimSpace(releaseID)
	default:
		version = strconv.FormatUint(uint64(build), 10)
	}
	return name, version
}
