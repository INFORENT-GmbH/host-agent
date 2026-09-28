//go:build windows

package checks

import (
	"strconv"

	"golang.org/x/sys/windows"
)

// runningKernel is the NT version, the closest Windows has to a kernel
// release, e.g. "10.0.17763". The reboot check that reads it on Linux is not
// part of the Windows check set — Windows reports a pending restart through
// its own servicing state (winreboot), not through a newer kernel on disk.
func runningKernel() string {
	v := windows.RtlGetVersion()
	return strconv.FormatUint(uint64(v.MajorVersion), 10) + "." +
		strconv.FormatUint(uint64(v.MinorVersion), 10) + "." +
		strconv.FormatUint(uint64(v.BuildNumber), 10)
}
