//go:build unix

package checks

import "golang.org/x/sys/unix"

// runningKernel is the release of the kernel this host booted, e.g.
// "6.1.0-23-amd64".
func runningKernel() string {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return ""
	}
	return unix.ByteSliceToString(uts.Release[:])
}
