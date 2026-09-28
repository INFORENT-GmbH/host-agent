//go:build windows

package checks

// Default returns the built-in Windows checks.
//
// Three of the Linux checks are deliberately absent, and one is missing for
// now:
//
//   - cpu.load — Windows has no load average. gopsutil emulates one from a
//     performance counter it samples in the background; that number would
//     look like the Linux one on the same dashboard while meaning something
//     else, so we do not report it at all.
//   - systemd, apt, reboot — Linux service manager and package manager. Their
//     Windows counterparts are their own checks, not adaptations of these:
//     "services" for the service control manager, "winupdate" for Windows
//     Update and "winreboot" for a pending restart.
//
// timesync stays in: the check disables itself where the platform cannot
// answer (collect.TimeSync reports errors.ErrUnsupported off Linux), so it
// costs nothing until Windows gets a real implementation.
func Default() []Check {
	return []Check{
		&cpuUtilCheck{},
		memCheck{},
		uptimeCheck{},
		timeSyncCheck{},
		dfCheck{},
		&ifCheck{},
		&servicesCheck{},
		&winUpdateCheck{},
		&winRebootCheck{},
	}
}
