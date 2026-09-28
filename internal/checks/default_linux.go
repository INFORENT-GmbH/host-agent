//go:build linux

package checks

// Default returns the built-in Linux checks.
func Default() []Check {
	return []Check{
		loadCheck{},
		&cpuUtilCheck{},
		memCheck{},
		uptimeCheck{},
		timeSyncCheck{},
		dfCheck{},
		&ifCheck{},
		&systemdCheck{},
		&aptCheck{},
		rebootCheck{},
	}
}
