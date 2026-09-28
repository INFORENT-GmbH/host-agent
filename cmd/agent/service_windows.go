//go:build windows

package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/INFORENT-GmbH/host-agent/internal/brand"
)

const serviceCommandHelp = `  service   register the Windows service: service install|uninstall|start|stop
`

// stopTimeout is how long `service stop` waits for the service control
// manager to report the service stopped.
const stopTimeout = 30 * time.Second

// serviceCommand registers the agent with the Windows service control
// manager. The MSI does this at install time; the command exists so a host
// can be set up and taken apart by hand.
func serviceCommand(b brand.Brand, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "usage: service install|uninstall|start|stop")
		return 2
	}
	m, err := mgr.Connect()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "service control manager: %v\n", err)
		return 1
	}
	defer func() { _ = m.Disconnect() }()

	switch args[0] {
	case "install":
		return installService(m, b, stdout, stderr)
	case "uninstall":
		return withService(m, b, stderr, func(s *mgr.Service) int {
			if err := s.Delete(); err != nil {
				_, _ = fmt.Fprintf(stderr, "removing %s: %v\n", b.Name(), err)
				return 1
			}
			_, _ = fmt.Fprintf(stdout, "%s removed\n", b.Name())
			return 0
		})
	case "start":
		return withService(m, b, stderr, func(s *mgr.Service) int {
			if err := s.Start(); err != nil {
				_, _ = fmt.Fprintf(stderr, "starting %s: %v\n", b.Name(), err)
				return 1
			}
			_, _ = fmt.Fprintf(stdout, "%s started\n", b.Name())
			return 0
		})
	case "stop":
		return withService(m, b, stderr, func(s *mgr.Service) int {
			return stopService(s, b, stdout, stderr)
		})
	}
	_, _ = fmt.Fprintf(stderr, "unknown service command %q\n", args[0])
	return 2
}

func installService(m *mgr.Mgr, b brand.Brand, stdout, stderr io.Writer) int {
	exe, err := os.Executable()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "locating the agent binary: %v\n", err)
		return 1
	}
	if s, err := m.OpenService(b.Name()); err == nil {
		_ = s.Close()
		_, _ = fmt.Fprintf(stderr, "%s is already installed\n", b.Name())
		return 1
	}
	s, err := m.CreateService(b.Name(), exe, mgr.Config{
		DisplayName: b.Name(),
		Description: b.Key + " host monitoring agent",
		StartType:   mgr.StartAutomatic,
		// LocalSystem: the agent reads every filesystem, the service control
		// manager and the update state, and it must survive user logoff.
		ServiceStartName: "LocalSystem",
	}, "run")
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "installing %s: %v\n", b.Name(), err)
		return 1
	}
	defer func() { _ = s.Close() }()
	// Restart the agent if it ever dies: a monitoring agent that stays down
	// after one crash is worse than no monitoring, because the host looks
	// quiet rather than broken.
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	}, 86400); err != nil {
		_, _ = fmt.Fprintf(stderr, "warning: recovery actions for %s: %v\n", b.Name(), err)
	}
	_, _ = fmt.Fprintf(stdout, "%s installed\n", b.Name())
	return 0
}

func stopService(s *mgr.Service, b brand.Brand, stdout, stderr io.Writer) int {
	status, err := s.Control(svc.Stop)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "stopping %s: %v\n", b.Name(), err)
		return 1
	}
	deadline := time.Now().Add(stopTimeout)
	for status.State != svc.Stopped {
		if time.Now().After(deadline) {
			_, _ = fmt.Fprintf(stderr, "%s did not stop within %s\n", b.Name(), stopTimeout)
			return 1
		}
		time.Sleep(300 * time.Millisecond)
		if status, err = s.Query(); err != nil {
			_, _ = fmt.Fprintf(stderr, "querying %s: %v\n", b.Name(), err)
			return 1
		}
	}
	_, _ = fmt.Fprintf(stdout, "%s stopped\n", b.Name())
	return 0
}

func withService(m *mgr.Mgr, b brand.Brand, stderr io.Writer, fn func(*mgr.Service) int) int {
	s, err := m.OpenService(b.Name())
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s is not installed: %v\n", b.Name(), err)
		return 1
	}
	defer func() { _ = s.Close() }()
	return fn(s)
}
