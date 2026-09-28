//go:build windows

package checks

import (
	"context"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// listServices enumerates the service control manager. Two calls per host
// are unavoidable: the enumeration gives names and states, the start type
// comes from each service's configuration.
//
// Handles are opened with query rights only, not with the ALL_ACCESS that
// mgr.Connect and mgr.OpenService ask for. The agent runs as LocalSystem and
// would usually get away with it, but a monitoring agent that holds a handle
// allowing it to delete or reconfigure every service on the host is a
// liability, not a convenience.
func listServices(ctx context.Context) ([]winService, error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return nil, err
	}
	defer func() { _ = windows.CloseServiceHandle(scm) }()

	names, err := enumServices(scm)
	if err != nil {
		return nil, err
	}
	out := make([]winService, 0, len(names))
	for _, s := range names {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		cfg, err := serviceConfig(scm, s.Name)
		if err != nil {
			// A service can disappear between the enumeration and this call,
			// and some protected services refuse the query. Neither is worth
			// failing the whole check for.
			continue
		}
		s.StartType = cfg.StartType
		s.DelayedAutoStart = cfg.DelayedAutoStart
		out = append(out, s)
	}
	return out, nil
}

// enumServices returns every Win32 service with its current state.
func enumServices(scm windows.Handle) ([]winService, error) {
	var bytesNeeded, count, resume uint32
	err := windows.EnumServicesStatusEx(scm, windows.SC_ENUM_PROCESS_INFO,
		windows.SERVICE_WIN32, windows.SERVICE_STATE_ALL, nil, 0, &bytesNeeded, &count, &resume, nil)
	if err != nil && err != windows.ERROR_MORE_DATA {
		return nil, err
	}
	buf := make([]byte, bytesNeeded)
	if err := windows.EnumServicesStatusEx(scm, windows.SC_ENUM_PROCESS_INFO,
		windows.SERVICE_WIN32, windows.SERVICE_STATE_ALL, &buf[0], bytesNeeded, &bytesNeeded, &count, &resume, nil); err != nil {
		return nil, err
	}
	services := unsafe.Slice((*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buf[0])), count) // #nosec G103 -- documented API layout
	out := make([]winService, 0, count)
	for _, s := range services {
		out = append(out, winService{
			Name:             windows.UTF16PtrToString(s.ServiceName),
			DisplayName:      windows.UTF16PtrToString(s.DisplayName),
			State:            s.ServiceStatusProcess.CurrentState,
			ExitCode:         s.ServiceStatusProcess.Win32ExitCode,
			SpecificExitCode: s.ServiceStatusProcess.ServiceSpecificExitCode,
		})
	}
	return out, nil
}

// serviceConfig reads the start type of one service through the mgr package,
// which knows how to unpack QUERY_SERVICE_CONFIG — but on a handle we opened
// ourselves with query rights only.
func serviceConfig(scm windows.Handle, name string) (mgr.Config, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return mgr.Config{}, err
	}
	h, err := windows.OpenService(scm, p, windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return mgr.Config{}, err
	}
	s := &mgr.Service{Name: name, Handle: h}
	defer func() { _ = s.Close() }()
	return s.Config()
}
