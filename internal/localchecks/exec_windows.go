//go:build windows

package localchecks

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"time"

	"golang.org/x/sys/windows"

	"github.com/INFORENT-GmbH/host-agent/internal/winsec"
)

// checkSecure requires every given path to be owned by a privileged account
// and to grant access to nobody else — the Windows counterpart of "owned by
// root, not writable by group or others". requireRoot is honoured the same
// way as on Unix: when the agent does not run privileged, it cannot demand
// that the scripts are.
func checkSecure(requireRoot bool, paths ...string) error {
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			return err
		}
		if !requireRoot {
			continue
		}
		if err := winsec.CheckPath(p); err != nil {
			return fmt.Errorf("%w: %v", ErrInsecure, err)
		}
	}
	return nil
}

// runCommand runs cmd in its own process group and kills the whole tree on
// timeout. Windows has no process groups in the Unix sense: CREATE_NEW_-
// PROCESS_GROUP makes the child the root of one, and `taskkill /T /F` is
// what ends it together with its children — killing only the process would
// leave a hung script's children behind.
func runCommand(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.Command(name, args...) // #nosec G204 -- privileged-owned local check / mrpe.cfg, checked by checkSecure
	// A bare environment the way the Unix branch does it does not work on
	// Windows: nearly every program needs SystemRoot, and the interpreters
	// need the standard search path.
	cmd.Env = append([]string{
		"SystemRoot=" + os.Getenv("SystemRoot"),
		"windir=" + os.Getenv("windir"),
		"PATH=" + os.Getenv("PATH"),
		"PATHEXT=.COM;.EXE;.BAT;.CMD",
	}, checkmkEnv()...) // variables scripts carried over from Checkmk rely on
	cmd.SysProcAttr = &windows.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}
	var stdout bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &stdout, left: maxOutput}
	cmd.Stderr = io.Discard

	if err := cmd.Start(); err != nil {
		return nil, -1, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		if err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				return stdout.Bytes(), exitErr.ExitCode(), nil
			}
			return stdout.Bytes(), -1, err
		}
		return stdout.Bytes(), 0, nil
	case <-ctx.Done():
		killTree(cmd.Process.Pid)
		<-done
		return nil, -1, fmt.Errorf("timed out after %s", timeout)
	}
}

func killTree(pid int) {
	kill := exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(pid)) // #nosec G204 -- pid of our own child
	_ = kill.Run()
}

// isExecutableScript replaces the executable bit, which Windows does not
// have: a plain file counts when its extension is one the shell can start.
func isExecutableScript(path string, info os.FileInfo) bool {
	if !info.Mode().IsRegular() {
		return false
	}
	return isWindowsScript(path)
}
