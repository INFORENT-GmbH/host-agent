//go:build unix

package localchecks

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// checkSecure requires every given path to be owned by root (when
// requireRoot) and not writable by group or others. Callers pass the file
// and each directory up to the configured base, so no level in between can
// be swapped by an unprivileged user.
func checkSecure(requireRoot bool, paths ...string) error {
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return err
		}
		if info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%w: %s is writable by group or others", ErrInsecure, p)
		}
		if requireRoot {
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok || st.Uid != 0 {
				return fmt.Errorf("%w: %s is not owned by root", ErrInsecure, p)
			}
		}
	}
	return nil
}

// runCommand runs cmd in its own process group and kills the whole group
// on timeout, so a hanging script cannot leave children behind.
func runCommand(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.Command(name, args...) // #nosec G204 -- root-owned local check / mrpe.cfg, checked by checkSecure
	cmd.Env = append([]string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=C.UTF-8",
	}, checkmkEnv()...) // variables some existing scripts rely on
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
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
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-done
		return nil, -1, fmt.Errorf("timed out after %s", timeout)
	}
}

// isExecutableScript is the Unix rule: a plain file with any execute bit.
func isExecutableScript(_ string, info os.FileInfo) bool {
	return info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0
}
