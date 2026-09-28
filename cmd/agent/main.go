// Command agent is the host monitoring agent. It is installed per brand as
// /usr/bin/<brand>-agent and derives its brand and paths from that name.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/INFORENT-GmbH/host-agent/internal/brand"
	"github.com/INFORENT-GmbH/host-agent/internal/buildinfo"
	"github.com/INFORENT-GmbH/host-agent/internal/config"
)

// Development overrides: `go run` produces a binary without the -agent
// suffix, and tests must not touch /etc.
const (
	envBrand = "AGENT_BRAND"
	envRoot  = "AGENT_ROOT"
)

func main() {
	os.Exit(run(os.Args, os.Getenv, os.Stdout, os.Stderr))
}

func run(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	b, err := resolveBrand(args[0], getenv)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%v\n", err)
		return 2
	}
	if len(args) < 2 {
		usage(stderr, b)
		return 2
	}
	switch args[1] {
	case "version":
		_, _ = fmt.Fprintf(stdout, "%s %s\n", b.Name(), buildinfo.Version)
		return 0
	case "status":
		return status(b, stdout, stderr)
	case "dump":
		return dump(context.Background(), b, args[2:], stdout, stderr)
	case "enroll":
		return enroll(context.Background(), b, args[2:], getenv, stdout, stderr)
	case "run":
		// How the agent is supervised differs: systemd starts it as a plain
		// foreground process, the Windows SCM expects a service that answers
		// control requests (run_unix.go, run_windows.go).
		return startAgent(b, stderr)
	case "service":
		// Registering a Windows service; on Linux systemd owns that and the
		// command says so (service_unix.go).
		return serviceCommand(b, args[2:], stdout, stderr)
	case "help", "-h", "--help":
		usage(stdout, b)
		return 0
	}
	_, _ = fmt.Fprintf(stderr, "unknown command %q\n\n", args[1])
	usage(stderr, b)
	return 2
}

func resolveBrand(argv0 string, getenv func(string) string) (brand.Brand, error) {
	root := getenv(envRoot)
	if key := getenv(envBrand); key != "" {
		return brand.New(key, root)
	}
	b, err := brand.FromExecutable(argv0, root)
	if errors.Is(err, brand.ErrNotBranded) {
		return brand.Brand{}, fmt.Errorf("%w (set %s for development)", err, envBrand)
	}
	return b, err
}

func usage(w io.Writer, b brand.Brand) {
	_, _ = fmt.Fprintf(w, `Usage: %s <command>

Commands:
  enroll    register this host: enroll -url https://<gateway> -token <token>
            [-channel stable|testing|off] [-local-checks=false] [-force]
            [-package-base https://<repo>]  (Windows self-update source)
  run       run the agent (started by the service manager)
  dump      collect once and print what would be sent (sends nothing)
  status    show configuration and enrollment state
  version   print the agent version
%s`, b.Name(), serviceCommandHelp)
}

// status never prints the token — its output ends up in support tickets.
func status(b brand.Brand, stdout, stderr io.Writer) int {
	_, _ = fmt.Fprintf(stdout, "agent:        %s %s\n", b.Name(), buildinfo.Version)
	_, _ = fmt.Fprintf(stdout, "config:       %s\n", b.ConfigFile())
	cfg, err := config.Load(b.ConfigFile())
	if errors.Is(err, os.ErrNotExist) {
		_, _ = fmt.Fprintln(stdout, "enrolled:     no (config file missing)")
		return 1
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "config error: %v\n", err)
		return 1
	}
	if cfg.Enrolled() {
		_, _ = fmt.Fprintln(stdout, "enrolled:     yes")
		_, _ = fmt.Fprintf(stdout, "gateway:      %s\n", cfg.Server.URL)
	} else {
		_, _ = fmt.Fprintln(stdout, "enrolled:     no")
	}
	_, _ = fmt.Fprintf(stdout, "satellite:    %s\n", onOff(cfg.Local.Satellite))
	_, _ = fmt.Fprintf(stdout, "local checks: %s\n", onOff(cfg.Local.LocalChecks))
	_, _ = fmt.Fprintf(stdout, "log level:    %s\n", cfg.Log.Level)
	return 0
}

func onOff(v bool) string {
	if v {
		return "on"
	}
	return "off"
}
