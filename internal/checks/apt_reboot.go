package checks

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

// ---------------------------------------------------------------- apt

// aptCacheTTL: the simulation takes seconds of CPU; package lists only
// change when the system's own apt timer refreshes them. The agent never
// runs `apt-get update` itself — no network, no side effects.
const aptCacheTTL = time.Hour

type aptCheck struct {
	// simulate is replaced in tests.
	simulate func(ctx context.Context) ([]byte, error)
	lookPath func(string) (string, error)

	cached   *protocol.CheckResult
	cachedAt time.Time
}

func (*aptCheck) Plugin() string { return "apt" }

func (c *aptCheck) applies() bool {
	lp := c.lookPath
	if lp == nil {
		lp = exec.LookPath
	}
	_, err := lp("apt-get")
	return err == nil
}

func (c *aptCheck) Discover(context.Context) ([]protocol.DiscoveredItem, error) {
	if !c.applies() {
		return nil, nil
	}
	return []protocol.DiscoveredItem{{Plugin: "apt", Description: "APT updates"}}, nil
}

func (c *aptCheck) Run(ctx context.Context, now time.Time) ([]protocol.CheckResult, error) {
	if !c.applies() {
		return nil, nil
	}
	if c.cached != nil && now.Sub(c.cachedAt) < aptCacheTTL {
		return []protocol.CheckResult{*c.cached}, nil
	}
	sim := c.simulate
	if sim == nil {
		sim = simulateUpgrade
	}
	out, err := sim(ctx)
	if err != nil {
		// Not cached: the next run tries again.
		return []protocol.CheckResult{unknown("apt", "", err)}, nil
	}
	r := evaluateApt(out)
	c.cached, c.cachedAt = &r, now
	return []protocol.CheckResult{r}, nil
}

var aptInstRE = regexp.MustCompile(`^Inst (\S+) (?:\[[^\]]*\] )?\((\S+) ([^)]*)\)`)

// evaluateApt parses `apt-get -s dist-upgrade`. A package counts as a
// security update when any of its origins is a security archive
// ("Debian-Security:13/stable-security", "Ubuntu:24.04/noble-security").
func evaluateApt(out []byte) protocol.CheckResult {
	var all, security []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		m := aptInstRE.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		all = append(all, m[1])
		if strings.Contains(strings.ToLower(m[3]), "security") {
			security = append(security, m[1])
		}
	}
	r := protocol.CheckResult{
		Plugin: "apt",
		Values: map[string]float64{"updates": float64(len(all)), "security_updates": float64(len(security))},
	}
	switch {
	case len(security) > 0:
		r.Summary = listSummary(fmt.Sprintf("%d updates, %d security", len(all), len(security)), security)
	case len(all) > 0:
		r.Summary = listSummary(fmt.Sprintf("%d updates", len(all)), all)
	}
	return r
}

func simulateUpgrade(ctx context.Context) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "apt-get",
		"-o", "Debug::NoLocking=1",
		"-o", "APT::Get::Show-User-Simulation-Note=false",
		"-s", "-qq", "dist-upgrade")
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, errors.New("apt-get simulation failed: " + msg)
	}
	return out, nil
}

// ---------------------------------------------------------------- reboot

// rebootCheck combines two signals: the reboot-required flag that Debian
// and Ubuntu packages set, and a running kernel older than the newest
// installed one (which also covers distributions without the flag).
type rebootCheck struct {
	root string // prefixes /run, /var/run and /boot in tests
	// release is the running kernel; replaced in tests.
	release func() string
}

func (rebootCheck) Plugin() string { return "reboot" }

func (rebootCheck) Discover(context.Context) ([]protocol.DiscoveredItem, error) {
	return []protocol.DiscoveredItem{{Plugin: "reboot", Description: "Reboot required"}}, nil
}

func (c rebootCheck) Run(context.Context, time.Time) ([]protocol.CheckResult, error) {
	flag, pkgs := c.flag()
	running := c.runningRelease()
	newest := c.newestKernel()
	outdated := running != "" && newest != "" && newest != running
	r := protocol.CheckResult{
		Plugin: "reboot",
		Values: map[string]float64{"reboot_required": boolValue(flag || outdated), "kernel_outdated": boolValue(outdated)},
	}
	switch {
	case outdated:
		r.Summary = Summary(fmt.Sprintf("running kernel %s, newest installed %s", running, newest))
	case flag && len(pkgs) > 0:
		r.Summary = listSummary("required by", pkgs)
	case flag:
		r.Summary = "reboot required"
	}
	return []protocol.CheckResult{r}, nil
}

func (c rebootCheck) path(p string) string { return filepath.Join("/", c.root, p) }

func (c rebootCheck) flag() (bool, []string) {
	for _, dir := range []string{"/run", "/var/run"} {
		if _, err := os.Stat(c.path(dir + "/reboot-required")); err != nil {
			continue
		}
		b, _ := os.ReadFile(c.path(dir + "/reboot-required.pkgs")) // #nosec G304 -- fixed system path
		var pkgs []string
		for _, l := range strings.Split(string(b), "\n") {
			if l = strings.TrimSpace(l); l != "" && !slices.Contains(pkgs, l) {
				pkgs = append(pkgs, l)
			}
		}
		return true, pkgs
	}
	return false, nil
}

func (c rebootCheck) runningRelease() string {
	if c.release != nil {
		return c.release()
	}
	return runningKernel()
}

// newestKernel is the release of the most recently installed
// /boot/vmlinuz-<release>. Install time, not version order: comparing
// distribution kernel versions correctly is not worth the risk here.
func (c rebootCheck) newestKernel() string {
	matches, _ := filepath.Glob(c.path("/boot/vmlinuz-*"))
	var (
		newest   string
		newestAt time.Time
	)
	for _, m := range matches {
		info, err := os.Stat(m)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if info.ModTime().After(newestAt) {
			newest, newestAt = strings.TrimPrefix(filepath.Base(m), "vmlinuz-"), info.ModTime()
		}
	}
	return newest
}
