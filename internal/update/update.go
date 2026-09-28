// Package update installs a newer agent build. The gateway's `update` message
// is the only action the server can trigger (see "Security model" in the
// README); everything runs through apt from the brand's own source, via a
// transient systemd unit that lives outside the agent's cgroup — dpkg
// restarts the agent service mid-upgrade, and the transient unit must survive
// that. Who reports the outcome depends on how it went: start and apt
// failures are reported by the still-running old agent, success by the
// restarted new one, which finds the pending file and compares its version.
package update

import (
	"context"
	"encoding/json/v2"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/INFORENT-GmbH/host-agent/internal/brand"
	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

const (
	// pendingFile below StateDir records the update in flight.
	pendingFile = "update.json"
	// runTimeout bounds the transient unit; a stale pending file older than
	// this is reported as a failure by whichever agent process finds it.
	runTimeout = 15 * time.Minute
	// restartGrace is how long after a successful apt run the old process
	// waits for dpkg to restart the service before calling it a failure.
	restartGrace = 30 * time.Second
)

// pending is the JSON in the pending file.
type pending struct {
	Version   string    `json:"version"`
	StartedAt time.Time `json:"startedAt"`
}

// Manager runs at most one update at a time.
type Manager struct {
	b       brand.Brand
	version string // this build, buildinfo.Version
	report  func(*protocol.UpdateResult)
	log     *slog.Logger

	// packageBase is the HTTPS base the Windows self-update fetches its
	// manifest and MSI from (https://apt.<brand>); the enroll/install step
	// writes it. Empty on Linux, where apt from the brand's own source needs
	// no such URL.
	packageBase string

	// Test seams.
	runCmd       func(ctx context.Context, name string, args ...string) ([]byte, error)
	httpGet      func(ctx context.Context, url string) ([]byte, error)
	now          func() time.Time
	runTimeout   time.Duration
	restartGrace time.Duration

	mu      sync.Mutex
	running bool
}

// New wires a manager; report sends the update_result (buffered, so it also
// reaches the gateway after a reconnect). packageBase is the Windows download
// base (empty on Linux).
func New(b brand.Brand, version, packageBase string, report func(*protocol.UpdateResult), log *slog.Logger) *Manager {
	return &Manager{
		b:           b,
		version:     version,
		packageBase: packageBase,
		report:      report,
		log:         log,
		runCmd: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			// The name is "systemd-run" (Linux) or "msiexec" (Windows); the
			// arguments contain only the strictly validated version and
			// brand-derived paths.
			return exec.CommandContext(ctx, name, args...).CombinedOutput() //nolint:gosec // G204: fixed arguments, see above
		},
		httpGet:      httpGet,
		now:          time.Now,
		runTimeout:   runTimeout,
		restartGrace: restartGrace,
	}
}

// Handle reacts to an `update` message. It returns quickly; the apt run
// happens in the background.
func (m *Manager) Handle(ctx context.Context, version string) {
	switch {
	case m.version == "dev":
		m.fail(version, "this is a dev build without a package; self-update is disabled")
		return
	case version == m.version:
		// Already there — make the gateway's book-keeping converge.
		m.report(&protocol.UpdateResult{Version: version, OK: true})
		return
	}
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		m.log.Info("update already running, ignoring", "version", version)
		return
	}
	m.running = true
	m.mu.Unlock()

	if err := m.writePending(pending{Version: version, StartedAt: m.now()}); err != nil {
		m.setIdle()
		m.fail(version, "recording the update: "+err.Error())
		return
	}
	m.log.Info("starting update", "from", m.version, "to", version)
	go m.run(ctx, version)
}

// waitForRestart is the shared tail of every successful install: the package
// manager (dpkg on Linux, Windows Installer on Windows) restarts the service
// mid-upgrade, so this process should die here. If it does not within the
// grace period, the install did not actually replace us — say so.
func (m *Manager) waitForRestart(ctx context.Context, version string) {
	select {
	case <-ctx.Done():
	case <-time.After(m.restartGrace):
		m.clearPending()
		m.fail(version, "package installed but the agent was not restarted; still running "+m.version)
	}
}

// ReportPending settles a pending file left by a previous process: after a
// successful update the new agent reports it, after a failed one whichever
// agent is running when the timeout passes.
func (m *Manager) ReportPending(ctx context.Context) {
	p, ok := m.readPending()
	if !ok {
		return
	}
	if p.Version == m.version {
		m.clearPending()
		m.log.Info("update finished", "version", m.version)
		m.report(&protocol.UpdateResult{Version: p.Version, OK: true})
		return
	}
	wait := p.StartedAt.Add(m.runTimeout).Sub(m.now())
	if wait <= 0 {
		m.clearPending()
		m.fail(p.Version, "agent still runs "+m.version+" after the update")
		return
	}
	// The update may still be running (this process was restarted for some
	// other reason). If it succeeds we die and the next start reports it;
	// otherwise the deadline turns it into a failure.
	m.log.Info("update still pending", "version", p.Version, "deadline_in", wait)
	go func() {
		select {
		case <-ctx.Done():
		case <-time.After(wait):
			if q, ok := m.readPending(); ok && q.Version == p.Version {
				m.clearPending()
				m.fail(p.Version, "agent still runs "+m.version+" after the update")
			}
		}
	}()
}

func (m *Manager) fail(version, msg string) {
	m.log.Error("update failed", "version", version, "err", msg)
	m.report(&protocol.UpdateResult{Version: version, OK: false, Error: msg})
}

func (m *Manager) setIdle() {
	m.mu.Lock()
	m.running = false
	m.mu.Unlock()
}

func (m *Manager) pendingPath() string { return filepath.Join(m.b.StateDir(), pendingFile) }

func (m *Manager) writePending(p pending) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return os.WriteFile(m.pendingPath(), b, 0o600)
}

// readPending treats an unreadable file as none at all (and removes it).
func (m *Manager) readPending() (pending, bool) {
	var p pending
	b, err := os.ReadFile(m.pendingPath())
	if err != nil {
		return p, false
	}
	if err := json.Unmarshal(b, &p); err != nil || p.Version == "" {
		m.log.Warn("discarding unreadable pending update file", "err", err)
		m.clearPending()
		return p, false
	}
	return p, true
}

func (m *Manager) clearPending() {
	if err := os.Remove(m.pendingPath()); err != nil && !os.IsNotExist(err) {
		m.log.Warn("removing pending update file", "err", err)
	}
}

// oneLine squeezes command output into a valid update_result error: control
// characters become spaces, and only the tail fits (that is where apt's
// actual error lives).
func oneLine(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, strings.TrimSpace(s))
	const maxLen = protocol.MaxSummary
	if runes := []rune(s); len(runes) > maxLen {
		s = "…" + string(runes[len(runes)-maxLen+1:])
	}
	return s
}
