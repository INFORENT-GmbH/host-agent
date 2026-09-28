package agent

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/INFORENT-GmbH/host-agent/internal/poll/snmp"
	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

// The satellite part of the agent: besides its own host it polls other
// devices on the portal's behalf and reports their results under THEIR host id
// (`target`). It only ever runs when the machine's own `agent.conf` says
// `satellite = true` — the portal cannot switch this on remotely.
//
// One goroutine per device, each on its own interval: 200 switches at 60 s
// must not queue up behind one slow device, and a device that times out may
// not hold back the others.

// dialSource is a test seam: the tests replace it with a session that replays
// canned varbinds instead of opening a UDP socket.
var dialSource = snmp.Dial

type satellite struct {
	log  *slog.Logger
	send func(protocol.Type, protocol.Message, bool) error

	mu      sync.Mutex
	runners map[string]*sourceRunner
}

func newSatellite(log *slog.Logger, send func(protocol.Type, protocol.Message, bool) error) *satellite {
	return &satellite{log: log, send: send, runners: map[string]*sourceRunner{}}
}

// apply reconciles the running pollers with the assignment from the gateway:
// new sources start, changed ones restart (a new address or credential must
// take effect at once), removed ones stop. An unchanged source keeps running —
// restarting it would throw away its counter history and cost one interval of
// rates for nothing.
func (s *satellite) apply(ctx context.Context, sources []protocol.SourceConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()

	wanted := make(map[string]protocol.SourceConfig, len(sources))
	for _, src := range sources {
		wanted[src.ID] = src
	}
	for id, r := range s.runners {
		next, keep := wanted[id]
		if keep && r.fingerprint == fingerprint(next) {
			continue
		}
		r.stop()
		delete(s.runners, id)
	}
	for id, src := range wanted {
		if _, running := s.runners[id]; running {
			continue
		}
		if src.Kind != "snmp" {
			// Forward compatibility: a future gateway may assign IPMI or
			// Redfish sources. Ignore them instead of failing the whole
			// assignment — the SNMP ones must keep working.
			s.log.Warn("ignoring source of unknown kind", "kind", src.Kind, "source", src.ID)
			continue
		}
		r := &sourceRunner{cfg: src, fingerprint: fingerprint(src), log: s.log, send: s.send}
		r.start(ctx)
		s.runners[id] = r
	}
}

// stop ends every poller; used when the agent shuts down.
func (s *satellite) stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, r := range s.runners {
		r.stop()
		delete(s.runners, id)
	}
}

func (s *satellite) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.runners)
}

// fingerprint covers every field that changes how a device is polled, so an
// edit in the portal restarts exactly the affected poller.
func fingerprint(c protocol.SourceConfig) string {
	return fmt.Sprintf("%+v", c)
}

type sourceRunner struct {
	cfg         protocol.SourceConfig
	fingerprint string
	log         *slog.Logger
	send        func(protocol.Type, protocol.Message, bool) error

	cancel context.CancelFunc
	done   chan struct{}

	poller        *snmp.Poller
	session       snmp.Session
	discoveryHash string
	discoveryAt   time.Time
	// What the last status frame said — resending the same thing every
	// interval would be noise.
	lastStatus string
}

func (r *sourceRunner) start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	r.done = make(chan struct{})
	r.poller = snmp.NewPoller()
	go r.run(ctx)
}

func (r *sourceRunner) stop() {
	if r.cancel != nil {
		r.cancel()
		<-r.done
	}
	r.closeSession()
}

func (r *sourceRunner) closeSession() {
	if r.session != nil {
		_ = r.session.Close()
		r.session = nil
	}
}

func (r *sourceRunner) run(ctx context.Context) {
	defer close(r.done)
	t := time.NewTicker(time.Duration(r.cfg.IntervalS) * time.Second)
	defer t.Stop()
	// Prime the counters right away; the first poll reports states, the
	// second one rates.
	r.poll(ctx, time.Now())
	for {
		select {
		case <-ctx.Done():
			r.closeSession()
			return
		case now := <-t.C:
			r.poll(ctx, now)
		}
	}
}

func (r *sourceRunner) poll(ctx context.Context, now time.Time) {
	// The whole poll is bounded: timeout × (retries + 1) per request, and a
	// generous multiple of that for the walks, so a device that answers the
	// first packet and then goes quiet cannot pin this goroutine.
	budget := time.Duration(r.cfg.TimeoutMS) * time.Millisecond * time.Duration(r.cfg.Retries+1) * 8
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	if r.session == nil {
		s, err := dialSource(sessionConfig(r.cfg))
		if err != nil {
			r.report(now, false, err.Error(), snmp.Identity{})
			return
		}
		r.session = s
	}

	res, err := r.poller.Poll(ctx, r.session, now)
	if err != nil {
		// Drop the socket: a v3 session whose engine time drifted apart only
		// recovers with a fresh handshake.
		r.closeSession()
		r.report(now, false, err.Error(), snmp.Identity{})
		return
	}

	if len(res.Checks) > 0 {
		r.sendMsg(protocol.TypeChecks, &protocol.Checks{Time: now.UnixMilli(), Target: r.cfg.Target, Results: res.Checks})
	}
	if len(res.Metrics) > 0 {
		r.sendMsg(protocol.TypeMetrics, &protocol.Metrics{Time: now.UnixMilli(), Target: r.cfg.Target, Series: res.Metrics})
	}
	if hash := discoveryHash(res.Discovery); hash != r.discoveryHash || now.Sub(r.discoveryAt) >= 2*time.Hour {
		r.sendMsg(protocol.TypeDiscovery, &protocol.Discovery{Time: now.UnixMilli(), Target: r.cfg.Target, Items: res.Discovery})
		r.discoveryHash, r.discoveryAt = hash, now
	}
	r.report(now, true, "", res.Identity)
}

// report sends the source status, but only when it says something new: every
// failure, the first success, a recovery, and a device whose identity changed
// (a replaced switch keeps the IP but not the sysObjectID). A healthy device
// would otherwise write one "still fine" per interval into the gateway's path.
func (r *sourceRunner) report(now time.Time, ok bool, errText string, id snmp.Identity) {
	state := statusOf(ok, errText, id)
	if state == r.lastStatus {
		return
	}
	if !ok {
		r.log.Warn("poll failed", "source", r.cfg.ID, "address", r.cfg.Address, "err", errText)
	}
	r.lastStatus = state
	r.sendMsg(protocol.TypeSourceStatus, &protocol.SourceStatus{
		Time:        now.UnixMilli(),
		Source:      r.cfg.ID,
		Target:      r.cfg.Target,
		OK:          ok,
		Error:       truncate(errText, protocol.MaxSummary),
		SysName:     truncate(id.Name, protocol.MaxShortText),
		SysObjectID: truncate(id.ObjectID, protocol.MaxShortText),
		Vendor:      truncate(id.Vendor, 32),
	})
}

func statusOf(ok bool, errText string, id snmp.Identity) string {
	if !ok {
		return "err\x00" + errText
	}
	return "ok\x00" + id.Name + "\x00" + id.ObjectID + "\x00" + id.Vendor
}

func (r *sourceRunner) sendMsg(t protocol.Type, m protocol.Message) {
	// Persisted like the host's own frames: a gateway outage must not lose a
	// device's history.
	if err := r.send(t, m, true); err != nil {
		r.log.Error("send", "type", t, "source", r.cfg.ID, "err", err)
	}
}

func sessionConfig(c protocol.SourceConfig) snmp.Config {
	return snmp.Config{
		Address:   c.Address,
		Port:      uint16(c.Port), // #nosec G115 -- validated 1..65535 by the protocol
		Version:   snmp.Version(c.SNMPVersion),
		Community: c.SNMPCommunity,
		User:      c.SNMPUser,
		AuthProto: c.SNMPAuthProto,
		AuthKey:   c.SNMPAuthKey,
		PrivProto: c.SNMPPrivProto,
		PrivKey:   c.SNMPPrivKey,
		Context:   c.SNMPContext,
		Timeout:   time.Duration(c.TimeoutMS) * time.Millisecond,
		Retries:   c.Retries,
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
