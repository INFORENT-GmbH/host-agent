// Package agent is the main loop: it schedules collectors and checks, sends
// their results through the transport and applies what the gateway may
// change — intervals, disabled collectors, live mode. Nothing else.
package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"slices"
	"time"

	"github.com/INFORENT-GmbH/host-agent/internal/brand"
	"github.com/INFORENT-GmbH/host-agent/internal/buffer"
	"github.com/INFORENT-GmbH/host-agent/internal/buildinfo"
	"github.com/INFORENT-GmbH/host-agent/internal/checks"
	"github.com/INFORENT-GmbH/host-agent/internal/collect"
	"github.com/INFORENT-GmbH/host-agent/internal/config"
	"github.com/INFORENT-GmbH/host-agent/internal/hostinfo"
	"github.com/INFORENT-GmbH/host-agent/internal/localchecks"
	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
	"github.com/INFORENT-GmbH/host-agent/internal/transport"
	"github.com/INFORENT-GmbH/host-agent/internal/update"
)

// Buffer limits: enough for several hours of outage at normal rates.
const (
	bufferMaxBytes = 50 << 20
	bufferMaxAge   = 6 * time.Hour
)

// DefaultIntervals apply until the gateway sends a config.
var DefaultIntervals = protocol.Intervals{MetricsS: 10, ChecksS: 60, DiscoveryS: 7200, InventoryS: 3600}

// Test seams: the real TLS client and the full check set (whose apt
// simulation takes seconds).
var (
	httpClient *http.Client
	newChecks  = checks.Default
)

type gatewayMsg struct {
	t   protocol.Type
	msg protocol.Message
}

// Run connects and works until ctx ends.
func Run(ctx context.Context, b brand.Brand, cfg config.Config, log *slog.Logger) error {
	if err := prepareStateDir(b); err != nil {
		return err
	}
	buf, err := buffer.Open(filepath.Join(b.StateDir(), "buffer"), bufferMaxBytes, bufferMaxAge)
	if err != nil {
		return fmt.Errorf("send buffer: %w", err)
	}
	defer func() { _ = buf.Close() }()

	info, err := hostinfo.Gather(b.Root)
	if err != nil {
		return err
	}

	msgs := make(chan gatewayMsg, 16)
	client, err := transport.New(transport.Options{
		BaseURL:    cfg.Server.URL,
		Token:      cfg.Server.Token,
		UserAgent:  b.Name() + "/" + buildinfo.Version,
		Buffer:     buf,
		Logger:     log,
		HTTPClient: httpClient,
		Hello: func() (*protocol.Hello, error) {
			return &protocol.Hello{
				Protocol:     protocol.Version,
				AgentVersion: buildinfo.Version,
				Brand:        b.Key,
				Hostname:     info.Hostname,
				MachineID:    info.MachineID,
				OS:           info.OS,
				Local:        protocol.LocalOptIns{Satellite: cfg.Local.Satellite, LocalChecks: cfg.Local.LocalChecks},
				Time:         time.Now().UnixMilli(),
				SeqEpoch:     buf.Epoch(),
			}, nil
		},
		OnMessage: func(t protocol.Type, m protocol.Message) {
			select {
			case msgs <- gatewayMsg{t, m}:
			default:
				log.Warn("dropping gateway message, main loop busy", "type", t)
			}
		},
	})
	if err != nil {
		return err
	}
	// The client must be gone before the deferred buffer close.
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		client.Run(ctx)
	}()
	defer func() { <-clientDone }()

	upd := update.New(b, buildinfo.Version, cfg.Server.PackageBase, func(r *protocol.UpdateResult) {
		if err := client.Send(protocol.TypeUpdateResult, r, true); err != nil {
			log.Error("send", "type", protocol.TypeUpdateResult, "err", err)
		}
	}, log)
	upd.ReportPending(ctx)

	cs := newChecks()
	if cfg.Local.LocalChecks {
		cs = append(cs, localchecks.New(b))
	}
	// Polling other devices is a local opt-in: the portal may assign sources,
	// but only `satellite = true` in this machine's agent.conf lets them run.
	var sat *satellite
	if cfg.Local.Satellite {
		sat = newSatellite(log, client.Send)
		defer sat.stop()
	}
	l := &loop{
		log:        log,
		send:       client.Send,
		satellite:  sat,
		collectors: collect.Default(),
		live:       collect.Default(), // own rate state: live ticks must not shorten the 10 s windows
		checks:     cs,
		intervals:  DefaultIntervals,
		onUpdate:   func(v string) { upd.Handle(ctx, v) },
	}
	return l.run(ctx, msgs)
}

type loop struct {
	log        *slog.Logger
	send       func(protocol.Type, protocol.Message, bool) error
	collectors []collect.Collector
	live       []collect.Collector
	checks     []checks.Check
	satellite  *satellite
	onUpdate   func(version string)

	intervals     protocol.Intervals
	disabled      []string
	configVersion int64

	liveUntil    time.Time
	liveInterval time.Duration

	discoveryHash string
	discoveryAt   time.Time
}

func (l *loop) run(ctx context.Context, msgs <-chan gatewayMsg) error {
	metricsT := time.NewTicker(seconds(l.intervals.MetricsS))
	checksT := time.NewTicker(seconds(l.intervals.ChecksS))
	defer metricsT.Stop()
	defer checksT.Stop()
	var liveT *time.Ticker
	liveC := func() <-chan time.Time {
		if liveT == nil {
			return nil
		}
		return liveT.C
	}
	stopLive := func() {
		if liveT != nil {
			liveT.Stop()
			liveT = nil
		}
	}
	defer stopLive()

	// Prime rate counters, then report checks and discovery right away so a
	// freshly started agent shows up without waiting a full interval.
	l.metrics(ctx, time.Now())
	l.checksAndDiscovery(ctx, time.Now())

	for {
		select {
		case <-ctx.Done():
			return nil
		case now := <-metricsT.C:
			l.metrics(ctx, now)
		case now := <-checksT.C:
			l.checksAndDiscovery(ctx, now)
		case now := <-liveC():
			if now.After(l.liveUntil) {
				stopLive()
				continue
			}
			l.liveMetrics(ctx, now)
		case m := <-msgs:
			switch msg := m.msg.(type) {
			case *protocol.Welcome:
				l.log.Info("gateway welcome", "host", msg.HostID)
			case *protocol.AgentConfig:
				if l.applyConfig(msg) {
					metricsT.Reset(seconds(l.intervals.MetricsS))
					checksT.Reset(seconds(l.intervals.ChecksS))
				}
				l.applySources(ctx, msg.Sources)
			case *protocol.Live:
				switch every := l.applyLive(msg, time.Now()); {
				case every == 0:
					stopLive()
				case liveT == nil:
					liveT = time.NewTicker(every)
				default:
					liveT.Reset(every)
				}
			case *protocol.Update:
				l.onUpdate(msg.Version)
			}
		}
	}
}

func (l *loop) metrics(ctx context.Context, now time.Time) {
	samples, err := collect.Run(ctx, l.collectors, l.disabled, now)
	if err != nil {
		l.log.Warn("collectors", "err", err)
	}
	if len(samples) > 0 {
		l.sendOrLog(protocol.TypeMetrics, &protocol.Metrics{Time: now.UnixMilli(), Series: samples}, true)
	}
}

func (l *loop) liveMetrics(ctx context.Context, now time.Time) {
	samples, _ := collect.Run(ctx, l.live, l.disabled, now)
	if len(samples) > 0 {
		l.sendOrLog(protocol.TypeMetrics, &protocol.Metrics{Time: now.UnixMilli(), Live: true, Series: samples}, false)
	}
}

func (l *loop) checksAndDiscovery(ctx context.Context, now time.Time) {
	results, err := checks.Run(ctx, l.checks, now)
	if err != nil {
		l.log.Warn("checks", "err", err)
	}
	if len(results) > 0 {
		l.sendOrLog(protocol.TypeChecks, &protocol.Checks{Time: now.UnixMilli(), Results: results}, true)
	}
	items, err := checks.Discover(ctx, l.checks)
	if err != nil {
		l.log.Warn("discovery", "err", err)
	}
	if hash := discoveryHash(items); hash != l.discoveryHash || now.Sub(l.discoveryAt) >= seconds(l.intervals.DiscoveryS) {
		l.sendOrLog(protocol.TypeDiscovery, &protocol.Discovery{Time: now.UnixMilli(), Items: items}, true)
		l.discoveryHash, l.discoveryAt = hash, now
	}
}

// applyConfig takes a newer config; it reports whether intervals changed.
func (l *loop) applyConfig(c *protocol.AgentConfig) bool {
	if c.Version <= l.configVersion {
		return false
	}
	l.configVersion = c.Version
	l.disabled = slices.Clone(c.DisabledCollectors)
	changed := c.Intervals != l.intervals
	l.intervals = c.Intervals
	l.log.Info("config applied", "version", c.Version, "intervals", c.Intervals, "disabled", c.DisabledCollectors)
	return changed
}

// applySources hands the assignment to the satellite. A host that is not one
// says so loudly instead of silently dropping the devices: the gateway should
// never have sent them, and somebody is waiting for data that will not come.
func (l *loop) applySources(ctx context.Context, sources []protocol.SourceConfig) {
	if l.satellite == nil {
		if len(sources) > 0 {
			l.log.Warn("gateway assigned sources, but satellite mode is off in agent.conf", "sources", len(sources))
		}
		return
	}
	l.satellite.apply(ctx, sources)
	l.log.Info("sources applied", "count", l.satellite.count())
}

// applyLive returns the live tick interval, or 0 to stop live mode.
func (l *loop) applyLive(m *protocol.Live, now time.Time) time.Duration {
	if !m.On {
		l.liveUntil = time.Time{}
		return 0
	}
	l.liveUntil = now.Add(seconds(m.TTLS))
	l.liveInterval = time.Duration(m.IntervalMs) * time.Millisecond
	return l.liveInterval
}

func (l *loop) sendOrLog(t protocol.Type, m protocol.Message, persist bool) {
	if err := l.send(t, m, persist); err != nil {
		l.log.Error("send", "type", t, "err", err)
	}
}

func discoveryHash(items []protocol.DiscoveredItem) string {
	h := sha256.New()
	for _, it := range items {
		_, _ = fmt.Fprintf(h, "%s\x00%s\x00%s\n", it.Plugin, it.Item, it.Description)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func seconds(n int) time.Duration { return time.Duration(n) * time.Second }
