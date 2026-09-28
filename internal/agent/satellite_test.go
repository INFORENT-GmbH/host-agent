package agent

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/INFORENT-GmbH/host-agent/internal/poll/snmp"
	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

// fakeSession answers the system group and nothing else — enough for a poll
// to succeed without a socket.
type fakeSession struct {
	mu     sync.Mutex
	closed bool
	name   string
}

func (f *fakeSession) Get(_ context.Context, oids []string) ([]gosnmp.SnmpPDU, error) {
	out := make([]gosnmp.SnmpPDU, 0, len(oids))
	for _, oid := range oids {
		switch strings.TrimPrefix(oid, ".") {
		case "1.3.6.1.2.1.1.1.0":
			out = append(out, gosnmp.SnmpPDU{Name: "." + oid, Type: gosnmp.OctetString, Value: []byte("Cisco IOS")})
		case "1.3.6.1.2.1.1.2.0":
			out = append(out, gosnmp.SnmpPDU{Name: "." + oid, Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.4.1.9.1.2494"})
		case "1.3.6.1.2.1.1.3.0":
			out = append(out, gosnmp.SnmpPDU{Name: "." + oid, Type: gosnmp.TimeTicks, Value: uint32(360000)})
		case "1.3.6.1.2.1.1.5.0":
			out = append(out, gosnmp.SnmpPDU{Name: "." + oid, Type: gosnmp.OctetString, Value: []byte(f.name)})
		default:
			out = append(out, gosnmp.SnmpPDU{Name: "." + oid, Type: gosnmp.NoSuchInstance})
		}
	}
	return out, nil
}

func (f *fakeSession) Walk(context.Context, string) ([]gosnmp.SnmpPDU, error) { return nil, nil }

func (f *fakeSession) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

type sentFrame struct {
	t   protocol.Type
	msg protocol.Message
}

type recorder struct {
	mu     sync.Mutex
	frames []sentFrame
}

func (r *recorder) send(t protocol.Type, m protocol.Message, _ bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.frames = append(r.frames, sentFrame{t, m})
	return nil
}

func (r *recorder) byType(t protocol.Type) []protocol.Message {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []protocol.Message
	for _, f := range r.frames {
		if f.t == t {
			out = append(out, f.msg)
		}
	}
	return out
}

const (
	sourceID  = "9f2c1a4b7d8e0f3a5b6c7d8e"
	targetPID = "1a2b3c4d5e6f708192a3b4c5"
)

func source(address string) protocol.SourceConfig {
	return protocol.SourceConfig{
		ID: sourceID, Target: targetPID, Kind: "snmp", Address: address, Port: 161,
		IntervalS: 3600, TimeoutMS: 500, Retries: 0,
		SNMPVersion: "2c", SNMPCommunity: "public",
	}
}

// waitForSource polls a condition; the runners work in their own goroutines.
func waitForSource(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// withFakeDial replaces the dialer and returns a race-free count of the
// sessions it opened — the runners append from their own goroutines.
func withFakeDial(t *testing.T, sessions *[]*fakeSession) (opened func() int) {
	t.Helper()
	var mu sync.Mutex
	prev := dialSource
	dialSource = func(cfg snmp.Config) (snmp.Session, error) {
		if cfg.Address == "unreachable" {
			return nil, errors.New("connect unreachable:161: no route to host")
		}
		s := &fakeSession{name: "sw-" + cfg.Address}
		mu.Lock()
		*sessions = append(*sessions, s)
		mu.Unlock()
		return s, nil
	}
	t.Cleanup(func() { dialSource = prev })
	return func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(*sessions)
	}
}

func TestSatelliteReportsUnderTheTargetHost(t *testing.T) {
	var sessions []*fakeSession
	withFakeDial(t, &sessions)
	rec := &recorder{}
	sat := newSatellite(slog.New(slog.DiscardHandler), rec.send)
	defer sat.stop()

	sat.apply(context.Background(), []protocol.SourceConfig{source("10.0.0.5")})
	waitForSource(t, "first poll", func() bool { return len(rec.byType(protocol.TypeChecks)) > 0 })

	checks := rec.byType(protocol.TypeChecks)[0].(*protocol.Checks)
	if checks.Target != targetPID {
		t.Errorf("checks target = %q, want the polled host", checks.Target)
	}
	// Everything the poller produced must carry the target, or the gateway
	// would file a switch's data under the satellite itself.
	for _, m := range rec.byType(protocol.TypeDiscovery) {
		if m.(*protocol.Discovery).Target != targetPID {
			t.Error("discovery without target")
		}
	}
	waitForSource(t, "status frame", func() bool { return len(rec.byType(protocol.TypeSourceStatus)) > 0 })
	st := rec.byType(protocol.TypeSourceStatus)[0].(*protocol.SourceStatus)
	if !st.OK || st.Source != sourceID || st.Vendor != "cisco" {
		t.Errorf("status = %+v", st)
	}
	if err := st.Validate(); err != nil {
		t.Errorf("status frame does not satisfy the protocol: %v", err)
	}
}

func TestSatelliteKeepsUnchangedSourcesRunning(t *testing.T) {
	var sessions []*fakeSession
	opened := withFakeDial(t, &sessions)
	rec := &recorder{}
	sat := newSatellite(slog.New(slog.DiscardHandler), rec.send)
	defer sat.stop()
	ctx := context.Background()

	sat.apply(ctx, []protocol.SourceConfig{source("10.0.0.5")})
	waitForSource(t, "first session", func() bool { return opened() == 1 })

	// Same config again: the poller must survive, because restarting it would
	// throw away the counter history and cost an interval of rates.
	sat.apply(ctx, []protocol.SourceConfig{source("10.0.0.5")})
	if sat.count() != 1 {
		t.Fatalf("running sources = %d", sat.count())
	}
	time.Sleep(50 * time.Millisecond)
	if n := opened(); n != 1 {
		t.Errorf("unchanged source was restarted (%d sessions)", n)
	}

	// A changed address must take effect at once.
	sat.apply(ctx, []protocol.SourceConfig{source("10.0.0.6")})
	waitForSource(t, "restart after change", func() bool { return opened() == 2 })

	// Removing it stops the poller.
	sat.apply(ctx, nil)
	if sat.count() != 0 {
		t.Errorf("source still running after it was unassigned")
	}
}

func TestSatelliteReportsUnreachableDevice(t *testing.T) {
	var sessions []*fakeSession
	withFakeDial(t, &sessions)
	rec := &recorder{}
	sat := newSatellite(slog.New(slog.DiscardHandler), rec.send)
	defer sat.stop()

	sat.apply(context.Background(), []protocol.SourceConfig{source("unreachable")})
	waitForSource(t, "failure report", func() bool { return len(rec.byType(protocol.TypeSourceStatus)) > 0 })

	st := rec.byType(protocol.TypeSourceStatus)[0].(*protocol.SourceStatus)
	if st.OK || st.Error == "" {
		t.Errorf("a device that cannot be dialled must be reported as failed, got %+v", st)
	}
	if len(rec.byType(protocol.TypeChecks)) != 0 {
		t.Error("a failed poll must not produce check results")
	}
}

func TestSatelliteIgnoresUnknownKind(t *testing.T) {
	var sessions []*fakeSession
	withFakeDial(t, &sessions)
	rec := &recorder{}
	sat := newSatellite(slog.New(slog.DiscardHandler), rec.send)
	defer sat.stop()

	ipmi := source("10.0.0.7")
	ipmi.Kind = "ipmi"
	sat.apply(context.Background(), []protocol.SourceConfig{ipmi, source("10.0.0.5")})
	if sat.count() != 1 {
		t.Errorf("running sources = %d, want only the SNMP one", sat.count())
	}
}
