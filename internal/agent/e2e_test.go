package agent

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/INFORENT-GmbH/host-agent/internal/brand"
	"github.com/INFORENT-GmbH/host-agent/internal/checks"
	"github.com/INFORENT-GmbH/host-agent/internal/config"
	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

const e2eToken = "host-token-0123456789abcdef0123456789"

type frame struct {
	t   protocol.Type
	seq uint64
	msg protocol.Message
}

// fakeGateway speaks the gateway side of protocol v1 over real TLS.
type fakeGateway struct {
	t      *testing.T
	mu     sync.Mutex
	ack    bool
	extra  []func() ([]byte, error) // sent right after welcome
	hellos []*protocol.Hello
	frames []frame
}

func (g *fakeGateway) handler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/v1/ws" || r.Header.Get("Authorization") != "Bearer "+e2eToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer func() { _ = conn.CloseNow() }()
	ctx := r.Context()
	_, data, err := conn.Read(ctx)
	if err != nil {
		return
	}
	env, msg, err := protocol.DecodeFromAgent(data)
	if err != nil || env.Type != protocol.TypeHello {
		g.t.Errorf("first frame is not a valid hello: %v", err)
		return
	}
	g.mu.Lock()
	g.hellos = append(g.hellos, msg.(*protocol.Hello))
	ack, extra := g.ack, g.extra
	g.mu.Unlock()

	out := []func() ([]byte, error){func() ([]byte, error) {
		return protocol.Encode(protocol.TypeWelcome, 0, &protocol.Welcome{Protocol: protocol.Version, HostID: "host-42", ServerTime: time.Now().UnixMilli()})
	}}
	for _, f := range append(out, extra...) {
		b, err := f()
		if err != nil {
			g.t.Error(err)
			return
		}
		if err := conn.Write(ctx, websocket.MessageText, b); err != nil {
			return
		}
	}
	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			return
		}
		env, msg, err := protocol.DecodeFromAgent(data)
		if err != nil {
			g.t.Errorf("invalid frame: %v", err)
			return
		}
		g.mu.Lock()
		g.frames = append(g.frames, frame{env.Type, env.Seq, msg})
		g.mu.Unlock()
		if ack {
			b, _ := protocol.Encode(protocol.TypeAck, 0, &protocol.Ack{Seq: env.Seq})
			_ = conn.Write(ctx, websocket.MessageText, b)
		}
	}
}

func (g *fakeGateway) snapshot() ([]*protocol.Hello, []frame) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Clone(g.hellos), slices.Clone(g.frames)
}

// e2eSetup starts a TLS gateway and returns an enrolled brand rooted in a
// temp dir. The check set is a fast fake; collectors are the real ones.
func e2eSetup(t *testing.T) (*fakeGateway, brand.Brand, config.Config) {
	t.Helper()
	g := &fakeGateway{t: t}
	srv := httptest.NewTLSServer(http.HandlerFunc(g.handler))
	t.Cleanup(srv.Close)

	origClient, origChecks := httpClient, newChecks
	httpClient = srv.Client()
	newChecks = func() []checks.Check { return []checks.Check{&fakeCheck{item: "a"}} }
	t.Cleanup(func() { httpClient, newChecks = origClient, origChecks })

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "machine-id"), []byte("00112233445566778899aabbccddeeff\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := brand.New("acme", root)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Server = config.Server{URL: srv.URL, Token: e2eToken}
	cfg.Local.LocalChecks = false
	return g, b, cfg
}

// startAgent runs the agent; the returned stop cancels it and waits.
func startAgent(t *testing.T, b brand.Brand, cfg config.Config) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, b, cfg, slog.New(slog.DiscardHandler)) }()
	return func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run: %v", err)
			}
		case <-time.After(20 * time.Second):
			t.Fatal("Run did not stop")
		}
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func hasTypes(fs []frame, types ...protocol.Type) bool {
	for _, want := range types {
		if !slices.ContainsFunc(fs, func(f frame) bool { return f.t == want }) {
			return false
		}
	}
	return true
}

func seqs(fs []frame) []uint64 {
	out := make([]uint64, len(fs))
	for i, f := range fs {
		out[i] = f.seq
	}
	return out
}

func TestEndToEndSession(t *testing.T) {
	g, b, cfg := e2eSetup(t)
	g.ack = true
	g.extra = []func() ([]byte, error){
		func() ([]byte, error) {
			return protocol.Encode(protocol.TypeConfig, 0, &protocol.AgentConfig{
				Version:   1,
				Intervals: protocol.Intervals{MetricsS: 5, ChecksS: 10, DiscoveryS: 300, InventoryS: 300},
			})
		},
		func() ([]byte, error) {
			return protocol.Encode(protocol.TypeUpdate, 0, &protocol.Update{Version: "1.2.3"})
		},
	}
	stop := startAgent(t, b, cfg)
	waitFor(t, "metrics, checks, discovery and update_result", func() bool {
		_, fs := g.snapshot()
		return hasTypes(fs, protocol.TypeMetrics, protocol.TypeChecks, protocol.TypeDiscovery, protocol.TypeUpdateResult)
	})
	stop()

	hellos, fs := g.snapshot()
	if len(hellos) != 1 {
		t.Fatalf("%d hellos", len(hellos))
	}
	h := hellos[0]
	if h.Brand != "acme" || h.MachineID != "00112233445566778899aabbccddeeff" || h.SeqEpoch == "" || h.Local.LocalChecks {
		t.Errorf("hello %+v", h)
	}
	if s := seqs(fs); !slices.IsSorted(s) || slices.Contains(s, 0) || len(slices.Compact(slices.Clone(s))) != len(s) {
		t.Errorf("seqs not strictly increasing from 1: %v", s)
	}
	for _, f := range fs {
		if r, ok := f.msg.(*protocol.UpdateResult); ok && (r.OK || r.Version != "1.2.3") {
			t.Errorf("update_result %+v", r)
		}
	}
}

// Unacked frames survive a restart and are resent with the same seq epoch;
// acked ones are not sent again.
func TestEndToEndResendAfterRestart(t *testing.T) {
	g, b, cfg := e2eSetup(t)

	stop := startAgent(t, b, cfg)
	waitFor(t, "first frames", func() bool {
		_, fs := g.snapshot()
		return hasTypes(fs, protocol.TypeChecks, protocol.TypeDiscovery)
	})
	stop()
	hellos, first := g.snapshot()
	firstSeqs := seqs(first)

	g.mu.Lock()
	g.ack = true
	g.mu.Unlock()
	stop = startAgent(t, b, cfg)
	waitFor(t, "resend", func() bool {
		_, fs := g.snapshot()
		return len(fs) >= 2*len(first)+1
	})
	// Wait until the buffer has persisted the acks for everything sent so far,
	// instead of a fixed sleep — on a loaded CI runner 200 ms was not enough.
	_, sent := g.snapshot()
	sentUpTo := slices.Max(seqs(sent))
	waitFor(t, "acks persisted", func() bool { return ackedSeq(t, b) >= sentUpTo })
	stop()
	ackedAtStop := ackedSeq(t, b)
	hellos2, all := g.snapshot()
	second := all[len(first):]
	if hellos2[1].SeqEpoch != hellos[0].SeqEpoch {
		t.Errorf("seq epoch changed across restart: %s → %s", hellos[0].SeqEpoch, hellos2[1].SeqEpoch)
	}
	if got := seqs(second[:len(first)]); !slices.Equal(got, firstSeqs) {
		t.Errorf("resent %v, want %v", got, firstSeqs)
	}
	secondSeqs := seqs(second)
	if !slices.IsSorted(secondSeqs) {
		t.Errorf("second session seqs not ordered: %v", secondSeqs)
	}

	stop = startAgent(t, b, cfg)
	waitFor(t, "third session", func() bool {
		_, fs := g.snapshot()
		return len(fs) > len(all)
	})
	stop()
	_, all3 := g.snapshot()
	// Frames sent after the last persisted ack may legitimately be resent;
	// nothing at or below the acked seq may.
	if next := all3[len(all)].seq; next <= ackedAtStop {
		t.Errorf("acked frames resent: third session starts at seq %d, acked up to %d", next, ackedAtStop)
	}
}

// ackedSeq reads the buffer's persisted ack mark (buffer.Ack → file "acked"); 0 if none yet.
func ackedSeq(t *testing.T, b brand.Brand) uint64 {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(b.StateDir(), "buffer", "acked"))
	if err != nil {
		return 0
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return 0
	}
	return n
}
