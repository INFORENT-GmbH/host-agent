package transport

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/INFORENT-GmbH/host-agent/internal/buffer"
	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

const token = "host-token-0123456789abcdef0123456789"

func hello() (*protocol.Hello, error) {
	return &protocol.Hello{
		Protocol: 1, AgentVersion: "dev", Brand: "acme", Hostname: "h1",
		MachineID: "00112233445566778899aabbccddeeff", SeqEpoch: "0011223344556677",
		OS:   protocol.OSInfo{Name: "Debian", Arch: "amd64"},
		Time: time.Now().UnixMilli(),
	}, nil
}

func welcome() []byte {
	b, _ := protocol.Encode(protocol.TypeWelcome, 0, &protocol.Welcome{Protocol: 1, HostID: "h", ServerTime: 1})
	return b
}

func ack(seq uint64) []byte {
	b, _ := protocol.Encode(protocol.TypeAck, 0, &protocol.Ack{Seq: seq})
	return b
}

// gateway is a minimal fake of the real one.
type gateway struct {
	t         *testing.T
	mu        sync.Mutex
	received  []uint64 // seqs of data frames, in arrival order
	hellos    int
	connects  atomic.Int32
	autoAck   bool
	dropAfter int  // close the connection after this many data frames (0 = never)
	reject    bool // answer 401
	noWS      bool // answer 404 on /v1/ws
	pushes    atomic.Int32
	extra     [][]byte // sent right after welcome
}

func (g *gateway) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/ws", func(w http.ResponseWriter, r *http.Request) {
		g.connects.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+token || g.reject {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if g.noWS {
			http.NotFound(w, r)
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
		if env, _, err := protocol.DecodeFromAgent(data); err != nil || env.Type != protocol.TypeHello {
			g.t.Errorf("first frame is not a valid hello: %v", err)
			return
		}
		g.mu.Lock()
		g.hellos++
		g.mu.Unlock()
		_ = conn.Write(ctx, websocket.MessageText, welcome())
		for _, f := range g.extra {
			_ = conn.Write(ctx, websocket.MessageText, f)
		}
		n := 0
		for {
			_, data, err := conn.Read(ctx)
			if err != nil {
				return
			}
			env, _, err := protocol.DecodeFromAgent(data)
			if err != nil {
				g.t.Errorf("invalid frame: %v", err)
				return
			}
			g.mu.Lock()
			g.received = append(g.received, env.Seq)
			g.mu.Unlock()
			n++
			if g.autoAck {
				_ = conn.Write(ctx, websocket.MessageText, ack(env.Seq))
			}
			if g.dropAfter > 0 && n >= g.dropAfter {
				g.dropAfter = 0
				_ = conn.CloseNow()
				return
			}
		}
	})
	mux.HandleFunc("/v1/push", func(w http.ResponseWriter, r *http.Request) {
		g.pushes.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+token || g.reject {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		sc := bufio.NewScanner(r.Body)
		var highest uint64
		first := true
		for sc.Scan() {
			env, _, err := protocol.DecodeFromAgent(sc.Bytes())
			if err != nil {
				g.t.Errorf("invalid pushed frame: %v", err)
				return
			}
			if first != (env.Type == protocol.TypeHello) {
				g.t.Errorf("push must start with exactly one hello, got %s", env.Type)
			}
			if !first {
				g.mu.Lock()
				g.received = append(g.received, env.Seq)
				g.mu.Unlock()
				highest = env.Seq
			}
			first = false
		}
		if highest > 0 {
			_, _ = w.Write(append(ack(highest), '\n'))
		}
	})
	return mux
}

func (g *gateway) seqs() []uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Clone(g.received)
}

func setup(t *testing.T, g *gateway, tune func(*Options)) (*Client, *buffer.Buffer, func()) {
	t.Helper()
	g.t = t
	srv := httptest.NewTLSServer(g.handler())
	buf, err := buffer.Open(t.TempDir(), 1<<30, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	o := Options{
		BaseURL: srv.URL, Token: token, UserAgent: "acme-agent/dev",
		Buffer: buf, Hello: hello, HTTPClient: srv.Client(),
		MaxBackoff: 50 * time.Millisecond, PushInterval: 50 * time.Millisecond,
		FallbackFor: 200 * time.Millisecond, UnauthorizedBackoff: 100 * time.Millisecond,
	}
	if tune != nil {
		tune(&o)
	}
	c, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	return c, buf, func() {
		cancel()
		<-done
		srv.Close()
		_ = buf.Close()
	}
}

func metrics(n int) *protocol.Metrics {
	return &protocol.Metrics{Time: time.Now().UnixMilli(), Series: []protocol.Sample{{Name: "load.1", Value: float64(n)}}}
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func pendingCount(b *buffer.Buffer) int {
	n := 0
	_ = b.Pending(func(buffer.Record) error { n++; return nil })
	return n
}

func TestDeliversAndAcks(t *testing.T) {
	g := &gateway{autoAck: true}
	c, buf, stop := setup(t, g, nil)
	defer stop()
	for i := 1; i <= 5; i++ {
		if err := c.Send(protocol.TypeMetrics, metrics(i), true); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, "5 frames delivered", func() bool { return len(g.seqs()) == 5 })
	eventually(t, "buffer drained by acks", func() bool { return pendingCount(buf) == 0 })
	if got := g.seqs(); !slices.IsSorted(got) {
		t.Errorf("out of order: %v", got)
	}
}

func TestResendsUnackedAfterReconnect(t *testing.T) {
	g := &gateway{dropAfter: 2}
	c, buf, stop := setup(t, g, nil)
	defer stop()
	// Frames written while disconnected are buffered and sent on connect.
	for i := 1; i <= 4; i++ {
		if err := c.Send(protocol.TypeMetrics, metrics(i), true); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, "second connection", func() bool { return g.connects.Load() >= 2 && len(g.seqs()) >= 6 })
	got := g.seqs()
	// First connection saw 1,2 and dropped; nothing was acked, so the
	// second connection resends everything in order.
	if !slices.Equal(got[:2], []uint64{1, 2}) || !slices.Equal(got[2:6], []uint64{1, 2, 3, 4}) {
		t.Errorf("seqs %v", got)
	}
	if pendingCount(buf) != 4 {
		t.Error("unacked frames must stay buffered")
	}
}

func TestLiveFramesAreNotBuffered(t *testing.T) {
	g := &gateway{reject: true}
	c, buf, stop := setup(t, g, nil)
	defer stop()
	if err := c.Send(protocol.TypeMetrics, metrics(1), false); err != nil {
		t.Fatal(err)
	}
	if pendingCount(buf) != 0 {
		t.Error("live frame was buffered")
	}
}

func TestUnauthorizedBacksOff(t *testing.T) {
	g := &gateway{reject: true}
	_, _, stop := setup(t, g, func(o *Options) { o.UnauthorizedBackoff = 300 * time.Millisecond })
	time.Sleep(700 * time.Millisecond)
	stop()
	// With 50 ms normal backoff this would be ~14 attempts.
	if n := g.connects.Load(); n > 4 {
		t.Errorf("%d connection attempts in 700 ms despite 401", n)
	}
}

func TestFallsBackToPush(t *testing.T) {
	g := &gateway{noWS: true}
	c, buf, stop := setup(t, g, nil)
	defer stop()
	for i := 1; i <= 3; i++ {
		if err := c.Send(protocol.TypeMetrics, metrics(i), true); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, "push delivered and acked", func() bool { return g.pushes.Load() > 0 && pendingCount(buf) == 0 })
	if got := g.seqs(); !slices.Equal(got[:3], []uint64{1, 2, 3}) {
		t.Errorf("pushed seqs %v", got)
	}
}

func TestGatewayMessagesReachHandler(t *testing.T) {
	cfg, _ := protocol.Encode(protocol.TypeConfig, 0, &protocol.AgentConfig{
		Version: 3, Intervals: protocol.Intervals{MetricsS: 10, ChecksS: 60, DiscoveryS: 7200, InventoryS: 3600},
	})
	// An unknown type and a malformed frame must be ignored without
	// dropping the connection; the config after them still arrives.
	g := &gateway{extra: [][]byte{[]byte(`{"type":"exec","data":{"cmd":"id"}}`), []byte(`not json`), cfg}}
	var mu sync.Mutex
	var got []protocol.Type
	_, _, stop := setup(t, g, func(o *Options) {
		o.OnMessage = func(t protocol.Type, _ protocol.Message) {
			mu.Lock()
			got = append(got, t)
			mu.Unlock()
		}
	})
	defer stop()
	eventually(t, "welcome and config handled", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(got) >= 2
	})
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(got, []protocol.Type{protocol.TypeWelcome, protocol.TypeConfig}) {
		t.Errorf("handler saw %v", got)
	}
	if n := g.connects.Load(); n != 1 {
		t.Errorf("ignored frames caused %d connects", n)
	}
}

func TestBackoffBounds(t *testing.T) {
	for attempt := 0; attempt < 20; attempt++ {
		d := backoff(attempt, time.Minute)
		limit := min(time.Second<<min(attempt, 10), time.Minute)
		if d < limit/2 || d > limit {
			t.Errorf("attempt %d: %v outside [%v, %v]", attempt, d, limit/2, limit)
		}
	}
}

func TestNewRejectsPlainHTTP(t *testing.T) {
	buf, _ := buffer.Open(t.TempDir(), 1<<20, time.Hour)
	defer func() { _ = buf.Close() }()
	if _, err := New(Options{BaseURL: "http://gw.example.com", Token: token, Buffer: buf, Hello: hello}); err == nil {
		t.Error("http URL accepted")
	}
	c, err := New(Options{BaseURL: "https://gw.example.com/", Token: token, Buffer: buf, Hello: hello})
	if err != nil {
		t.Fatal(err)
	}
	if c.wsURL != "wss://gw.example.com/v1/ws" || c.pushURL != "https://gw.example.com/v1/push" {
		t.Errorf("urls %s %s", c.wsURL, c.pushURL)
	}
}
