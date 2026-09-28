// Package transport delivers frames to the gateway: over one outbound
// WebSocket when possible, over HTTPS push every few seconds when WebSockets
// are blocked (proxies, middleboxes). Nothing listens on the host.
//
// Delivery is at-least-once for persisted frames: they go to the disk
// buffer first and are only dropped when the gateway acknowledges them. Live
// frames (fast metrics while someone watches) are best effort and never
// buffered.
package transport

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/INFORENT-GmbH/host-agent/internal/buffer"
	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

// ErrUnauthorized means the gateway rejected the host token (revoked host,
// deleted host). Retrying fast would only hammer the gateway.
var ErrUnauthorized = errors.New("gateway rejected the host token")

// CloseUnauthorized is the WebSocket close code the gateway uses for a
// revoked token.
const CloseUnauthorized websocket.StatusCode = 4001

// Options configure a Client. Zero durations take the defaults.
type Options struct {
	BaseURL   string // https://agent.example.com
	Token     string
	UserAgent string
	Buffer    *buffer.Buffer
	// Hello builds a fresh hello for every connection.
	Hello func() (*protocol.Hello, error)
	// OnMessage receives welcome, config, live and update. It runs on the
	// reader goroutine and must not block.
	OnMessage  func(protocol.Type, protocol.Message)
	HTTPClient *http.Client
	Logger     *slog.Logger

	PushInterval        time.Duration // HTTPS fallback cadence, default 10 s
	FallbackAfter       int           // failed WebSocket dials before falling back, default 3
	FallbackFor         time.Duration // how long to stay on HTTPS before retrying WebSocket, default 5 min
	MaxBackoff          time.Duration // default 60 s
	UnauthorizedBackoff time.Duration // default 10 min
	PingInterval        time.Duration // default 30 s
	HandshakeTimeout    time.Duration // default 15 s
	WriteTimeout        time.Duration // default 10 s
}

// Client is safe for concurrent use.
type Client struct {
	o       Options
	wsURL   string
	pushURL string

	mu   sync.Mutex
	wake chan struct{}
	live chan liveFrame
}

type liveFrame struct {
	seq   uint64
	frame []byte
}

// New validates the options.
func New(o Options) (*Client, error) {
	u, err := url.Parse(o.BaseURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("gateway URL must be https://host, got %q", o.BaseURL)
	}
	if o.Buffer == nil || o.Hello == nil || o.Token == "" {
		return nil, errors.New("transport: buffer, hello and token are required")
	}
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	def(&o.PushInterval, 10*time.Second)
	def(&o.FallbackFor, 5*time.Minute)
	def(&o.MaxBackoff, time.Minute)
	def(&o.UnauthorizedBackoff, 10*time.Minute)
	def(&o.PingInterval, 30*time.Second)
	def(&o.HandshakeTimeout, 15*time.Second)
	def(&o.WriteTimeout, 10*time.Second)
	if o.FallbackAfter <= 0 {
		o.FallbackAfter = 3
	}
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: 60 * time.Second}
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.OnMessage == nil {
		o.OnMessage = func(protocol.Type, protocol.Message) {}
	}
	base := strings.TrimSuffix(u.String(), "/")
	return &Client{
		o:       o,
		wsURL:   "wss://" + strings.TrimPrefix(base, "https://") + "/v1/ws",
		pushURL: base + "/v1/push",
	}, nil
}

// Send encodes msg with the next seq. Persisted frames are written to the
// buffer and picked up by the connection (now or after a reconnect); live
// frames go out only while a WebSocket is up and are dropped otherwise.
func (c *Client) Send(t protocol.Type, msg protocol.Message, persist bool) error {
	seq, err := c.o.Buffer.NextSeq()
	if err != nil {
		return err
	}
	frame, err := protocol.Encode(t, seq, msg)
	if err != nil {
		return err
	}
	if persist {
		dropped, err := c.o.Buffer.Append(seq, time.Now(), frame)
		if err != nil {
			return err
		}
		if dropped > 0 {
			c.o.Logger.Warn("send buffer full, dropped oldest records", "dropped", dropped)
		}
	}
	c.mu.Lock()
	wake, live := c.wake, c.live
	c.mu.Unlock()
	switch {
	case wake == nil:
	case persist:
		select {
		case wake <- struct{}{}:
		default: // a wake-up is already pending
		}
	default:
		select {
		case live <- liveFrame{seq, frame}:
		default: // connection is behind; live data is best effort
		}
	}
	return nil
}

// Run keeps a connection up until ctx ends.
func (c *Client) Run(ctx context.Context) {
	failures, attempt := 0, 0
	for ctx.Err() == nil {
		start := time.Now()
		err := c.session(ctx)
		if ctx.Err() != nil {
			return
		}
		var dialErr *dialError
		switch {
		case errors.Is(err, ErrUnauthorized):
			c.o.Logger.Error("gateway rejected the host token; re-enroll the host", "retry_in", c.o.UnauthorizedBackoff)
			sleep(ctx, c.o.UnauthorizedBackoff)
			continue
		case errors.As(err, &dialErr):
			failures++
			c.o.Logger.Warn("websocket connect failed", "err", err, "failures", failures)
		default:
			failures = 0
			c.o.Logger.Info("websocket disconnected", "err", err)
		}
		if time.Since(start) > time.Minute {
			attempt = 0 // the session was healthy; reconnect quickly
		}
		if failures >= c.o.FallbackAfter {
			c.o.Logger.Warn("falling back to https push", "for", c.o.FallbackFor)
			if err := c.fallback(ctx); errors.Is(err, ErrUnauthorized) {
				continue // handled at the top of the next round
			}
			failures, attempt = 0, 0
			continue
		}
		sleep(ctx, backoff(attempt, c.o.MaxBackoff))
		attempt++
	}
}

type dialError struct{ err error }

func (e *dialError) Error() string { return "dial: " + e.err.Error() }
func (e *dialError) Unwrap() error { return e.err }

func (c *Client) headers() http.Header {
	h := http.Header{}
	h.Set("Authorization", "Bearer "+c.o.Token)
	h.Set("User-Agent", c.o.UserAgent)
	return h
}

func (c *Client) helloFrame() ([]byte, error) {
	h, err := c.o.Hello()
	if err != nil {
		return nil, err
	}
	return protocol.Encode(protocol.TypeHello, 0, h)
}

func (c *Client) session(ctx context.Context) error {
	dctx, cancel := context.WithTimeout(ctx, c.o.HandshakeTimeout)
	defer cancel()
	conn, resp, err := websocket.Dial(dctx, c.wsURL, &websocket.DialOptions{
		HTTPClient:      c.o.HTTPClient,
		HTTPHeader:      c.headers(),
		CompressionMode: websocket.CompressionNoContextTakeover,
	})
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		if resp != nil && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
			return ErrUnauthorized
		}
		return &dialError{err}
	}
	defer func() { _ = conn.CloseNow() }()
	conn.SetReadLimit(protocol.MaxMessageBytes)

	hello, err := c.helloFrame()
	if err != nil {
		return err
	}
	if err := c.write(ctx, conn, hello); err != nil {
		return err
	}
	if err := c.awaitWelcome(dctx, conn); err != nil {
		return err
	}
	c.o.Logger.Info("connected to gateway")

	sctx, stop := context.WithCancel(ctx)
	defer stop()
	wake := make(chan struct{}, 1)
	live := make(chan liveFrame, 16)
	c.mu.Lock()
	c.wake, c.live = wake, live
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.wake, c.live = nil, nil
		c.mu.Unlock()
	}()

	errc := make(chan error, 2)
	go func() { errc <- c.readLoop(sctx, conn) }()
	go func() {
		t := time.NewTicker(c.o.PingInterval)
		defer t.Stop()
		for {
			select {
			case <-sctx.Done():
				return
			case <-t.C:
				pctx, cancel := context.WithTimeout(sctx, c.o.WriteTimeout)
				err := conn.Ping(pctx)
				cancel()
				if err != nil {
					errc <- fmt.Errorf("ping: %w", err)
					return
				}
			}
		}
	}()

	var lastSent uint64
	sendPending := func() error {
		return c.o.Buffer.Pending(func(r buffer.Record) error {
			if r.Seq <= lastSent {
				return nil
			}
			if err := c.write(sctx, conn, r.Frame); err != nil {
				return err
			}
			lastSent = r.Seq
			return nil
		})
	}
	if err := sendPending(); err != nil {
		return err
	}
	for {
		select {
		case <-sctx.Done():
			_ = conn.Close(websocket.StatusNormalClosure, "agent stopping")
			return sctx.Err()
		case err := <-errc:
			return err
		case <-wake:
			if err := sendPending(); err != nil {
				return err
			}
		case lf := <-live:
			// The gateway drops anything not above the last seq it saw, so a
			// live frame overtaken by a persisted one is skipped here.
			if lf.seq <= lastSent {
				continue
			}
			if err := c.write(sctx, conn, lf.frame); err != nil {
				return err
			}
			lastSent = lf.seq
		}
	}
}

func (c *Client) write(ctx context.Context, conn *websocket.Conn, frame []byte) error {
	wctx, cancel := context.WithTimeout(ctx, c.o.WriteTimeout)
	defer cancel()
	return conn.Write(wctx, websocket.MessageText, frame)
}

func (c *Client) awaitWelcome(ctx context.Context, conn *websocket.Conn) error {
	_, data, err := conn.Read(ctx)
	if err != nil {
		return closeError(err)
	}
	env, msg, err := protocol.DecodeFromGateway(data)
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	if env.Type != protocol.TypeWelcome {
		return fmt.Errorf("handshake: expected welcome, got %s", env.Type)
	}
	c.o.OnMessage(env.Type, msg)
	return nil
}

func (c *Client) readLoop(ctx context.Context, conn *websocket.Conn) error {
	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			return closeError(err)
		}
		c.handle(data)
	}
}

// handle processes one gateway frame. A frame the agent does not understand
// is logged and ignored — never guessed at.
func (c *Client) handle(data []byte) {
	env, msg, err := protocol.DecodeFromGateway(data)
	if err != nil {
		c.o.Logger.Warn("ignoring gateway frame", "err", err)
		return
	}
	if ack, ok := msg.(*protocol.Ack); ok {
		if err := c.o.Buffer.Ack(ack.Seq); err != nil {
			c.o.Logger.Error("buffer ack failed", "err", err)
		}
		return
	}
	c.o.OnMessage(env.Type, msg)
}

func closeError(err error) error {
	if websocket.CloseStatus(err) == CloseUnauthorized {
		return ErrUnauthorized
	}
	return err
}

// fallback pushes over HTTPS until FallbackFor has passed.
func (c *Client) fallback(ctx context.Context) error {
	until := time.Now().Add(c.o.FallbackFor)
	for ctx.Err() == nil && time.Now().Before(until) {
		if err := c.pushOnce(ctx); err != nil {
			if errors.Is(err, ErrUnauthorized) {
				return err
			}
			c.o.Logger.Warn("https push failed", "err", err)
		}
		sleep(ctx, c.o.PushInterval)
	}
	return nil
}

// pushOnce sends hello plus pending frames as NDJSON and processes the
// gateway frames in the NDJSON response (ack, config, update, …).
func (c *Client) pushOnce(ctx context.Context) error {
	hello, err := c.helloFrame()
	if err != nil {
		return err
	}
	var body bytes.Buffer
	body.Write(hello)
	body.WriteByte('\n')
	errFull := errors.New("batch full")
	err = c.o.Buffer.Pending(func(r buffer.Record) error {
		if body.Len()+len(r.Frame)+1 > protocol.MaxMessageBytes {
			return errFull
		}
		body.Write(r.Frame)
		body.WriteByte('\n')
		return nil
	})
	if err != nil && !errors.Is(err, errFull) {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.pushURL, &body)
	if err != nil {
		return err
	}
	req.Header = c.headers()
	req.Header.Set("Content-Type", "application/x-ndjson")
	resp, err := c.o.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return ErrUnauthorized
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("push: HTTP %d", resp.StatusCode)
	}
	sc := bufio.NewScanner(io.LimitReader(resp.Body, protocol.MaxMessageBytes))
	sc.Buffer(make([]byte, 64*1024), protocol.MaxMessageBytes)
	for sc.Scan() {
		if line := bytes.TrimSpace(sc.Bytes()); len(line) > 0 {
			c.handle(line)
		}
	}
	return sc.Err()
}

// backoff: exponential from 1 s up to maxDelay with jitter, so a gateway
// restart does not get every agent back in the same second.
func backoff(attempt int, maxDelay time.Duration) time.Duration {
	d := time.Second << min(attempt, 10)
	d = min(d, maxDelay)
	return d/2 + rand.N(d/2+1) // #nosec G404 -- jitter, not security
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
