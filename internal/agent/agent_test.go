package agent

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/INFORENT-GmbH/host-agent/internal/checks"
	"github.com/INFORENT-GmbH/host-agent/internal/collect"
	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

type sent struct {
	t       protocol.Type
	msg     protocol.Message
	persist bool
}

type fakeCollector struct{}

func (fakeCollector) Name() string { return "fake" }
func (fakeCollector) Collect(context.Context, time.Time) ([]protocol.Sample, error) {
	return []protocol.Sample{{Name: "fake.value", Value: 1}}, nil
}

type fakeCheck struct{ item string }

func (fakeCheck) Plugin() string { return "fake" }
func (c *fakeCheck) Discover(context.Context) ([]protocol.DiscoveredItem, error) {
	return []protocol.DiscoveredItem{{Plugin: "fake", Item: c.item}}, nil
}
func (c *fakeCheck) Run(context.Context, time.Time) ([]protocol.CheckResult, error) {
	return []protocol.CheckResult{{Plugin: "fake", Item: c.item, Values: map[string]float64{"v": 1}}}, nil
}

func newLoop() (*loop, *[]sent, *sync.Mutex) {
	var mu sync.Mutex
	var out []sent
	l := &loop{
		log: slog.New(slog.DiscardHandler),
		send: func(t protocol.Type, m protocol.Message, persist bool) error {
			if err := m.Validate(); err != nil {
				panic(err)
			}
			mu.Lock()
			out = append(out, sent{t, m, persist})
			mu.Unlock()
			return nil
		},
		collectors: []collect.Collector{fakeCollector{}},
		live:       []collect.Collector{fakeCollector{}},
		intervals:  DefaultIntervals,
		onUpdate:   func(string) {},
	}
	return l, &out, &mu
}

func TestDiscoverySentOnChangeOrInterval(t *testing.T) {
	l, out, _ := newLoop()
	c := &fakeCheck{item: "a"}
	l.checks = []checks.Check{c}
	now := time.Now()
	count := func() int {
		n := 0
		for _, s := range *out {
			if s.t == protocol.TypeDiscovery {
				n++
			}
		}
		return n
	}
	l.checksAndDiscovery(context.Background(), now)
	l.checksAndDiscovery(context.Background(), now.Add(time.Minute))
	if n := count(); n != 1 {
		t.Fatalf("unchanged discovery sent %d times", n)
	}
	c.item = "b"
	l.checksAndDiscovery(context.Background(), now.Add(2*time.Minute))
	if n := count(); n != 2 {
		t.Fatalf("changed discovery not sent (%d)", n)
	}
	l.checksAndDiscovery(context.Background(), now.Add(2*time.Minute+seconds(DefaultIntervals.DiscoveryS)))
	if n := count(); n != 3 {
		t.Fatalf("discovery not refreshed after its interval (%d)", n)
	}
}

func TestApplyConfigIgnoresOlderVersions(t *testing.T) {
	l, _, _ := newLoop()
	newer := &protocol.AgentConfig{Version: 5, Intervals: protocol.Intervals{MetricsS: 30, ChecksS: 120, DiscoveryS: 3600, InventoryS: 3600}, DisabledCollectors: []string{"diskio"}}
	if !l.applyConfig(newer) || l.intervals.MetricsS != 30 || len(l.disabled) != 1 {
		t.Fatalf("config not applied: %+v", l)
	}
	older := &protocol.AgentConfig{Version: 4, Intervals: DefaultIntervals}
	if l.applyConfig(older) || l.intervals.MetricsS != 30 {
		t.Error("older config applied")
	}
}

func TestLiveModeExpiresAndIsNotPersisted(t *testing.T) {
	l, out, mu := newLoop()
	msgs := make(chan gatewayMsg, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- l.run(ctx, msgs) }()
	msgs <- gatewayMsg{protocol.TypeLive, &protocol.Live{On: true, IntervalMs: 500, TTLS: 1}}
	time.Sleep(2500 * time.Millisecond)
	cancel()
	<-done

	mu.Lock()
	defer mu.Unlock()
	live := 0
	for _, s := range *out {
		if s.t == protocol.TypeMetrics && !s.persist {
			live++
		}
	}
	// 1 s TTL at 500 ms: two ticks, then the ticker stops by itself.
	if live < 1 || live > 3 {
		t.Errorf("%d live frames in 2.5 s for a 1 s TTL", live)
	}
}

func TestUpdateDelegated(t *testing.T) {
	l, _, _ := newLoop()
	got := make(chan string, 1)
	l.onUpdate = func(v string) { got <- v }
	msgs := make(chan gatewayMsg, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- l.run(ctx, msgs) }()
	msgs <- gatewayMsg{protocol.TypeUpdate, &protocol.Update{Version: "1.2.3"}}
	select {
	case v := <-got:
		if v != "1.2.3" {
			t.Errorf("update version %q", v)
		}
	case <-time.After(2 * time.Second):
		t.Error("update not delegated")
	}
	cancel()
	<-done
}
