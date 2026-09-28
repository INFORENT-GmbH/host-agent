package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"encoding/json/jsontext"

	"github.com/INFORENT-GmbH/host-agent/internal/brand"
	"github.com/INFORENT-GmbH/host-agent/internal/buildinfo"
	"github.com/INFORENT-GmbH/host-agent/internal/checks"
	"github.com/INFORENT-GmbH/host-agent/internal/collect"
	"github.com/INFORENT-GmbH/host-agent/internal/config"
	"github.com/INFORENT-GmbH/host-agent/internal/hostinfo"
	"github.com/INFORENT-GmbH/host-agent/internal/localchecks"
	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

// defaultChecks is replaced in tests to keep the slow apt simulation out.
var defaultChecks = checks.Default

// dump collects once and prints exactly the frames the agent would send —
// validated by the protocol package, but sent nowhere. It is the first thing
// to run when a customer asks why a value looks wrong.
func dump(ctx context.Context, b brand.Brand, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("dump", flag.ContinueOnError)
	fs.SetOutput(stderr)
	wait := fs.Duration("wait", 2*time.Second, "gap between the two readings that rate metrics need")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *wait < 10*time.Millisecond || *wait > time.Minute {
		_, _ = fmt.Fprintln(stderr, "-wait must be between 10ms and 1m")
		return 2
	}

	cfg, err := config.Load(b.ConfigFile())
	switch {
	case errors.Is(err, os.ErrNotExist):
		cfg = config.Default()
	case err != nil:
		_, _ = fmt.Fprintf(stderr, "config error: %v\n", err)
		return 1
	}

	info, err := hostinfo.Gather(b.Root)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "host info: %v\n", err)
		return 1
	}
	hello := &protocol.Hello{
		Protocol:     protocol.Version,
		AgentVersion: buildinfo.Version,
		Brand:        b.Key,
		Hostname:     info.Hostname,
		MachineID:    info.MachineID,
		OS:           info.OS,
		Local:        protocol.LocalOptIns{Satellite: cfg.Local.Satellite, LocalChecks: cfg.Local.LocalChecks},
		Time:         time.Now().UnixMilli(),
		// dump never touches the send buffer, so there is no real counter.
		SeqEpoch: "0000000000000000",
	}

	warn := func(err error) {
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "warning: %v\n", err)
		}
	}
	collectors := collect.Default()
	cs := defaultChecks()
	if cfg.Local.LocalChecks {
		cs = append(cs, localchecks.New(b))
	}
	items, err := checks.Discover(ctx, cs)
	warn(err)
	_, err = collect.Run(ctx, collectors, nil, time.Now())
	warn(err)
	_, err = checks.Run(ctx, cs, time.Now())
	warn(err)
	select {
	case <-time.After(*wait):
	case <-ctx.Done():
		return 1
	}
	now := time.Now()
	samples, err := collect.Run(ctx, collectors, nil, now)
	warn(err)
	results, err := checks.Run(ctx, cs, now)
	warn(err)

	var frames [][]byte
	add := func(t protocol.Type, seq uint64, m protocol.Message) bool {
		f, err := protocol.Encode(t, seq, m)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "%v\n", err)
			return false
		}
		frames = append(frames, f)
		return true
	}
	ms := now.UnixMilli()
	if !add(protocol.TypeHello, 0, hello) ||
		(len(samples) > 0 && !add(protocol.TypeMetrics, 1, &protocol.Metrics{Time: ms, Series: samples})) ||
		!add(protocol.TypeDiscovery, 2, &protocol.Discovery{Time: ms, Items: items}) ||
		(len(results) > 0 && !add(protocol.TypeChecks, 3, &protocol.Checks{Time: ms, Results: results})) {
		return 1
	}

	out := jsontext.Value("[")
	for i, f := range frames {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, f...)
	}
	out = append(out, ']')
	if err := out.Indent(jsontext.WithIndent("  ")); err != nil {
		_, _ = fmt.Fprintf(stderr, "format: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "%s\n", out)
	return 0
}
