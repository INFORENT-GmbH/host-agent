//go:build windows

package main

import (
	"context"
	"io"
	"os"
	"os/signal"

	"golang.org/x/sys/windows/svc"

	"github.com/INFORENT-GmbH/host-agent/internal/brand"
)

// startAgent runs under the service control manager when the SCM started us,
// and in the foreground otherwise — the same binary serves `sc start` and an
// administrator debugging the agent in a console.
func startAgent(b brand.Brand, stderr io.Writer) int {
	inService, err := svc.IsWindowsService()
	if err != nil || !inService {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		return runAgent(ctx, b, stderr)
	}
	h := &serviceHandler{b: b, stderr: stderr}
	if err := svc.Run(b.Name(), h); err != nil {
		return 1
	}
	return h.code
}

// serviceHandler answers the SCM. The agent itself runs in a goroutine; a
// stop or shutdown request cancels its context, and Execute only returns once
// the agent has actually finished — returning earlier would let the SCM kill
// the process mid-flush, losing the send buffer's last segment.
type serviceHandler struct {
	b      brand.Brand
	stderr io.Writer
	code   int
}

func (h *serviceHandler) Execute(_ []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	s <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan int, 1)
	go func() { done <- runAgent(ctx, h.b, h.stderr) }()

	s <- svc.Status{State: svc.Running, Accepts: accepted}
	for {
		select {
		case code := <-done:
			// The agent gave up on its own (not enrolled, broken config).
			h.code = code
			s <- svc.Status{State: svc.StopPending}
			return false, uint32(code)
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				s <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				s <- svc.Status{State: svc.StopPending}
				cancel()
				h.code = <-done
				return false, uint32(h.code)
			}
		}
	}
}
