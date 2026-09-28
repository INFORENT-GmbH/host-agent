package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/INFORENT-GmbH/host-agent/internal/config"
)

func TestRunNotEnrolled(t *testing.T) {
	_, b := agentRoot(t)
	var stderr strings.Builder
	if code := runAgent(context.Background(), b, &stderr); code != 1 || !strings.Contains(stderr.String(), "not enrolled") {
		t.Fatalf("no config: %d %q", code, stderr.String())
	}
	if err := config.Save(b.ConfigFile(), config.Default()); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	if code := runAgent(context.Background(), b, &stderr); code != 1 || !strings.Contains(stderr.String(), "not enrolled") {
		t.Fatalf("empty server: %d %q", code, stderr.String())
	}
}

func TestRunStopsCleanly(t *testing.T) {
	_, b := agentRoot(t)
	cfg := config.Default()
	// Nothing listens there: the agent keeps retrying until it is stopped.
	cfg.Server = config.Server{URL: "https://127.0.0.1:1", Token: testHostToken}
	cfg.Local.LocalChecks = false
	if err := config.Save(b.ConfigFile(), cfg); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	var stderr strings.Builder
	start := time.Now()
	code := runAgent(ctx, b, &stderr)
	if code != 0 || !strings.Contains(stderr.String(), "stopped") {
		t.Fatalf("exit %d:\n%s", code, stderr.String())
	}
	if d := time.Since(start); d > 20*time.Second {
		t.Errorf("stopping took %v", d)
	}
	if strings.Contains(stderr.String(), testHostToken) {
		t.Error("run logged the host token")
	}
}
