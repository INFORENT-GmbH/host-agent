package snmp

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// An optional test against a REAL SNMP agent — normally the simulator:
//
//	docker compose up -d snmpsim
//	SNMP_LIVE_TARGET=127.0.0.1:1161 go test ./internal/poll/snmp/
//
// It is skipped without that variable, because CI has no simulator and must
// not depend on a UDP socket. What it adds over the replay tests is the one
// thing they cannot cover: that the gosnmp wiring (v2c and v3, GETBULK across
// a long table) really speaks to an agent.
func TestLiveAgainstSimulator(t *testing.T) {
	target := os.Getenv("SNMP_LIVE_TARGET")
	if target == "" {
		t.Skip("set SNMP_LIVE_TARGET=<host:port> to test against a running SNMP agent")
	}
	host, portStr, ok := strings.Cut(target, ":")
	if !ok {
		t.Fatalf("SNMP_LIVE_TARGET must look like host:port, got %q", target)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatalf("port in %q: %v", target, err)
	}

	cfgs := map[string]Config{
		"v2c": {
			Address: host, Port: uint16(port), Version: V2c,
			Community: envOr("SNMP_LIVE_COMMUNITY", "public"), Timeout: 3 * time.Second, Retries: 1,
		},
		"v3": {
			Address: host, Port: uint16(port), Version: V3,
			User:      envOr("SNMP_LIVE_USER", "portal"),
			AuthProto: "SHA", AuthKey: envOr("SNMP_LIVE_AUTH_KEY", "simulated-auth-key"),
			PrivProto: "AES", PrivKey: envOr("SNMP_LIVE_PRIV_KEY", "simulated-priv-key"),
			// snmpsim derives the context from the data file name; a real device
			// usually needs none.
			Context: envOr("SNMP_LIVE_CONTEXT", "public"),
			Timeout: 3 * time.Second, Retries: 1,
		},
	}

	for name, cfg := range cfgs {
		t.Run(name, func(t *testing.T) {
			s, err := Dial(cfg)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer func() { _ = s.Close() }()

			p := NewPoller()
			ctx := context.Background()
			if _, err := p.Poll(ctx, s, time.Now()); err != nil {
				t.Fatalf("first poll: %v", err)
			}
			time.Sleep(2 * time.Second)
			res, err := p.Poll(ctx, s, time.Now())
			if err != nil {
				t.Fatalf("second poll: %v", err)
			}
			if res.Identity.Name == "" {
				t.Error("no sysName")
			}
			var ports, withRate int
			for _, c := range res.Checks {
				if c.Plugin != "if" {
					continue
				}
				ports++
				if _, ok := c.Values["rx_bytes_per_sec"]; ok {
					withRate++
				}
			}
			if ports == 0 {
				t.Fatal("no interfaces — GETBULK over ifTable failed")
			}
			if withRate == 0 {
				t.Error("no interface reported a rate; the simulator's counters should move")
			}
			t.Logf("%s: %s, %d ports, %d with rates", name, res.Identity.Name, ports, withRate)
		})
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
