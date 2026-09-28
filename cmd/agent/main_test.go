package main

import (
	"bytes"
	"encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/INFORENT-GmbH/host-agent/internal/brand"
	"github.com/INFORENT-GmbH/host-agent/internal/checks"
	"github.com/INFORENT-GmbH/host-agent/internal/config"
)

type result struct {
	code           int
	stdout, stderr string
}

func invoke(env map[string]string, args ...string) result {
	var out, errOut bytes.Buffer
	code := run(args, func(k string) string { return env[k] }, &out, &errOut)
	return result{code, out.String(), errOut.String()}
}

func TestVersionFromExecutableName(t *testing.T) {
	r := invoke(nil, "/usr/bin/acme-agent", "version")
	if r.code != 0 || r.stdout != "acme-agent dev\n" {
		t.Fatalf("got %+v", r)
	}
}

func TestUnbrandedNeedsOverride(t *testing.T) {
	r := invoke(nil, "/tmp/go-build/exe/agent", "version")
	if r.code != 2 || !strings.Contains(r.stderr, envBrand) {
		t.Fatalf("want exit 2 mentioning %s, got %+v", envBrand, r)
	}
	r = invoke(map[string]string{envBrand: "acme"}, "/tmp/go-build/exe/agent", "version")
	if r.code != 0 || r.stdout != "acme-agent dev\n" {
		t.Fatalf("override: got %+v", r)
	}
}

func TestUsageAndUnknownCommand(t *testing.T) {
	if r := invoke(nil, "acme-agent"); r.code != 2 || !strings.Contains(r.stderr, "Usage: acme-agent") {
		t.Errorf("no command: %+v", r)
	}
	if r := invoke(nil, "acme-agent", "frobnicate"); r.code != 2 || !strings.Contains(r.stderr, `unknown command "frobnicate"`) {
		t.Errorf("unknown command: %+v", r)
	}
	if r := invoke(nil, "acme-agent", "help"); r.code != 0 || !strings.Contains(r.stdout, "status") {
		t.Errorf("help: %+v", r)
	}
}

func TestStatusWithoutConfig(t *testing.T) {
	root := t.TempDir()
	r := invoke(map[string]string{envRoot: root}, "acme-agent", "status")
	if r.code != 1 || !strings.Contains(r.stdout, "config file missing") {
		t.Fatalf("got %+v", r)
	}
}

func TestDump(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "machine-id"), []byte("00112233445566778899aabbccddeeff\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := defaultChecks
	defaultChecks = func() []checks.Check {
		var cs []checks.Check
		for _, c := range orig() {
			if c.Plugin() != "apt" {
				cs = append(cs, c)
			}
		}
		return cs
	}
	t.Cleanup(func() { defaultChecks = orig })

	r := invoke(map[string]string{envRoot: root}, "acme-agent", "dump", "-wait", "50ms")
	if r.code != 0 {
		t.Fatalf("got %+v", r)
	}
	var frames []struct {
		Type string `json:"type"`
		Seq  uint64 `json:"seq"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &frames); err != nil {
		t.Fatalf("output is not a JSON array: %v\n%s", err, r.stdout)
	}
	var got []string
	for _, f := range frames {
		got = append(got, fmt.Sprintf("%s:%d", f.Type, f.Seq))
	}
	if strings.Join(got, " ") != "hello:0 metrics:1 discovery:2 checks:3" {
		t.Errorf("frames %v", got)
	}
	if !strings.Contains(r.stdout, `"machineId": "00112233445566778899aabbccddeeff"`) {
		t.Errorf("machine id missing:\n%s", r.stdout)
	}
}

func TestDumpRejectsBadWait(t *testing.T) {
	if r := invoke(nil, "acme-agent", "dump", "-wait", "2h"); r.code != 2 {
		t.Errorf("got %+v", r)
	}
}

func TestStatusEnrolledHidesToken(t *testing.T) {
	root := t.TempDir()
	b, err := brand.New("acme", root)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Server.URL = "https://agent.example.com"
	cfg.Server.Token = "super-secret-token"
	if err := config.Save(b.ConfigFile(), cfg); err != nil {
		t.Fatal(err)
	}
	r := invoke(map[string]string{envRoot: root}, "acme-agent", "status")
	if r.code != 0 {
		t.Fatalf("got %+v", r)
	}
	for _, want := range []string{"enrolled:     yes", "gateway:      https://agent.example.com", "satellite:    off", "local checks: on"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, r.stdout)
		}
	}
	if strings.Contains(r.stdout+r.stderr, "super-secret-token") {
		t.Error("status leaked the token")
	}
}
