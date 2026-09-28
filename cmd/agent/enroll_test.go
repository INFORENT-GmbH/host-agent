package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/INFORENT-GmbH/host-agent/internal/brand"
	"github.com/INFORENT-GmbH/host-agent/internal/config"
	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

const (
	testEnrollToken = "enroll-token-0123456789"
	testHostToken   = "host-token-0123456789abcdef0123456789"
)

// agentRoot is a fake filesystem root with the machine-id hostinfo needs.
func agentRoot(t *testing.T) (string, brand.Brand) {
	t.Helper()
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
	return root, b
}

// enrollGateway answers /v1/enroll over TLS; status 0 means 200 with a host token.
func enrollGateway(t *testing.T, status int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/v1/enroll" {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		req, err := protocol.DecodeEnrollRequest(body)
		if err != nil {
			t.Errorf("invalid enroll request: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if req.EnrollToken != testEnrollToken || req.Brand != "acme" || req.MachineID != "00112233445566778899aabbccddeeff" {
			t.Errorf("unexpected request %+v", req)
		}
		if status != 0 {
			http.Error(w, "nope", status)
			return
		}
		_, _ = io.WriteString(w, `{"hostId":"host-42","hostToken":"`+testHostToken+`"}`)
	}))
	t.Cleanup(srv.Close)
	orig := enrollHTTPClient
	enrollHTTPClient = srv.Client()
	t.Cleanup(func() { enrollHTTPClient = orig })
	return srv, &calls
}

func TestEnrollWritesConfig(t *testing.T) {
	root, b := agentRoot(t)
	srv, _ := enrollGateway(t, 0)
	r := invoke(map[string]string{envRoot: root, envEnrollToken: testEnrollToken}, "acme-agent", "enroll", "-url", srv.URL+"/")
	if r.code != 0 || !strings.Contains(r.stdout, "enrolled as host host-42") || !strings.Contains(r.stdout, "acme-agent.service") {
		t.Fatalf("got %+v", r)
	}
	if strings.Contains(r.stdout+r.stderr, testHostToken) {
		t.Error("enroll printed the host token")
	}
	cfg, err := config.Load(b.ConfigFile())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.URL != srv.URL || cfg.Server.Token != testHostToken {
		t.Errorf("saved server %+v", cfg.Server)
	}
	info, err := os.Stat(b.ConfigFile())
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("config mode %v, %v", info.Mode(), err)
	}
}

func TestEnrollRefusesReplaceWithoutForce(t *testing.T) {
	root, b := agentRoot(t)
	srv, calls := enrollGateway(t, 0)
	cfg := config.Default()
	cfg.Server = config.Server{URL: "https://old.example.com", Token: "old-token-0123456789abcdef0123456789"}
	cfg.Local.Satellite = true
	cfg.Local.LocalChecks = false
	if err := config.Save(b.ConfigFile(), cfg); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{envRoot: root}

	r := invoke(env, "acme-agent", "enroll", "-url", srv.URL, "-token", testEnrollToken)
	if r.code != 1 || !strings.Contains(r.stderr, "already enrolled with https://old.example.com") || calls.Load() != 0 {
		t.Fatalf("without -force: %+v, %d gateway calls", r, calls.Load())
	}

	r = invoke(env, "acme-agent", "enroll", "-force", "-url", srv.URL, "-token", testEnrollToken)
	if r.code != 0 {
		t.Fatalf("with -force: %+v", r)
	}
	got, err := config.Load(b.ConfigFile())
	if err != nil {
		t.Fatal(err)
	}
	if got.Server.URL != srv.URL || got.Server.Token != testHostToken {
		t.Errorf("server not replaced: %+v", got.Server)
	}
	if !got.Local.Satellite || got.Local.LocalChecks {
		t.Errorf("local opt-ins not kept: %+v", got.Local)
	}
}

func TestEnrollRejectedToken(t *testing.T) {
	root, b := agentRoot(t)
	srv, _ := enrollGateway(t, http.StatusUnauthorized)
	r := invoke(map[string]string{envRoot: root}, "acme-agent", "enroll", "-url", srv.URL, "-token", testEnrollToken)
	if r.code != 1 || !strings.Contains(r.stderr, "invalid or expired") {
		t.Fatalf("got %+v", r)
	}
	if _, err := os.Stat(b.ConfigFile()); !os.IsNotExist(err) {
		t.Errorf("config written after a rejected enroll: %v", err)
	}
}

func TestEnrollGatewayError(t *testing.T) {
	root, _ := agentRoot(t)
	srv, _ := enrollGateway(t, http.StatusInternalServerError)
	r := invoke(map[string]string{envRoot: root}, "acme-agent", "enroll", "-url", srv.URL, "-token", testEnrollToken)
	if r.code != 1 || !strings.Contains(r.stderr, "HTTP 500") {
		t.Fatalf("got %+v", r)
	}
}

func TestEnrollUsage(t *testing.T) {
	root, _ := agentRoot(t)
	env := map[string]string{envRoot: root}
	for name, args := range map[string][]string{
		"no token":   {"-url", "https://agent.example.com"},
		"plain http": {"-url", "http://agent.example.com", "-token", testEnrollToken},
		"with path":  {"-url", "https://agent.example.com/v1", "-token", testEnrollToken},
		"with query": {"-url", "https://agent.example.com/?x=1", "-token", testEnrollToken},
		"no url":     {"-token", testEnrollToken},
	} {
		r := invoke(env, append([]string{"acme-agent", "enroll"}, args...)...)
		if r.code != 2 || !strings.Contains(r.stderr, "usage: acme-agent enroll") {
			t.Errorf("%s: %+v", name, r)
		}
	}
}

// capturingGateway answers /v1/enroll and hands the decoded request back —
// the setup script's choices (channel, local checks) are only visible there.
func capturingGateway(t *testing.T, got **protocol.EnrollRequest) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, err := protocol.DecodeEnrollRequest(body)
		if err != nil {
			t.Errorf("invalid enroll request: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		*got = req
		_, _ = io.WriteString(w, `{"hostId":"host-42","hostToken":"`+testHostToken+`"}`)
	}))
	t.Cleanup(srv.Close)
	orig := enrollHTTPClient
	enrollHTTPClient = srv.Client()
	t.Cleanup(func() { enrollHTTPClient = orig })
	return srv
}

func TestEnrollChannelAndLocalChecks(t *testing.T) {
	root, b := agentRoot(t)
	var got *protocol.EnrollRequest
	srv := capturingGateway(t, &got)
	env := map[string]string{envRoot: root, envEnrollToken: testEnrollToken}

	r := invoke(env, "acme-agent", "enroll", "-url", srv.URL, "-channel", "testing", "-local-checks=false")
	if r.code != 0 {
		t.Fatalf("got %+v", r)
	}
	if got == nil || got.UpdateChannel != "testing" {
		t.Fatalf("channel not sent: %+v", got)
	}
	cfg, err := config.Load(b.ConfigFile())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Local.LocalChecks {
		t.Error("-local-checks=false not applied")
	}

	// Without the flags: no channel (the portal decides) and the opt-in stays.
	got = nil
	r = invoke(env, "acme-agent", "enroll", "-force", "-url", srv.URL)
	if r.code != 0 {
		t.Fatalf("re-enroll: %+v", r)
	}
	if got.UpdateChannel != "" {
		t.Errorf("channel %q sent without -channel", got.UpdateChannel)
	}
	if cfg, err = config.Load(b.ConfigFile()); err != nil || cfg.Local.LocalChecks {
		t.Errorf("local checks opt-out not kept: %+v, %v", cfg.Local, err)
	}
}

func TestEnrollRejectsUnknownChannel(t *testing.T) {
	root, _ := agentRoot(t)
	_, calls := enrollGateway(t, 0)
	r := invoke(map[string]string{envRoot: root, envEnrollToken: testEnrollToken},
		"acme-agent", "enroll", "-url", "https://agent.example.com", "-channel", "nightly")
	if r.code != 2 || !strings.Contains(r.stderr, "-channel must be one of") || calls.Load() != 0 {
		t.Fatalf("got %+v, %d gateway calls", r, calls.Load())
	}
}

func TestEnrollErrorMessagesAreActionable(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		want   string
	}{
		{409, `{"code":"MACHINE_ID_IN_USE","host":"web02.example.com"}`, `"web02.example.com" already uses this machine-id`},
		{409, `{"code":"MACHINE_ID_IN_USE","host":"web02.example.com"}`, "systemd-machine-id-setup"},
		{403, `{"code":"NOT_ENTITLED"}`, "not enabled for this tenant"},
		{409, `{"code":"LIMIT_REACHED"}`, "server limit is reached"},
		{429, `{"code":"RATE_LIMITED"}`, "too many enrollments"},
		{401, `{"code":"INVALID_TOKEN"}`, "invalid or expired"},
		{403, `nonsense`, "invalid or expired"},
		{500, `{}`, "HTTP 500"},
	} {
		if err := enrollError(tc.status, []byte(tc.body)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("status %d body %s: got %v, want %q", tc.status, tc.body, err, tc.want)
		}
	}
}

func TestEnrollCloneCollisionReachesTheOperator(t *testing.T) {
	root, b := agentRoot(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, `{"code":"MACHINE_ID_IN_USE","host":"web02.example.com"}`)
	}))
	t.Cleanup(srv.Close)
	orig := enrollHTTPClient
	enrollHTTPClient = srv.Client()
	t.Cleanup(func() { enrollHTTPClient = orig })

	r := invoke(map[string]string{envRoot: root, envEnrollToken: testEnrollToken}, "acme-agent", "enroll", "-url", srv.URL)
	if r.code != 1 || !strings.Contains(r.stderr, "looks like a clone") {
		t.Fatalf("got %+v", r)
	}
	if _, err := os.Stat(b.ConfigFile()); !os.IsNotExist(err) {
		t.Errorf("config written after a refused enroll: %v", err)
	}
}
