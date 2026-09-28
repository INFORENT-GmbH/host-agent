package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent.conf")
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	// WriteFile honours the umask; force the mode under test.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadMissing(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "agent.conf"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("want ErrNotExist, got %v", err)
	}
}

func TestLoadRejectsLoosePermissions(t *testing.T) {
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o660} {
		path := write(t, "", mode)
		if _, err := Load(path); !errors.Is(err, ErrInsecure) {
			t.Errorf("mode %04o: want ErrInsecure, got %v", mode, err)
		}
	}
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(write(t, "", 0o600))
	if err != nil {
		t.Fatal(err)
	}
	if cfg != Default() {
		t.Errorf("empty file = %+v, want defaults %+v", cfg, Default())
	}
	if cfg.Enrolled() {
		t.Error("empty config must not count as enrolled")
	}
	if cfg.Local.Satellite {
		t.Error("satellite must default to off")
	}
}

func TestLoadRejectsUnknownKeys(t *testing.T) {
	path := write(t, "[local]\nlocal_check = false\n", 0o600)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "local.local_check") {
		t.Fatalf("want unknown-key error naming local.local_check, got %v", err)
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		ok   bool
	}{
		{"defaults", Default(), true},
		{"https", with(Default(), "https://agent.example.com", "tok"), true},
		{"wss", with(Default(), "wss://agent.example.com/v1/ws", "tok"), false},
		{"plain ws", with(Default(), "ws://agent.example.com", "tok"), false},
		{"http", with(Default(), "http://agent.example.com", "tok"), false},
		{"no host", with(Default(), "https:///v1/ws", "tok"), false},
		{"url without token", with(Default(), "https://agent.example.com", ""), false},
		{"token without url", with(Default(), "", "tok"), false},
		{"bad level", func() Config { c := Default(); c.Log.Level = "loud"; return c }(), false},
	}
	for _, c := range cases {
		err := c.cfg.Validate()
		if c.ok && err != nil {
			t.Errorf("%s: unexpected error %v", c.name, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%s: expected error", c.name)
		}
	}
}

func TestSaveRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "etc", "acme-agent", "agent.conf")
	cfg := with(Default(), "https://agent.example.com", "secret-token")
	cfg.Local.Satellite = true
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode %04o, want 0600", perm)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != cfg {
		t.Errorf("round trip = %+v, want %+v", got, cfg)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("temp files left behind: %v", entries)
	}
}

func TestSaveRejectsInvalid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.conf")
	if err := Save(path, with(Default(), "http://x", "tok")); err == nil {
		t.Fatal("expected validation error")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("invalid config must not be written, stat err = %v", err)
	}
}

func with(c Config, url, token string) Config {
	c.Server.URL = url
	c.Server.Token = token
	return c
}
