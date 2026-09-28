package brand

import (
	"errors"
	"strings"
	"testing"
)

func TestFromExecutable(t *testing.T) {
	cases := []struct {
		path    string
		key     string
		wantErr bool
	}{
		{path: "/usr/bin/acme-agent", key: "acme"},
		{path: "acme-agent", key: "acme"},
		{path: "/usr/bin/my-brand2-agent", key: "my-brand2"},
		{path: "/usr/bin/agent", wantErr: true},
		{path: "/usr/bin/acme", wantErr: true},
		{path: "/usr/bin/ac-agent", wantErr: true},    // too short
		{path: "/usr/bin/2acme-agent", wantErr: true}, // must start with a letter
		{path: "/usr/bin/acme--agent", wantErr: true}, // hyphen at the end of the key
		{path: "/usr/bin/Acme-agent", wantErr: true},  // upper case
		{path: "/usr/bin/ac_me-agent", wantErr: true}, // underscore

		{path: "/usr/bin/" + long(24) + "-agent", key: long(24)},
		{path: "/usr/bin/" + long(25) + "-agent", wantErr: true},
	}
	for _, c := range cases {
		b, err := FromExecutable(c.path, "")
		if c.wantErr {
			if err == nil {
				t.Errorf("%s: expected error, got key %q", c.path, b.Key)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: unexpected error %v", c.path, err)
			continue
		}
		if b.Key != c.key {
			t.Errorf("%s: key %q, want %q", c.path, b.Key, c.key)
		}
	}
}

func TestNotBrandedIsDistinguishable(t *testing.T) {
	_, err := FromExecutable("/tmp/go-build123/exe/agent", "")
	if !errors.Is(err, ErrNotBranded) {
		t.Fatalf("want ErrNotBranded, got %v", err)
	}
}

func TestPaths(t *testing.T) {
	b, err := New("acme", "")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"Name":       "acme-agent",
		"Unit":       "acme-agent.service",
		"ConfigDir":  "/etc/acme-agent",
		"ConfigFile": "/etc/acme-agent/agent.conf",
		"StateDir":   "/var/lib/acme-agent",
	}
	got := map[string]string{
		"Name":       b.Name(),
		"Unit":       b.Unit(),
		"ConfigDir":  b.ConfigDir(),
		"ConfigFile": b.ConfigFile(),
		"StateDir":   b.StateDir(),
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

func TestRootPrefix(t *testing.T) {
	b, err := New("acme", "/tmp/scratch")
	if err != nil {
		t.Fatal(err)
	}
	if got := b.ConfigFile(); got != "/tmp/scratch/etc/acme-agent/agent.conf" {
		t.Errorf("ConfigFile = %q", got)
	}
	if got := b.StateDir(); got != "/tmp/scratch/var/lib/acme-agent" {
		t.Errorf("StateDir = %q", got)
	}
}

func long(n int) string {
	s := make([]byte, n)
	for i := range s {
		s[i] = 'a'
	}
	return string(s)
}

func TestKeyLengthCap(t *testing.T) {
	long := "abcdefghij-klmnopqrst-xyz" // 25 chars: one over the cap
	if _, err := New(long, ""); err == nil {
		t.Errorf("25-char key accepted")
	}
	b, err := New(long[:24], "")
	if err != nil {
		t.Fatalf("24-char key rejected: %v", err)
	}
	// Worst case: exactly the 32-char Linux limit for user names.
	if u := b.PollerUser(); u != "_abcdefghij-klmnopqrst-xy-poller" || len(u) != 32 {
		t.Errorf("poller user %q (%d chars)", u, len(u))
	}
}

func TestPollerUserAndAptSource(t *testing.T) {
	b, err := New("acme", "/scratch")
	if err != nil {
		t.Fatal(err)
	}
	if got := b.PollerUser(); got != "_acme-poller" {
		t.Errorf("PollerUser() = %q", got)
	}
	if got := b.AptSourceFile(); got != "/scratch/etc/apt/sources.list.d/acme-agent.list" {
		t.Errorf("AptSourceFile() = %q", got)
	}
}

// windowsBase is only called from paths_windows.go, so this is the only
// place it is exercised on our Linux CI.
func TestWindowsBase(t *testing.T) {
	// The separator is the host's, so the test states the two properties
	// that matter rather than a literal path: the brand directory sits below
	// %ProgramData%, and an unset %ProgramData% still yields an absolute
	// location instead of a relative one.
	got := windowsBase(`C:\ProgramData`, "acme-agent")
	if !strings.HasPrefix(got, `C:\ProgramData`) || !strings.HasSuffix(got, "acme-agent") {
		t.Errorf("got %q, want C:\\ProgramData + separator + acme-agent", got)
	}
	if got := windowsBase("  ", "acme-agent"); !strings.HasPrefix(got, `C:\`) {
		t.Errorf("an empty %%ProgramData%% must fall back to C:\\ProgramData, got %q", got)
	}
}
