//go:build linux

package collect

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestScanProcDir(t *testing.T) {
	root := t.TempDir()
	write := func(pid, status string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(root, pid), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, pid, "status"), []byte(status), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("1", "Name:\tsystemd\nVmRSS:\t   12000 kB\nRssAnon:\t    4000 kB\nRssFile:\t    8000 kB\n")
	write("200", "Name:\tphp-fpm8.2\nRssAnon:\t   10000 kB\n")
	write("201", "Name:\tphp-fpm8.2\nRssAnon:\t   30000 kB\n")
	write("2", "Name:\tkthreadd\nThreads:\t1\n") // kernel thread: no RssAnon
	write("self", "Name:\tnot-a-pid\nRssAnon:\t1 kB\n")
	write("300", "Name:\tbroken\nRssAnon:\tlots kB\n")
	write("500", "Name:\tdefunct-child\nState:\tZ (zombie)\n")
	if err := os.MkdirAll(filepath.Join(root, "400"), 0o750); err != nil { // exited mid-scan
		t.Fatal(err)
	}

	got, err := scanProcDir(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]procUsage{
		"systemd":    {Bytes: 4000 * 1024, Count: 1},
		"php-fpm8.2": {Bytes: 40000 * 1024, Count: 2},
	}
	if len(got.ByName) != len(want) {
		t.Fatalf("got %v", got.ByName)
	}
	for k, v := range want {
		if got.ByName[k] != v {
			t.Errorf("%s: got %+v want %+v", k, got.ByName[k], v)
		}
	}
	// systemd, 2× php-fpm, kthreadd, broken, zombie — not "self", not the empty dir.
	if got.Total != 6 || got.Zombies != 1 {
		t.Errorf("total %d zombies %d", got.Total, got.Zombies)
	}
}

func TestScanProcessesLive(t *testing.T) {
	got, err := scanProcesses(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// The test binary itself has private memory.
	if len(got.ByName) == 0 || got.Total == 0 {
		t.Fatal("no processes found")
	}
}
