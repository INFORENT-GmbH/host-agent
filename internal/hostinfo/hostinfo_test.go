package hostinfo

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestGather(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "etc/machine-id", "4f1c2d3e4b5a69788796a5b4c3d2e1f0\n")
	writeFile(t, root, "etc/os-release", "# comment\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"13\"\nPRETTY_NAME='Debian 13'\n")
	info, err := Gather(root)
	if err != nil {
		t.Fatal(err)
	}
	if info.MachineID != "4f1c2d3e4b5a69788796a5b4c3d2e1f0" {
		t.Errorf("machine id %q", info.MachineID)
	}
	if info.OS.Name != "Debian GNU/Linux" || info.OS.Version != "13" {
		t.Errorf("os %+v", info.OS)
	}
	if info.Hostname == "" || info.OS.Arch == "" {
		t.Errorf("hostname/arch empty: %+v", info)
	}
}

func TestMachineIDFallbackAndValidation(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "etc/machine-id", "uninitialized\n")
	writeFile(t, root, "var/lib/dbus/machine-id", "00112233445566778899aabbccddeeff")
	id, err := machineID(root)
	if err != nil || id != "00112233445566778899aabbccddeeff" {
		t.Fatalf("got %q, %v", id, err)
	}
	if _, err := machineID(t.TempDir()); err == nil {
		t.Fatal("expected error without machine-id")
	}
}

func TestOSReleaseFallbackPath(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "usr/lib/os-release", "NAME=Ubuntu\nVERSION_ID=24.04\n")
	osr := osRelease(root)
	if osr["NAME"] != "Ubuntu" || osr["VERSION_ID"] != "24.04" {
		t.Fatalf("got %v", osr)
	}
}

// The Windows branch cannot run on our CI, so its pure parts are tested
// here: without this, a wrong product name or a malformed machine id would
// only show up on a customer's server.
func TestNormalizeMachineID(t *testing.T) {
	for _, tc := range []struct {
		name, in, want string
		ok             bool
	}{
		{name: "systemd machine-id", in: "1f0c2d3e4a5b6c7d8e9f0a1b2c3d4e5f\n", want: "1f0c2d3e4a5b6c7d8e9f0a1b2c3d4e5f", ok: true},
		{name: "windows MachineGuid", in: "1F0C2D3E-4A5B-6C7D-8E9F-0A1B2C3D4E5F", want: "1f0c2d3e4a5b6c7d8e9f0a1b2c3d4e5f", ok: true},
		{name: "too short", in: "1f0c2d3e", ok: false},
		{name: "not hex", in: "zzzc2d3e4a5b6c7d8e9f0a1b2c3d4e5f", ok: false},
		{name: "empty", in: "", ok: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := normalizeMachineID(tc.in)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if ok && got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestWindowsOSName(t *testing.T) {
	for _, tc := range []struct {
		name, product, display, release string
		build                           uint32
		wantName, wantVersion           string
	}{
		{
			name:    "server 2019 has neither DisplayVersion nor ReleaseId",
			product: "Windows Server 2019 Standard", build: 17763,
			wantName: "Windows Server 2019 Standard", wantVersion: "17763",
		},
		{
			name:    "windows 11 still calls itself 10 in the registry",
			product: "Windows 10 Pro", display: "23H2", build: 22631,
			wantName: "Windows 11 Pro", wantVersion: "23H2",
		},
		{
			name:    "windows 10 stays windows 10",
			product: "Windows 10 Pro", display: "22H2", build: 19045,
			wantName: "Windows 10 Pro", wantVersion: "22H2",
		},
		{
			name:    "older builds only have ReleaseId",
			product: "Windows 10 Enterprise", release: "1809", build: 17763,
			wantName: "Windows 10 Enterprise", wantVersion: "1809",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name, version := windowsOSName(tc.product, tc.display, tc.release, tc.build)
			if name != tc.wantName || version != tc.wantVersion {
				t.Fatalf("got (%q, %q), want (%q, %q)", name, version, tc.wantName, tc.wantVersion)
			}
		})
	}
}

func TestWindowsKernel(t *testing.T) {
	if got := windowsKernel(10, 0, 17763); got != "10.0.17763" {
		t.Fatalf("got %q", got)
	}
}
