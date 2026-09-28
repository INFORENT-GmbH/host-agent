package update

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"strings"
	"testing"
)

// The Windows self-update's parsing and verification cannot run on our CI
// (no Windows runner), so they are exercised here — they decide what the
// agent downloads and installs as SYSTEM, so they must not be untested.

func goodManifest(body []byte) manifest {
	sum := sha256.Sum256(body)
	return manifest{
		Version: "1.7.0", OS: "windows", Arch: "amd64",
		File: "acme-agent-1.7.0.msi", SHA256: hex.EncodeToString(sum[:]), Size: int64(len(body)),
	}
}

func marshal(t *testing.T, m manifest) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseManifestAcceptsAMatchingManifest(t *testing.T) {
	m := goodManifest([]byte("MSI"))
	got, err := parseManifest(marshal(t, m), "1.7.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.File != "acme-agent-1.7.0.msi" {
		t.Errorf("file = %q", got.File)
	}
}

func TestParseManifestRejectsMismatches(t *testing.T) {
	base := goodManifest([]byte("MSI"))
	for name, mutate := range map[string]func(*manifest){
		"wrong version":  func(m *manifest) { m.Version = "1.8.0" },
		"wrong os":       func(m *manifest) { m.OS = "linux" },
		"wrong arch":     func(m *manifest) { m.Arch = "arm64" },
		"bad checksum":   func(m *manifest) { m.SHA256 = "not-hex" },
		"short checksum": func(m *manifest) { m.SHA256 = "abcd" },
		// A file name with a path could redirect the download anywhere.
		"path in file":  func(m *manifest) { m.File = "../../evil.msi" },
		"absolute file": func(m *manifest) { m.File = "/etc/passwd" },
		"windows path":  func(m *manifest) { m.File = `C:\evil.msi` },
		"empty file":    func(m *manifest) { m.File = "" },
	} {
		t.Run(name, func(t *testing.T) {
			m := base
			mutate(&m)
			if _, err := parseManifest(marshal(t, m), "1.7.0"); err == nil {
				t.Fatalf("expected rejection for %s", name)
			}
		})
	}
}

func TestParseManifestRejectsGarbage(t *testing.T) {
	if _, err := parseManifest([]byte("{not json"), "1.7.0"); err == nil {
		t.Fatal("expected an error for invalid JSON")
	}
}

func TestVerifyMSI(t *testing.T) {
	body := []byte("the installer bytes")
	m := goodManifest(body)
	if err := verifyMSI(body, m); err != nil {
		t.Fatalf("a matching body must verify: %v", err)
	}
	// A checksum stated in upper case must still match.
	m.SHA256 = strings.ToUpper(m.SHA256)
	if err := verifyMSI(body, m); err != nil {
		t.Fatalf("checksum comparison must be case-insensitive: %v", err)
	}
	// One flipped byte fails, and a truncated download fails on size first.
	m = goodManifest(body)
	if err := verifyMSI(append([]byte(nil), append(body, '!')...), m); err == nil {
		t.Fatal("a longer body must fail on size")
	}
	tampered := append([]byte(nil), body...)
	tampered[0] ^= 0xff
	if err := verifyMSI(tampered, m); err == nil {
		t.Fatal("a tampered body must fail on checksum")
	}
}

func TestURLsAndPackageBase(t *testing.T) {
	if got := manifestURL("https://apt.acme.example/", "1.7.0"); got != "https://apt.acme.example/windows/1.7.0.json" {
		t.Errorf("manifestURL = %q", got)
	}
	if got := msiURL("https://apt.acme.example", manifest{File: "acme-agent-1.7.0.msi"}); got != "https://apt.acme.example/windows/acme-agent-1.7.0.msi" {
		t.Errorf("msiURL = %q", got)
	}
	for base, ok := range map[string]bool{
		"https://apt.acme.example": true,
		"http://apt.acme.example":  false, // never a signed installer over http
		"ftp://apt.acme.example":   false,
		"apt.acme.example":         false,
		"":                         false,
	} {
		if validPackageBase(base) != ok {
			t.Errorf("validPackageBase(%q) = %v, want %v", base, !ok, ok)
		}
	}
}

func TestIsDowngrade(t *testing.T) {
	for _, tc := range []struct {
		current, target string
		want            bool
	}{
		{"1.7.0", "1.8.0", false},
		{"1.7.0", "1.7.0", false},
		{"1.8.0", "1.7.0", true},
		{"2.0.0", "1.99.99", true},
		{"1.7.1", "1.7.0", true},
		{"1.10.0", "1.9.0", true}, // numeric, not lexical
		{"1.9.0", "1.10.0", false},
		// A pre-release suffix must not flip the verdict between releases.
		{"1.7.0", "1.7.0-rc.1", false},
		// "dev" and anything unparsable: do not claim a downgrade, let the
		// installer speak for itself.
		{"dev", "1.7.0", false},
		{"1.7.0", "nonsense", false},
	} {
		if got := isDowngrade(tc.current, tc.target); got != tc.want {
			t.Errorf("isDowngrade(%q, %q) = %v, want %v", tc.current, tc.target, got, tc.want)
		}
	}
}
