package update

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// manifest is one entry of <packageBase>/windows/<version>.json, as the
// portal's release pipeline publishes it. It names
// the MSI and its SHA-256; the agent trusts it only after its detached
// signature verified against the compiled-in release keys (signature.go), and
// it downloads exactly this file and no other.
//
// This parsing and the checks around it live in an untagged file so they run
// in the Linux tests too.
type manifest struct {
	Version string `json:"version"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	File    string `json:"file"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
}

var sha256Hex = func(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// manifestURL is <base>/windows/<version>.json. The version was validated
// against the protocol pattern before it reaches here, so it cannot inject a
// path; base is checked for a trailing scheme once at enroll.
func manifestURL(base, version string) string {
	return strings.TrimRight(base, "/") + "/windows/" + version + ".json"
}

// parseManifest reads the JSON and rejects anything that does not match the
// version the gateway asked for: a manifest for another version, another OS,
// another arch, or a malformed checksum is a mismatch, not something to act
// on. The file name must be a bare name — a manifest that pointed at "../.."
// or an absolute URL could otherwise make the agent fetch from anywhere.
func parseManifest(data []byte, wantVersion string) (manifest, error) {
	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return manifest{}, fmt.Errorf("manifest is not valid JSON: %w", err)
	}
	if m.Version != wantVersion {
		return manifest{}, fmt.Errorf("manifest is for %q, expected %q", m.Version, wantVersion)
	}
	if m.OS != "windows" || m.Arch != "amd64" {
		return manifest{}, fmt.Errorf("manifest is for %s/%s, expected windows/amd64", m.OS, m.Arch)
	}
	if !sha256Hex(strings.ToLower(m.SHA256)) {
		return manifest{}, errors.New("manifest sha256 is not 64 hex digits")
	}
	if m.File == "" || strings.ContainsAny(m.File, "/\\") || m.File != cleanBase(m.File) {
		return manifest{}, fmt.Errorf("manifest file name %q is not a bare file name", m.File)
	}
	return m, nil
}

// cleanBase returns the last path element, so a check File==cleanBase(File)
// rejects any name that carries a directory.
func cleanBase(name string) string {
	if i := strings.LastIndexAny(name, "/\\"); i >= 0 {
		return name[i+1:]
	}
	return name
}

// msiURL is the download URL of the MSI named by the manifest.
func msiURL(base string, m manifest) string {
	return strings.TrimRight(base, "/") + "/windows/" + m.File
}

// verifyMSI checks the downloaded bytes against the manifest's size and
// checksum. Size first: a truncated download is the common case and a cheaper,
// clearer failure than a hash mismatch.
func verifyMSI(body []byte, m manifest) error {
	if int64(len(body)) != m.Size {
		return fmt.Errorf("downloaded %d bytes, manifest says %d", len(body), m.Size)
	}
	sum := sha256.Sum256(body)
	if got := hex.EncodeToString(sum[:]); !strings.EqualFold(got, m.SHA256) {
		return fmt.Errorf("sha256 mismatch: got %s, manifest says %s", got, m.SHA256)
	}
	return nil
}

// validPackageBase reports whether the configured download base is a plain
// https URL — the self-update must never fetch a signed installer over http.
func validPackageBase(base string) bool {
	if base == "" {
		return false
	}
	u, err := url.Parse(base)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

// isDowngrade reports whether target is older than current. Windows Installer
// refuses to install an older version over a newer one (the MSI carries that
// rule as a LaunchCondition), so the agent recognises the case and says what
// to do instead of passing a bare msiexec error code up. The Linux path has no
// such limit — apt installs an exact version in either direction, which is why
// a withdrawal is just a republished snapshot there.
//
// The comparison only has to order the numeric triple: a pre-release suffix
// never decides between two different releases of ours, and treating
// "1.7.0-rc.1" and "1.7.0" as equal here errs towards attempting the install,
// which then fails with the installer's own message.
func isDowngrade(current, target string) bool {
	c, okC := versionTriple(current)
	t, okT := versionTriple(target)
	if !okC || !okT {
		return false
	}
	for i := range 3 {
		if t[i] != c[i] {
			return t[i] < c[i]
		}
	}
	return false
}

func versionTriple(v string) ([3]int, bool) {
	var out [3]int
	parts := strings.SplitN(strings.SplitN(v, "-", 2)[0], ".", 4)
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}
