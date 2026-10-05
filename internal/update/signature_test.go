package update

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

// testdata/manifest-1.11.0.json(.asc) is a manifest exactly as the release
// pipeline published it, with its detached signature. It proves the compiled-in
// key is the one production signs with — a key mix-up would otherwise only
// show as every Windows host failing its next update.

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name) // #nosec G304 -- fixed test fixtures
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestReleaseKeysLoad(t *testing.T) {
	ring, err := releaseKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(ring) == 0 {
		t.Fatal("no release key compiled in")
	}
}

func TestPublishedManifestVerifies(t *testing.T) {
	ring, err := releaseKeys()
	if err != nil {
		t.Fatal(err)
	}
	man := readFixture(t, "manifest-1.11.0.json")
	sig := readFixture(t, "manifest-1.11.0.json.asc")
	if err := verifyManifestSignature(ring, man, sig); err != nil {
		t.Fatalf("published manifest rejected: %v", err)
	}
	if _, err := parseManifest(man, "1.11.0"); err != nil {
		t.Fatalf("published manifest does not parse: %v", err)
	}
}

func TestTamperedManifestIsRejected(t *testing.T) {
	ring, _ := releaseKeys()
	man := readFixture(t, "manifest-1.11.0.json")
	sig := readFixture(t, "manifest-1.11.0.json.asc")
	evil := bytes.Replace(man, []byte(`"sha256": "ca`), []byte(`"sha256": "cb`), 1)
	if bytes.Equal(evil, man) {
		t.Fatal("fixture changed — adjust the tampering")
	}
	if err := verifyManifestSignature(ring, evil, sig); err == nil {
		t.Fatal("tampered manifest accepted")
	}
}

func TestForeignKeySignatureIsRejected(t *testing.T) {
	ring, _ := releaseKeys()
	man := readFixture(t, "manifest-1.11.0.json")
	if err := verifyManifestSignature(ring, man, signWithNewKey(t, man)); err == nil {
		t.Fatal("signature by an unknown key accepted")
	}
}

func TestMissingOrGarbageSignatureIsRejected(t *testing.T) {
	ring, _ := releaseKeys()
	man := readFixture(t, "manifest-1.11.0.json")
	for _, sig := range [][]byte{nil, []byte("not a signature"), []byte("<html>404</html>")} {
		if err := verifyManifestSignature(ring, man, sig); err == nil {
			t.Fatalf("signature %q accepted", sig)
		}
	}
}

func TestEmptyKeyRingNeverPasses(t *testing.T) {
	man := readFixture(t, "manifest-1.11.0.json")
	sig := readFixture(t, "manifest-1.11.0.json.asc")
	if err := verifyManifestSignature(nil, man, sig); err == nil {
		t.Fatal("empty key ring accepted a signature")
	}
	if _, err := loadKeyRing(fstest.MapFS{}); err == nil {
		t.Fatal("an empty releasekeys/ loaded without error")
	}
}

func TestSignatureURL(t *testing.T) {
	got := signatureURL(manifestURL("https://apt.example.com/", "1.7.0"))
	if got != "https://apt.example.com/windows/1.7.0.json.asc" {
		t.Fatalf("signatureURL = %s", got)
	}
}

// signWithNewKey signs data with a freshly generated key that is not in the
// release key ring — what an attacker controlling the download host can do.
func signWithNewKey(t *testing.T, data []byte) []byte {
	t.Helper()
	e, err := openpgp.NewEntity("attacker", "", "attacker@example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	w, err := armor.Encode(&out, "PGP SIGNATURE", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := openpgp.DetachSign(w, e, bytes.NewReader(data), nil); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "BEGIN PGP SIGNATURE") {
		t.Fatal("no armored signature produced")
	}
	return out.Bytes()
}
