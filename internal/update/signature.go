package update

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sync"

	"github.com/ProtonMail/go-crypto/openpgp"
)

// releaseKeyFiles are the armored public keys whose detached signature the
// Windows self-update demands on every manifest. They are compiled in on
// purpose: the manifest, its signature and the MSI all come from the same
// host, so a key fetched from there too would only prove that the host agrees
// with itself. With the key in the binary, whoever controls the download host
// (or the path to it) still cannot get an installer of their choosing run as
// LocalSystem — they would need the private key, which never leaves the
// portal's release pipeline.
//
// It is the same key that signs the apt repositories, so Linux and Windows
// trust one root. Every file in releasekeys/ is trusted; a key rotation ships
// the new key here in an agent release BEFORE the pipeline signs with it,
// and drops the old one only once no agent depends on it. A build of this
// repository for another vendor replaces the directory with its own keys.
//
//go:embed releasekeys/*.asc
var releaseKeyFiles embed.FS

// releaseKeys parses the embedded keys once. An empty or unreadable set is an
// error, never "trust nothing and accept everything".
var releaseKeys = sync.OnceValues(func() (openpgp.EntityList, error) {
	return loadKeyRing(releaseKeyFiles)
})

func loadKeyRing(fsys fs.FS) (openpgp.EntityList, error) {
	names, err := fs.Glob(fsys, "releasekeys/*.asc")
	if err != nil {
		return nil, err
	}
	var ring openpgp.EntityList
	for _, name := range names {
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, err
		}
		keys, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("release key %s: %w", name, err)
		}
		ring = append(ring, keys...)
	}
	if len(ring) == 0 {
		return nil, errors.New("no release signing key compiled in")
	}
	return ring, nil
}

// signatureURL is where the pipeline puts the detached, armored signature of
// a manifest: right next to it, with ".asc" appended.
func signatureURL(manifestURL string) string { return manifestURL + ".asc" }

// verifyManifestSignature checks that sig is a valid detached signature over
// exactly these manifest bytes by one of the keys in ring. It runs before the
// manifest is parsed: nothing an unsigned manifest says is acted upon.
func verifyManifestSignature(ring openpgp.EntityList, manifest, sig []byte) error {
	if len(ring) == 0 {
		return errors.New("no release signing key compiled in")
	}
	if _, err := openpgp.CheckArmoredDetachedSignature(ring, bytes.NewReader(manifest), bytes.NewReader(sig), nil); err != nil {
		return fmt.Errorf("manifest signature does not verify: %w", err)
	}
	return nil
}
