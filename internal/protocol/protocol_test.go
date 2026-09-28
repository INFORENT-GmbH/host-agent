package protocol

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixtures are the cross-language contract: the gateway's TypeScript
// schema must accept every valid/ file and reject every invalid/ file.

type decoder func([]byte) (Envelope, Message, error)

var directions = map[string]decoder{
	"agent":   DecodeFromAgent,
	"gateway": DecodeFromGateway,
}

func fixtures(t *testing.T, kind, dir string) map[string][]byte {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("testdata", kind, dir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatalf("no fixtures in testdata/%s/%s", kind, dir)
	}
	out := make(map[string][]byte, len(paths))
	for _, p := range paths {
		b, err := os.ReadFile(p) // #nosec G304 -- test fixtures
		if err != nil {
			t.Fatal(err)
		}
		out[p] = b
	}
	return out
}

func TestValidFixtures(t *testing.T) {
	for dir, decode := range directions {
		for path, b := range fixtures(t, "valid", dir) {
			env, msg, err := decode(b)
			if err != nil {
				t.Errorf("%s: %v", path, err)
				continue
			}
			// Round trip: encoding the decoded message and decoding it again
			// must yield the same JSON.
			again, err := Encode(env.Type, env.Seq, msg)
			if err != nil {
				t.Errorf("%s: re-encode: %v", path, err)
				continue
			}
			_, msg2, err := decode(again)
			if err != nil {
				t.Errorf("%s: decode re-encoded: %v", path, err)
				continue
			}
			first, _ := json.Marshal(msg, json.Deterministic(true))
			second, _ := json.Marshal(msg2, json.Deterministic(true))
			if !bytes.Equal(first, second) {
				t.Errorf("%s: round trip differs:\n%s\n%s", path, first, second)
			}
		}
	}
}

func TestInvalidFixtures(t *testing.T) {
	for dir, decode := range directions {
		for path, b := range fixtures(t, "invalid", dir) {
			if _, _, err := decode(b); err == nil {
				t.Errorf("%s: accepted, want rejection", path)
			}
		}
	}
}

// Enroll bodies are plain JSON; the file name says which side sent it.
func TestEnrollFixtures(t *testing.T) {
	decode := func(path string, b []byte) error {
		if strings.HasPrefix(filepath.Base(path), "request") {
			_, err := DecodeEnrollRequest(b)
			return err
		}
		_, err := DecodeEnrollResponse(b)
		return err
	}
	for path, b := range fixtures(t, "valid", "enroll") {
		if err := decode(path, b); err != nil {
			t.Errorf("%s: %v", path, err)
		}
	}
	for path, b := range fixtures(t, "invalid", "enroll") {
		if err := decode(path, b); err == nil {
			t.Errorf("%s: accepted, want rejection", path)
		}
	}
}

func TestUnknownTypeIsDistinguishable(t *testing.T) {
	_, _, err := DecodeFromGateway([]byte(`{"type":"exec","data":{}}`))
	if !errors.Is(err, ErrUnknownType) {
		t.Fatalf("want ErrUnknownType, got %v", err)
	}
}

func TestTooLarge(t *testing.T) {
	big := make([]byte, MaxMessageBytes+1)
	if _, _, err := DecodeFromAgent(big); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
}

func TestEncodeRejectsNonFinite(t *testing.T) {
	for _, v := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		m := &Metrics{Time: 1, Series: []Sample{{Name: "load.1", Value: v}}}
		if _, err := Encode(TypeMetrics, 1, m); err == nil {
			t.Errorf("value %v accepted", v)
		}
	}
}

func TestEncodeValidates(t *testing.T) {
	if _, err := Encode(TypeUpdate, 0, &Update{Version: "1.0.0 && reboot"}); err == nil {
		t.Fatal("invalid update encoded")
	}
}
