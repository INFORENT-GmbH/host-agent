package snmp

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/gosnmp/gosnmp"
)

// A test session that replays the very files the simulator serves
// (snmpsim/data/<device>/public.snmprec). Testing against those instead of
// hand-written varbinds means a change to the simulated devices shows up here
// — and it keeps the whole suite offline: no container, no UDP socket.
//
// The `<tag>:numeric` variation is resolved the way snmpsim does at runtime:
// value = initial + rate × seconds. `advance` moves the clock so a second poll
// sees counters that have really moved on.
type recording struct {
	rows    []recRow
	seconds float64
}

type recRow struct {
	oid     string
	tag     string
	value   string
	initial float64
	rate    float64
	numeric bool
}

func loadRecording(t *testing.T, device string) *recording {
	t.Helper()
	// The recordings live next to the simulator in the portal repository; the
	// public mirror carries a copy in testdata/snmpsim.
	path := filepath.Join("testdata", "snmpsim", device, "public.snmprec")
	if _, err := os.Stat(path); err != nil {
		path = filepath.Join("..", "..", "..", "..", "snmpsim", "data", device, "public.snmprec")
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- fixed test fixture path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	rec := &recording{}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 3)
		if len(parts) != 3 {
			t.Fatalf("%s: malformed line %q", path, line)
		}
		row := recRow{oid: parts[0], tag: parts[1], value: parts[2]}
		if tag, opts, ok := strings.Cut(parts[1], ":"); ok {
			if opts != "numeric" {
				t.Fatalf("%s: unsupported variation %q", path, opts)
			}
			row.tag, row.numeric = tag, true
			for _, kv := range strings.Split(parts[2], ",") {
				k, v, _ := strings.Cut(kv, "=")
				n, _ := strconv.ParseFloat(v, 64)
				switch k {
				case "initial":
					row.initial = n
				case "rate":
					row.rate = n
				case "min":
					if row.initial == 0 {
						row.initial = n
					}
				}
			}
		}
		rec.rows = append(rec.rows, row)
	}
	sort.Slice(rec.rows, func(i, j int) bool { return oidLess(rec.rows[i].oid, rec.rows[j].oid) })
	return rec
}

// advance simulates time passing between two polls.
func (r *recording) advance(seconds float64) { r.seconds += seconds }

func oidLess(a, b string) bool {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		x, _ := strconv.Atoi(as[i])
		y, _ := strconv.Atoi(bs[i])
		if x != y {
			return x < y
		}
	}
	return len(as) < len(bs)
}

func (r *recording) pdu(row recRow) gosnmp.SnmpPDU {
	if row.numeric {
		v := uint64(row.initial + row.rate*r.seconds)
		switch row.tag {
		case "65":
			return gosnmp.SnmpPDU{Name: "." + row.oid, Type: gosnmp.Counter32, Value: uint(v % (1 << 32))}
		case "66":
			return gosnmp.SnmpPDU{Name: "." + row.oid, Type: gosnmp.Gauge32, Value: uint(v % (1 << 32))}
		case "67":
			return gosnmp.SnmpPDU{Name: "." + row.oid, Type: gosnmp.TimeTicks, Value: uint32(v % (1 << 32))}
		case "70":
			return gosnmp.SnmpPDU{Name: "." + row.oid, Type: gosnmp.Counter64, Value: v}
		default:
			return gosnmp.SnmpPDU{Name: "." + row.oid, Type: gosnmp.Integer, Value: int(v % (1 << 31))}
		}
	}
	switch row.tag {
	case "2":
		n, _ := strconv.Atoi(row.value)
		return gosnmp.SnmpPDU{Name: "." + row.oid, Type: gosnmp.Integer, Value: n}
	case "4":
		return gosnmp.SnmpPDU{Name: "." + row.oid, Type: gosnmp.OctetString, Value: []byte(row.value)}
	case "4x":
		b, _ := hex.DecodeString(row.value)
		return gosnmp.SnmpPDU{Name: "." + row.oid, Type: gosnmp.OctetString, Value: b}
	case "6":
		return gosnmp.SnmpPDU{Name: "." + row.oid, Type: gosnmp.ObjectIdentifier, Value: "." + row.value}
	case "65":
		n, _ := strconv.ParseUint(row.value, 10, 32)
		return gosnmp.SnmpPDU{Name: "." + row.oid, Type: gosnmp.Counter32, Value: uint(n)}
	case "66":
		n, _ := strconv.ParseUint(row.value, 10, 32)
		return gosnmp.SnmpPDU{Name: "." + row.oid, Type: gosnmp.Gauge32, Value: uint(n)}
	case "67":
		n, _ := strconv.ParseUint(row.value, 10, 32)
		return gosnmp.SnmpPDU{Name: "." + row.oid, Type: gosnmp.TimeTicks, Value: uint32(n)}
	case "70":
		n, _ := strconv.ParseUint(row.value, 10, 64)
		return gosnmp.SnmpPDU{Name: "." + row.oid, Type: gosnmp.Counter64, Value: n}
	default:
		return gosnmp.SnmpPDU{Name: "." + row.oid, Type: gosnmp.OctetString, Value: []byte(row.value)}
	}
}

func (r *recording) Get(_ context.Context, oids []string) ([]gosnmp.SnmpPDU, error) {
	out := make([]gosnmp.SnmpPDU, 0, len(oids))
	for _, want := range oids {
		want = strings.TrimPrefix(want, ".")
		found := false
		for _, row := range r.rows {
			if row.oid == want {
				out = append(out, r.pdu(row))
				found = true
				break
			}
		}
		if !found {
			// A real agent answers a missing instance, it does not fail the
			// whole request — the collectors must cope with that.
			out = append(out, gosnmp.SnmpPDU{Name: "." + want, Type: gosnmp.NoSuchInstance})
		}
	}
	return out, nil
}

func (r *recording) Walk(_ context.Context, root string) ([]gosnmp.SnmpPDU, error) {
	prefix := strings.TrimPrefix(root, ".") + "."
	var out []gosnmp.SnmpPDU
	for _, row := range r.rows {
		if strings.HasPrefix(row.oid, prefix) {
			out = append(out, r.pdu(row))
		}
	}
	return out, nil
}

func (r *recording) Close() error { return nil }
