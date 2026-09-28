package snmp

import (
	"fmt"
	"strings"

	"github.com/gosnmp/gosnmp"
)

// number converts the numeric SNMP types to float64. Counters are unsigned on
// the wire; gosnmp hands 32-bit ones over as uint and 64-bit ones as uint64.
// Anything that is not a number (or an absent instance) yields ok=false — a
// missing value must never turn into a silent zero, because zero reads as
// "no traffic" or "no memory used" downstream.
func number(pdu gosnmp.SnmpPDU) (float64, bool) {
	switch pdu.Type {
	case gosnmp.Integer, gosnmp.Counter32, gosnmp.Gauge32, gosnmp.TimeTicks, gosnmp.Uinteger32, gosnmp.Counter64:
		return float64(gosnmp.ToBigInt(pdu.Value).Int64()), true
	case gosnmp.OpaqueFloat:
		if v, ok := pdu.Value.(float32); ok {
			return float64(v), true
		}
	case gosnmp.OpaqueDouble:
		if v, ok := pdu.Value.(float64); ok {
			return v, true
		}
	}
	return 0, false
}

// text renders the string-ish types. Devices pad interface names and
// descriptions with NULs and trailing blanks; both would end up in a service
// name, so they are cut here once.
func text(pdu gosnmp.SnmpPDU) string {
	switch v := pdu.Value.(type) {
	case []byte:
		return strings.TrimRight(strings.TrimRight(string(v), "\x00"), " \t\r\n")
	case string:
		return strings.TrimSpace(v)
	case nil:
		return ""
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}

// suffix returns the part of oid below root ("1.3.6.1.2.1.2.2.1.8.7" under
// ".1.3.6.1.2.1.2.2.1.8" is "7"). Leading dots on either side do not matter.
func suffix(oid, root string) (string, bool) {
	o, r := strings.TrimPrefix(oid, "."), strings.TrimPrefix(root, ".")
	if !strings.HasPrefix(o, r+".") {
		return "", false
	}
	return o[len(r)+1:], true
}

// column indexes a walked table column by its instance suffix.
func column(pdus []gosnmp.SnmpPDU, root string) map[string]gosnmp.SnmpPDU {
	out := make(map[string]gosnmp.SnmpPDU, len(pdus))
	for _, p := range pdus {
		if idx, ok := suffix(p.Name, root); ok {
			out[idx] = p
		}
	}
	return out
}

// numbers reduces a walked column to the numeric values it carries, keyed by
// instance suffix.
func numbers(pdus []gosnmp.SnmpPDU, root string) map[string]float64 {
	out := make(map[string]float64)
	for idx, p := range column(pdus, root) {
		if v, ok := number(p); ok {
			out[idx] = v
		}
	}
	return out
}

// texts is the string counterpart of numbers.
func texts(pdus []gosnmp.SnmpPDU, root string) map[string]string {
	out := make(map[string]string)
	for idx, p := range column(pdus, root) {
		out[idx] = text(p)
	}
	return out
}
