package snmp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

// Identity is what one poll learned about the device itself. The satellite
// passes it up so the portal can show the model and remember the vendor branch
// it took (`host_sources.sys_object_id`, `.vendor`).
type Identity struct {
	Name        string
	Description string
	ObjectID    string
	Vendor      string
	Location    string
	Contact     string
}

// Result is one poll of one device, in exactly the shapes the agent already
// sends for a local host.
type Result struct {
	Identity  Identity
	Checks    []protocol.CheckResult
	Metrics   []protocol.Sample
	Discovery []protocol.DiscoveredItem
}

// Poller keeps what a single device's next poll needs: the previous counter
// readings, because SNMP reports totals and the portal wants rates. It is not
// safe for concurrent use — one poller per source, which is how the satellite
// schedules them.
type Poller struct {
	prev   map[string]float64
	prevAt time.Time
}

// NewPoller returns a poller with no history: the first poll of a device
// reports states and gauges but no rates, exactly like the agent's first tick.
func NewPoller() *Poller { return &Poller{} }

// Poll reads the device once. A failure to reach the device is returned as an
// error (the satellite turns that into the source's `last_error`); a MIB the
// device does not implement is simply absent from the result — most devices
// answer only a part of what is asked here.
func (p *Poller) Poll(ctx context.Context, s Session, now time.Time) (Result, error) {
	var res Result

	sys, err := s.Get(ctx, []string{oidSysDescr, oidSysObjectID, oidSysUpTime, oidSysContact, oidSysName, oidSysLocation})
	if err != nil {
		return res, fmt.Errorf("system group: %w", err)
	}
	byOID := map[string]gosnmp.SnmpPDU{}
	for _, pdu := range sys {
		byOID[strings.TrimPrefix(pdu.Name, ".")] = pdu
	}
	res.Identity = Identity{
		Name:        text(byOID[oidSysName]),
		Description: text(byOID[oidSysDescr]),
		ObjectID:    strings.TrimPrefix(text(byOID[oidSysObjectID]), "."),
		Location:    text(byOID[oidSysLocation]),
		Contact:     text(byOID[oidSysContact]),
	}
	res.Identity.Vendor = vendorOf(res.Identity.ObjectID, res.Identity.Description)

	// sysUpTime counts hundredths of a second since the agent on the device
	// started — after ~497 days it wraps, so a small value is not proof of a
	// reboot. The check reports the number; judging it is the server's job.
	if ticks, ok := number(byOID[oidSysUpTime]); ok {
		seconds := ticks / 100
		res.Checks = append(res.Checks, protocol.CheckResult{
			Plugin: "uptime", Values: map[string]float64{"uptime_seconds": seconds},
		})
		res.Metrics = append(res.Metrics, protocol.Sample{Name: "system.uptime_seconds", Value: seconds})
		res.Discovery = append(res.Discovery, protocol.DiscoveredItem{Plugin: "uptime", Description: "Uptime"})
	}

	p.interfaces(ctx, s, now, &res)
	p.resources(ctx, s, &res)
	p.sensors(ctx, s, &res)

	p.prevAt = now
	return res, nil
}

// interfaces turns ifTable/ifXTable into one `if` service per port — the same
// plugin, item and value names the local agent reports, so the existing
// judgement and the existing graphs apply unchanged.
func (p *Poller) interfaces(ctx context.Context, s Session, now time.Time, res *Result) {
	base, err := s.Walk(ctx, oidIfTable)
	if err != nil {
		return
	}
	ext, _ := s.Walk(ctx, oidIfXTable) // ifXTable is optional (old devices)

	names := texts(ext, oidIfName)
	descr := texts(base, oidIfDescr)
	alias := texts(ext, oidIfAlias)
	ifType := numbers(base, oidIfType)
	admin := numbers(base, oidIfAdminStatus)
	oper := numbers(base, oidIfOperStatus)
	speed := numbers(base, oidIfSpeed)
	highSpeed := numbers(ext, oidIfHighSpeed)

	elapsed := now.Sub(p.prevAt).Seconds()
	next := make(map[string]float64, len(oper)*6)

	for idx := range oper {
		name := names[idx]
		if name == "" {
			name = descr[idx]
		}
		if name == "" {
			continue
		}
		// Only the loopback (ifType 24) is dropped: it has no link to watch and
		// its counters are the device talking to itself. VLAN and aggregation
		// interfaces stay — they carry real traffic worth graphing, and a
		// customer-facing VLAN going down is exactly the kind of event this is
		// for.
		if ifType[idx] == 24 {
			continue
		}
		values := map[string]float64{
			"link_up":        boolValue(oper[idx] == 1),
			"admin_up":       boolValue(admin[idx] == 1),
			"if_index":       mustFloat(idx),
			"oper_status":    oper[idx],
			"admin_status":   admin[idx],
			"interface_type": ifType[idx],
		}
		if mbit, ok := highSpeed[idx]; ok && mbit > 0 {
			values["speed_mbps"] = mbit
		} else if bps, ok := speed[idx]; ok && bps > 0 {
			values["speed_mbps"] = bps / 1_000_000
		}

		labels := map[string]string{"iface": name}
		res.Metrics = append(res.Metrics, protocol.Sample{Name: "net.link_up", Labels: labels, Value: values["link_up"]})

		// 64-bit counters where the device has them: a 10G port overruns a
		// 32-bit octet counter in roughly three seconds.
		for _, c := range []struct {
			key      string
			metric   string
			hc, base string
		}{
			{"rx_bytes_per_sec", "net.rx_bytes_per_sec", oidIfHCInOctets, oidIfInOctets},
			{"tx_bytes_per_sec", "net.tx_bytes_per_sec", oidIfHCOutOctets, oidIfOutOctets},
		} {
			cur, ok := numbers(ext, c.hc)[idx]
			if !ok {
				cur, ok = numbers(base, c.base)[idx]
			}
			if !ok {
				continue
			}
			key := idx + "/" + c.key
			next[key] = cur
			if rate, ok := p.rate(key, cur, elapsed); ok {
				values[c.key] = rate
				res.Metrics = append(res.Metrics, protocol.Sample{Name: c.metric, Labels: labels, Value: rate})
			}
		}
		for _, c := range []struct{ key, oid, metric string }{
			{"rx_errors_per_sec", oidIfInErrors, "net.rx_errors_per_sec"},
			{"tx_errors_per_sec", oidIfOutErrors, "net.tx_errors_per_sec"},
			{"rx_drops_per_sec", oidIfInDiscards, "net.rx_drops_per_sec"},
			{"tx_drops_per_sec", oidIfOutDiscards, "net.tx_drops_per_sec"},
		} {
			cur, ok := numbers(base, c.oid)[idx]
			if !ok {
				continue
			}
			key := idx + "/" + c.key
			next[key] = cur
			if rate, ok := p.rate(key, cur, elapsed); ok {
				values[c.key] = rate
				res.Metrics = append(res.Metrics, protocol.Sample{Name: c.metric, Labels: labels, Value: rate})
			}
		}

		res.Checks = append(res.Checks, protocol.CheckResult{Plugin: "if", Item: name, Values: values})
		// Like Checkmk and like the local agent: only a port that is up right
		// now becomes a service, so unused ports do not start out critical.
		if oper[idx] == 1 {
			desc := "Interface " + name
			if a := alias[idx]; a != "" {
				desc += " (" + a + ")"
			}
			res.Discovery = append(res.Discovery, protocol.DiscoveredItem{Plugin: "if", Item: name, Description: desc})
		}
	}
	p.prev = next
}

// rate turns two counter readings into a per-second value. A counter that went
// backwards (device reboot, 32-bit wrap) yields nothing instead of a spike —
// the same rule the local collectors follow.
func (p *Poller) rate(key string, cur, elapsed float64) (float64, bool) {
	if elapsed <= 0 || p.prev == nil {
		return 0, false
	}
	before, ok := p.prev[key]
	if !ok || cur < before {
		return 0, false
	}
	return (cur - before) / elapsed, true
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func mustFloat(s string) float64 {
	var n float64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + float64(c-'0')
	}
	return n
}

// vendorOf picks the branch the resource collectors take. sysObjectID is the
// reliable signal; sysDescr is only consulted when the enterprise number is
// one that many products share (net-snmp).
func vendorOf(objectID, descr string) string {
	switch {
	case strings.HasPrefix(objectID, entCisco):
		return "cisco"
	case strings.HasPrefix(objectID, entEdgecore):
		return "edgecore"
	case strings.HasPrefix(objectID, entUbiquiti):
		return "ubiquiti"
	case strings.HasPrefix(objectID, entNetSNMP):
		if strings.Contains(strings.ToLower(descr), "edgeos") || strings.Contains(strings.ToLower(descr), "ubnt") {
			return "ubiquiti"
		}
		return "linux"
	default:
		return "generic"
	}
}
