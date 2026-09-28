package snmp

import (
	"context"
	"math"
	"strconv"
	"strings"

	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

// sensors reports temperature, fans and power supplies as `sensor` services.
//
// Unlike CPU and memory this is the one place where the DEVICE judges: Cisco's
// ENVMON and the ENTITY-SENSOR status column say "normal", "warning" or
// "critical" about their own hardware, and a switch knows its shutdown
// threshold better than any rule we could write. Where a device only reports a
// number, the result carries the number alone and the server judges it.
func (p *Poller) sensors(ctx context.Context, s Session, res *Result) {
	if p.ciscoEnv(ctx, s, res) {
		return
	}
	p.entitySensors(ctx, s, res)
}

// ciscoEnvState maps CISCO-ENVMON-MIB's state column. `notPresent` (5) is not
// a problem — an empty power supply bay is the normal case for a device that
// can take two.
func ciscoEnvState(v float64) (protocol.State, string, bool) {
	switch v {
	case 1:
		return protocol.StateOK, "normal", true
	case 2:
		return protocol.StateWarn, "warning", true
	case 3, 4:
		return protocol.StateCrit, "critical", true
	case 5:
		return protocol.StateOK, "not present", true
	case 6:
		return protocol.StateUnknown, "not functioning", true
	default:
		return protocol.StateUnknown, "unknown", false
	}
}

func (p *Poller) ciscoEnv(ctx context.Context, s Session, res *Result) bool {
	found := false
	// Temperature: a number AND a verdict.
	temps := mustWalk(ctx, s, oidCiscoEnvTemp)
	tempNames := texts(temps, oidCiscoEnvTemp+".2")
	tempValues := numbers(temps, oidCiscoEnvTemp+".3")
	tempStates := numbers(temps, oidCiscoEnvTemp+".6")
	for idx, name := range tempNames {
		v, ok := tempValues[idx]
		if !ok {
			continue
		}
		found = true
		item := sensorItem(name, "Temperature "+idx)
		values := map[string]float64{"temperature_celsius": v}
		res.Checks = append(res.Checks, withState(tempStates[idx], protocol.CheckResult{
			Plugin: "sensor", Item: item, Values: values,
		}, "temperature "+formatNum(v)+" °C"))
		res.Metrics = append(res.Metrics, protocol.Sample{
			Name: "sensor.temperature_celsius", Labels: map[string]string{"sensor": item}, Value: v,
		})
		res.Discovery = append(res.Discovery, protocol.DiscoveredItem{Plugin: "sensor", Item: item, Description: "Sensor " + item})
	}

	// Fans and power supplies report a state only.
	for _, group := range []struct{ root, kind string }{
		{oidCiscoEnvFan, "Fan"},
		{oidCiscoEnvSupply, "Power supply"},
	} {
		table := mustWalk(ctx, s, group.root)
		names := texts(table, group.root+".2")
		states := numbers(table, group.root+".3")
		for idx, name := range names {
			raw, ok := states[idx]
			if !ok {
				continue
			}
			found = true
			item := sensorItem(name, group.kind+" "+idx)
			state, label, _ := ciscoEnvState(raw)
			res.Checks = append(res.Checks, protocol.CheckResult{
				Plugin: "sensor", Item: item, State: &state, Summary: strings.ToLower(group.kind) + " " + label,
			})
			res.Discovery = append(res.Discovery, protocol.DiscoveredItem{Plugin: "sensor", Item: item, Description: "Sensor " + item})
		}
	}
	return found
}

// entitySensors reads ENTITY-SENSOR-MIB, the vendor-neutral table. Values come
// scaled (entPhySensorScale) and with a precision (digits after the point),
// both of which have to be applied or a 31 °C sensor reads as 310.
func (p *Poller) entitySensors(ctx context.Context, s Session, res *Result) {
	table := mustWalk(ctx, s, oidEntSensorTable)
	if len(table) == 0 {
		return
	}
	descr := texts(mustWalk(ctx, s, oidEntPhysicalDescr), oidEntPhysicalDescr)
	types := numbers(table, oidEntSensorType)
	scales := numbers(table, oidEntSensorScale)
	precs := numbers(table, oidEntSensorPrec)
	values := numbers(table, oidEntSensorValue)
	states := numbers(table, oidEntSensorStatus)

	for idx, raw := range values {
		key, unit, ok := entSensorMetric(types[idx])
		if !ok {
			continue
		}
		v := raw * entScaleFactor(scales[idx]) / math.Pow(10, precs[idx])
		item := sensorItem(descr[idx], "Sensor "+idx)
		result := protocol.CheckResult{Plugin: "sensor", Item: item, Values: map[string]float64{key: v}}
		// entPhySensorOperStatus: 1 ok, 2 unavailable, 3 nonoperational.
		switch states[idx] {
		case 2:
			st := protocol.StateUnknown
			result.State, result.Summary = &st, "sensor unavailable"
		case 3:
			st := protocol.StateCrit
			result.State, result.Summary = &st, "sensor not operational"
		}
		res.Checks = append(res.Checks, result)
		res.Metrics = append(res.Metrics, protocol.Sample{
			Name: "sensor." + key, Labels: map[string]string{"sensor": item}, Value: v,
		})
		res.Discovery = append(res.Discovery, protocol.DiscoveredItem{Plugin: "sensor", Item: item, Description: "Sensor " + item})
		_ = unit
	}
}

// entSensorMetric maps entPhySensorType to our value name. Only the three
// kinds a network device really reports are taken; the rest (truth values,
// "other", percent-of-something) would need a unit to be meaningful.
func entSensorMetric(t float64) (key, unit string, ok bool) {
	switch t {
	case 4:
		return "voltage_volts", "V", true
	case 8:
		return "temperature_celsius", "°C", true
	case 10:
		return "fan_rpm", "rpm", true
	default:
		return "", "", false
	}
}

// entScaleFactor turns entPhySensorScale (yocto … yotta) into a multiplier.
func entScaleFactor(scale float64) float64 {
	// 9 = units; every step is three orders of magnitude.
	if scale == 0 {
		return 1
	}
	return math.Pow(10, (scale-9)*3)
}

func sensorItem(name, fallback string) string {
	if n := strings.TrimSpace(name); n != "" {
		return n
	}
	return fallback
}

// withState attaches the device's own verdict when it gave one; otherwise the
// result stays a bare measurement for the server to judge.
func withState(raw float64, r protocol.CheckResult, summary string) protocol.CheckResult {
	if raw == 0 {
		return r
	}
	state, label, known := ciscoEnvState(raw)
	if !known {
		return r
	}
	r.State = &state
	r.Summary = summary + " (" + label + ")"
	return r
}

// formatNum renders a measurement for the summary line: no trailing zeros,
// no exponent for the ranges a sensor reports.
func formatNum(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}
