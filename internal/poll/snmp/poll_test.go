package snmp

import (
	"context"
	"testing"
	"time"

	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

func checkFor(t *testing.T, res Result, plugin, item string) protocol.CheckResult {
	t.Helper()
	for _, c := range res.Checks {
		if c.Plugin == plugin && c.Item == item {
			return c
		}
	}
	t.Fatalf("no %s check for item %q", plugin, item)
	return protocol.CheckResult{}
}

func hasCheck(res Result, plugin, item string) bool {
	for _, c := range res.Checks {
		if c.Plugin == plugin && c.Item == item {
			return true
		}
	}
	return false
}

func discovered(res Result, plugin, item string) bool {
	for _, d := range res.Discovery {
		if d.Plugin == plugin && d.Item == item {
			return true
		}
	}
	return false
}

func metric(t *testing.T, res Result, name, iface string) float64 {
	t.Helper()
	for _, s := range res.Metrics {
		if s.Name == name && (iface == "" || s.Labels["iface"] == iface) {
			return s.Value
		}
	}
	t.Fatalf("no metric %s for %q", name, iface)
	return 0
}

// pollTwice runs the poll the way the satellite does: once to fill the counter
// history, then again after `gap` — only the second one can report rates.
func pollTwice(t *testing.T, device string, gap time.Duration) (*recording, Result) {
	t.Helper()
	rec := loadRecording(t, device)
	p := NewPoller()
	now := time.Unix(1_700_000_000, 0)
	if _, err := p.Poll(context.Background(), rec, now); err != nil {
		t.Fatalf("first poll: %v", err)
	}
	rec.advance(gap.Seconds())
	res, err := p.Poll(context.Background(), rec, now.Add(gap))
	if err != nil {
		t.Fatalf("second poll: %v", err)
	}
	return rec, res
}

func TestCiscoCatalyst(t *testing.T) {
	_, res := pollTwice(t, "1161-cisco-catalyst", time.Minute)

	if res.Identity.Vendor != "cisco" {
		t.Errorf("vendor = %q, want cisco", res.Identity.Vendor)
	}
	if res.Identity.Name != "sw-fra-core01" {
		t.Errorf("sysName = %q", res.Identity.Name)
	}

	// Port 1 carries 35 % of a gigabit in, 60 % of that out.
	rx := checkFor(t, res, "if", "Gi1/0/1").Values["rx_bytes_per_sec"]
	if want := 1e9 / 8 * 0.35; rx < want*0.99 || rx > want*1.01 {
		t.Errorf("rx rate = %.0f B/s, want ≈ %.0f", rx, want)
	}
	if tx := checkFor(t, res, "if", "Gi1/0/1").Values["tx_bytes_per_sec"]; tx > rx {
		t.Errorf("tx %.0f should be below rx %.0f", tx, rx)
	}
	if got := metric(t, res, "net.rx_bytes_per_sec", "Gi1/0/1"); got != rx {
		t.Errorf("metric and check disagree: %.0f vs %.0f", got, rx)
	}

	// A port with the cable pulled is down but still a service; the two ports
	// that are administratively off are not discovered at all.
	if got := checkFor(t, res, "if", "Gi1/0/7").Values["link_up"]; got != 0 {
		t.Errorf("Gi1/0/7 link_up = %v, want 0", got)
	}
	if discovered(res, "if", "Gi1/0/7") {
		t.Error("a port that is down must not be discovered")
	}
	if !discovered(res, "if", "Gi1/0/1") {
		t.Error("an up port must be discovered")
	}
	if speed := checkFor(t, res, "if", "Te1/1/1").Values["speed_mbps"]; speed != 10_000 {
		t.Errorf("10G uplink speed = %v Mbit/s", speed)
	}

	// CPU and memory come from the Cisco MIBs, not from a generic fallback.
	// The five-minute average, not the five-second spike: that is the value a
	// monitoring system should act on, and it is what Checkmk uses too.
	if util := checkFor(t, res, "cpu.util", "").Values["util_percent"]; util != 8 {
		t.Errorf("cpu util = %v, want cpmCPUTotal5minRev 8", util)
	}
	mem := checkFor(t, res, "mem", "").Values
	if mem["total_bytes"] != 214773760+641597440 {
		t.Errorf("mem total = %v, want used+free of the processor pool", mem["total_bytes"])
	}

	// The device judges its own hardware.
	temp := checkFor(t, res, "sensor", "Switch 1 - Inlet Temp Sensor")
	if temp.Values["temperature_celsius"] != 28 {
		t.Errorf("inlet temperature = %v", temp.Values["temperature_celsius"])
	}
	if temp.State == nil || *temp.State != protocol.StateOK {
		t.Errorf("inlet sensor state = %v, want ok from ciscoEnvMonTemperatureState", temp.State)
	}
	psu := checkFor(t, res, "sensor", "Switch 1 - Power Supply B")
	if psu.State == nil || *psu.State != protocol.StateOK {
		t.Errorf("an empty power supply bay must not be a problem, got %v", psu.State)
	}
}

func TestUbiquitiEdgeRouter(t *testing.T) {
	_, res := pollTwice(t, "1163-ubiquiti-edgerouter", time.Minute)

	if res.Identity.Vendor != "ubiquiti" {
		t.Errorf("vendor = %q — EdgeOS reports the net-snmp enterprise id and must be recognised by sysDescr", res.Identity.Vendor)
	}
	// UCD-SNMP-MIB branch: load, memory and CPU come from the Linux stack.
	load := checkFor(t, res, "cpu.load", "").Values
	if load["load15"] != 0.29 || load["cpus"] != 1 {
		t.Errorf("load = %+v", load)
	}
	mem := checkFor(t, res, "mem", "").Values
	if mem["total_bytes"] != 1013352*1024 {
		t.Errorf("mem total = %v", mem["total_bytes"])
	}
	if mem["available_bytes"] <= 0 || mem["available_bytes"] >= mem["total_bytes"] {
		t.Errorf("available %v out of range for total %v", mem["available_bytes"], mem["total_bytes"])
	}
	if util := checkFor(t, res, "cpu.util", "").Values["util_percent"]; util < 0 || util > 100 {
		t.Errorf("cpu util = %v", util)
	}
	// The loopback is not a port anyone watches.
	if hasCheck(res, "if", "lo") {
		t.Error("loopback must not become an if service")
	}
	if !hasCheck(res, "if", "eth0") {
		t.Error("eth0 missing")
	}
	// An interface that is administratively down keeps its service but is not
	// rediscovered.
	if discovered(res, "if", "eth3") {
		t.Error("a disabled interface must not be discovered")
	}
}

func TestEdgecoreECS(t *testing.T) {
	_, res := pollTwice(t, "1162-edgecore-ecs", time.Minute)

	if res.Identity.Vendor != "edgecore" {
		t.Errorf("vendor = %q", res.Identity.Vendor)
	}
	// HOST-RESOURCES fallback: hrProcessorLoad and the RAM storage row.
	if util := checkFor(t, res, "cpu.util", "").Values["util_percent"]; util != 13 {
		t.Errorf("cpu util = %v, want hrProcessorLoad 13", util)
	}
	mem := checkFor(t, res, "mem", "").Values
	if mem["total_bytes"] != 524288*1024 {
		t.Errorf("mem total = %v, want size × allocation units", mem["total_bytes"])
	}
	// ENTITY-SENSOR-MIB: temperature, fan and voltage with their scales.
	temp := checkFor(t, res, "sensor", "Temperature Sensor 1")
	if temp.Values["temperature_celsius"] != 31 {
		t.Errorf("temperature = %v", temp.Values["temperature_celsius"])
	}
	if fan := checkFor(t, res, "sensor", "Fan 1").Values["fan_rpm"]; fan != 7200 {
		t.Errorf("fan = %v", fan)
	}
	// 12047 milli-volts with entPhySensorScale = milli must read as 12.047 V.
	if v := checkFor(t, res, "sensor", "Power Supply 1").Values["voltage_volts"]; v < 12.04 || v > 12.05 {
		t.Errorf("voltage = %v, want ≈ 12.047 V (scale applied?)", v)
	}
}

func TestFirstPollHasNoRates(t *testing.T) {
	rec := loadRecording(t, "1161-cisco-catalyst")
	p := NewPoller()
	res, err := p.Poll(context.Background(), rec, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	c := checkFor(t, res, "if", "Gi1/0/1")
	if _, ok := c.Values["rx_bytes_per_sec"]; ok {
		t.Error("the first poll has nothing to compare against and must not report a rate")
	}
	if c.Values["link_up"] != 1 {
		t.Error("states are available from the first poll on")
	}
}

func TestCounterGoingBackwardsYieldsNoRate(t *testing.T) {
	rec := loadRecording(t, "1161-cisco-catalyst")
	p := NewPoller()
	now := time.Unix(1_700_000_000, 0)
	rec.advance(3600) // as if the device had been up for a while
	if _, err := p.Poll(context.Background(), rec, now); err != nil {
		t.Fatal(err)
	}
	// Device reboot: counters restart at their initial value.
	rec.seconds = 0
	res, err := p.Poll(context.Background(), rec, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := checkFor(t, res, "if", "Gi1/0/1").Values["rx_bytes_per_sec"]; ok {
		t.Error("a counter that went backwards must yield no value instead of a spike")
	}
}

func TestVendorDetection(t *testing.T) {
	for _, tc := range []struct{ oid, descr, want string }{
		{"1.3.6.1.4.1.9.1.2494", "Cisco IOS", "cisco"},
		{"1.3.6.1.4.1.259.10.1.45.104", "Edgecore ECS", "edgecore"},
		{"1.3.6.1.4.1.41112.1.5", "UniFi", "ubiquiti"},
		{"1.3.6.1.4.1.8072.3.2.10", "EdgeOS v2.0.9", "ubiquiti"},
		{"1.3.6.1.4.1.8072.3.2.10", "Debian GNU/Linux", "linux"},
		{"1.3.6.1.4.1.2636.1.1.1.2.29", "Juniper", "generic"},
	} {
		if got := vendorOf(tc.oid, tc.descr); got != tc.want {
			t.Errorf("vendorOf(%q, %q) = %q, want %q", tc.oid, tc.descr, got, tc.want)
		}
	}
}

// A small switch answers only IF-MIB and one sensor. Then there must be NO
// cpu/mem services — a branch that invents something here would otherwise
// only show up on the real device.
func TestDeviceWithoutCpuOrMemory(t *testing.T) {
	_, res := pollTwice(t, "1166-ubiquiti-edgeswitch", time.Minute)

	if hasCheck(res, "cpu.util", "") || hasCheck(res, "mem", "") || hasCheck(res, "cpu.load", "") {
		t.Error("device reports no CPU or memory MIB — no such service may appear")
	}
	if !hasCheck(res, "if", "0/1") {
		t.Error("ports missing")
	}
	if temp := checkFor(t, res, "sensor", "Temperature Sensor").Values["temperature_celsius"]; temp != 44 {
		t.Errorf("temperature = %v", temp)
	}
}

// The WAN router: few ports, lots of traffic, and a sensor the device itself
// reports as "warning".
func TestCiscoWanRouter(t *testing.T) {
	_, res := pollTwice(t, "1164-cisco-asr-wan", time.Minute)

	if util := checkFor(t, res, "cpu.util", "").Values["util_percent"]; util != 41 {
		t.Errorf("cpu util = %v, want 41", util)
	}
	cpuSensor := checkFor(t, res, "sensor", "CPU Temperature Sensor")
	if cpuSensor.State == nil || *cpuSensor.State != protocol.StateWarn {
		t.Errorf("sensor state = %v, want the device's own warning", cpuSensor.State)
	}
	wan := checkFor(t, res, "if", "Gi0/0/0")
	if wan.Values["rx_errors_per_sec"] <= 0 {
		t.Error("the WAN port is meant to show input errors")
	}
	if down := checkFor(t, res, "if", "Gi0/0/2").Values["link_up"]; down != 0 {
		t.Error("the peering port is meant to be down")
	}
}
