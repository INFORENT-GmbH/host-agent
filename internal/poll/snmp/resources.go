package snmp

import (
	"context"
	"strings"

	"github.com/gosnmp/gosnmp"

	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

// resources reads CPU and memory. There is no single MIB every switch and
// router implements, so three branches are tried in the order the vendor makes
// likely and the first one that answers wins. A device that answers none
// simply has no cpu/mem service — better than inventing one from a MIB that
// means something else.
func (p *Poller) resources(ctx context.Context, s Session, res *Result) {
	order := []func(context.Context, Session, *Result) bool{p.ucd, p.cisco, p.hostResources}
	switch res.Identity.Vendor {
	case "cisco":
		order = []func(context.Context, Session, *Result) bool{p.cisco, p.hostResources, p.ucd}
	case "edgecore":
		order = []func(context.Context, Session, *Result) bool{p.hostResources, p.cisco, p.ucd}
	}
	for _, try := range order {
		if try(ctx, s, res) {
			return
		}
	}
}

// ucd reads UCD-SNMP-MIB, which every Linux-based device answers (EdgeOS,
// OpenWrt, anything running net-snmp).
func (p *Poller) ucd(ctx context.Context, s Session, res *Result) bool {
	pdus, err := s.Get(ctx, []string{oidSsCPUIdle, oidSsCPUUser, oidSsCPUSystem, oidMemTotal, oidMemAvail, oidMemBuffer, oidMemCached})
	if err != nil {
		return false
	}
	got := map[string]float64{}
	for i, oid := range []string{oidSsCPUIdle, oidSsCPUUser, oidSsCPUSystem, oidMemTotal, oidMemAvail, oidMemBuffer, oidMemCached} {
		if i < len(pdus) {
			if v, ok := number(pdus[i]); ok {
				got[oid] = v
			}
		}
	}
	found := false

	// ssCpuIdle is the honest source; where it is missing, user+system is the
	// next best thing (it ignores iowait, which a router barely has).
	if idle, ok := got[oidSsCPUIdle]; ok {
		found = true
		p.cpuUtil(res, 100-idle)
	} else if u, ok := got[oidSsCPUUser]; ok {
		if sys, ok2 := got[oidSsCPUSystem]; ok2 {
			found = true
			p.cpuUtil(res, u+sys)
		}
	}

	// UCD reports kibibytes. "available" follows free + buffers + cached, the
	// same definition the local agent uses for MemAvailable.
	if total, ok := got[oidMemTotal]; ok && total > 0 {
		if avail, ok2 := got[oidMemAvail]; ok2 {
			found = true
			availBytes := (avail + got[oidMemBuffer] + got[oidMemCached]) * 1024
			p.memory(res, total*1024, availBytes)
		}
	}

	// Load average, if the device keeps one (laLoadInt is load × 100).
	if load := numbers(mustWalk(ctx, s, oidUCDLoad), oidLaLoadInt); len(load) > 0 {
		values := map[string]float64{}
		for idx, key := range map[string]string{"1": "load1", "2": "load5", "3": "load15"} {
			if v, ok := load[idx]; ok {
				values[key] = v / 100
			}
		}
		if _, ok := values["load15"]; ok {
			found = true
			// cpus is what the judgement divides by; without a CPU count from
			// the device, one is the safe assumption (it never understates).
			values["cpus"] = 1
			res.Checks = append(res.Checks, protocol.CheckResult{Plugin: "cpu.load", Values: values})
			res.Metrics = append(res.Metrics,
				protocol.Sample{Name: "load.15", Value: values["load15"]},
				protocol.Sample{Name: "load.1", Value: values["load1"]})
			res.Discovery = append(res.Discovery, protocol.DiscoveredItem{Plugin: "cpu.load", Description: "CPU load"})
		}
	}
	return found
}

// cisco reads CISCO-PROCESS-MIB and CISCO-MEMORY-POOL-MIB.
func (p *Poller) cisco(ctx context.Context, s Session, res *Result) bool {
	found := false
	if cpus := numbers(mustWalk(ctx, s, oidCiscoProcessCPUs), oidCiscoCPU5min); len(cpus) > 0 {
		// A stack reports one entry per member; the busiest one decides,
		// because that is the one that drops packets.
		worst := 0.0
		for _, v := range cpus {
			worst = max(worst, v)
		}
		found = true
		p.cpuUtil(res, worst)
	}
	pools := mustWalk(ctx, s, oidCiscoMemTable)
	names := texts(pools, oidCiscoMemName)
	used := numbers(pools, oidCiscoMemUsed)
	free := numbers(pools, oidCiscoMemFree)
	for idx, name := range names {
		// Only the processor pool is the device's working memory; the I/O and
		// driver pools are buffers and would drown it in the same number.
		if !strings.EqualFold(name, "Processor") {
			continue
		}
		u, okU := used[idx]
		f, okF := free[idx]
		if okU && okF && u+f > 0 {
			found = true
			p.memory(res, u+f, f)
		}
	}
	return found
}

// hostResources reads HOST-RESOURCES-MIB — the generic fallback that most
// switch firmwares (Edgecore, Broadcom-based) implement.
func (p *Poller) hostResources(ctx context.Context, s Session, res *Result) bool {
	found := false
	if loads := numbers(mustWalk(ctx, s, oidHrProcessorLoad), oidHrProcessorLoad); len(loads) > 0 {
		sum := 0.0
		for _, v := range loads {
			sum += v
		}
		found = true
		p.cpuUtil(res, sum/float64(len(loads)))
	}

	table := mustWalk(ctx, s, oidHrStorageTable)
	types := texts(table, oidHrStorageType)
	units := numbers(table, oidHrStorageUnits)
	size := numbers(table, oidHrStorageSize)
	usedCol := numbers(table, oidHrStorageUsed)
	for idx, t := range types {
		if strings.TrimPrefix(t, ".") != oidHrStorageRAM {
			continue
		}
		unit := units[idx]
		if unit <= 0 {
			unit = 1
		}
		total, okT := size[idx]
		used, okU := usedCol[idx]
		if okT && okU && total > 0 {
			found = true
			p.memory(res, total*unit, (total-used)*unit)
		}
	}
	return found
}

func (p *Poller) cpuUtil(res *Result, percent float64) {
	percent = clamp(percent, 0, 100)
	res.Checks = append(res.Checks, protocol.CheckResult{
		Plugin: "cpu.util", Values: map[string]float64{"util_percent": percent},
	})
	res.Metrics = append(res.Metrics, protocol.Sample{Name: "cpu.util_percent", Value: percent})
	res.Discovery = append(res.Discovery, protocol.DiscoveredItem{Plugin: "cpu.util", Description: "CPU utilization"})
}

func (p *Poller) memory(res *Result, totalBytes, availableBytes float64) {
	availableBytes = clamp(availableBytes, 0, totalBytes)
	res.Checks = append(res.Checks, protocol.CheckResult{
		Plugin: "mem", Values: map[string]float64{"total_bytes": totalBytes, "available_bytes": availableBytes},
	})
	res.Metrics = append(res.Metrics,
		protocol.Sample{Name: "mem.total_bytes", Value: totalBytes},
		protocol.Sample{Name: "mem.available_bytes", Value: availableBytes})
	res.Discovery = append(res.Discovery, protocol.DiscoveredItem{Plugin: "mem", Description: "Memory"})
}

func clamp(v, lo, hi float64) float64 {
	return max(lo, min(v, hi))
}

// mustWalk swallows the error: a device that does not implement a table
// answers with an empty subtree, and that is indistinguishable from "no such
// object" for our purpose — both mean "this branch has nothing".
func mustWalk(ctx context.Context, s Session, root string) []gosnmp.SnmpPDU {
	pdus, err := s.Walk(ctx, root)
	if err != nil {
		return nil
	}
	return pdus
}
