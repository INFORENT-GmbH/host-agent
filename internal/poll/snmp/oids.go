package snmp

// The OIDs this package reads, by name. Numeric on purpose: shipping MIB files
// (and a compiler for them) to every satellite would be a second update path
// for no gain — a device either answers these object identifiers or it does
// not, and the names here document which MIB they come from.
const (
	// SNMPv2-MIB, system group
	oidSysDescr    = "1.3.6.1.2.1.1.1.0"
	oidSysObjectID = "1.3.6.1.2.1.1.2.0"
	oidSysUpTime   = "1.3.6.1.2.1.1.3.0"
	oidSysContact  = "1.3.6.1.2.1.1.4.0"
	oidSysName     = "1.3.6.1.2.1.1.5.0"
	oidSysLocation = "1.3.6.1.2.1.1.6.0"

	// IF-MIB, ifTable
	oidIfDescr       = "1.3.6.1.2.1.2.2.1.2"
	oidIfType        = "1.3.6.1.2.1.2.2.1.3"
	oidIfSpeed       = "1.3.6.1.2.1.2.2.1.5"
	oidIfAdminStatus = "1.3.6.1.2.1.2.2.1.7"
	oidIfOperStatus  = "1.3.6.1.2.1.2.2.1.8"
	oidIfInOctets    = "1.3.6.1.2.1.2.2.1.10"
	oidIfInDiscards  = "1.3.6.1.2.1.2.2.1.13"
	oidIfInErrors    = "1.3.6.1.2.1.2.2.1.14"
	oidIfOutOctets   = "1.3.6.1.2.1.2.2.1.16"
	oidIfOutDiscards = "1.3.6.1.2.1.2.2.1.19"
	oidIfOutErrors   = "1.3.6.1.2.1.2.2.1.20"
	oidIfTable       = "1.3.6.1.2.1.2.2.1"

	// IF-MIB, ifXTable (64-bit counters; a 1G port wraps ifInOctets in ~34 s)
	oidIfName        = "1.3.6.1.2.1.31.1.1.1.1"
	oidIfHCInOctets  = "1.3.6.1.2.1.31.1.1.1.6"
	oidIfHCOutOctets = "1.3.6.1.2.1.31.1.1.1.10"
	oidIfHighSpeed   = "1.3.6.1.2.1.31.1.1.1.15"
	oidIfAlias       = "1.3.6.1.2.1.31.1.1.1.18"
	oidIfXTable      = "1.3.6.1.2.1.31.1.1.1"

	// HOST-RESOURCES-MIB
	oidHrProcessorLoad = "1.3.6.1.2.1.25.3.3.1.2"
	oidHrStorageType   = "1.3.6.1.2.1.25.2.3.1.2"
	oidHrStorageDescr  = "1.3.6.1.2.1.25.2.3.1.3"
	oidHrStorageUnits  = "1.3.6.1.2.1.25.2.3.1.4"
	oidHrStorageSize   = "1.3.6.1.2.1.25.2.3.1.5"
	oidHrStorageUsed   = "1.3.6.1.2.1.25.2.3.1.6"
	oidHrStorageTable  = "1.3.6.1.2.1.25.2.3.1"
	oidHrStorageRAM    = "1.3.6.1.2.1.25.2.1.2"

	// ENTITY-MIB / ENTITY-SENSOR-MIB
	oidEntPhysicalDescr = "1.3.6.1.2.1.47.1.1.1.1.2"
	oidEntSensorType    = "1.3.6.1.2.1.99.1.1.1.1"
	oidEntSensorScale   = "1.3.6.1.2.1.99.1.1.1.2"
	oidEntSensorPrec    = "1.3.6.1.2.1.99.1.1.1.3"
	oidEntSensorValue   = "1.3.6.1.2.1.99.1.1.1.4"
	oidEntSensorStatus  = "1.3.6.1.2.1.99.1.1.1.5"
	oidEntSensorTable   = "1.3.6.1.2.1.99.1.1.1"

	// UCD-SNMP-MIB — every Linux-based router (EdgeOS, OpenWrt, net-snmp)
	oidLaNames     = "1.3.6.1.4.1.2021.10.1.2"
	oidLaLoadInt   = "1.3.6.1.4.1.2021.10.1.5" // load × 100, integer
	oidMemTotal    = "1.3.6.1.4.1.2021.4.5.0"
	oidMemAvail    = "1.3.6.1.4.1.2021.4.6.0"
	oidMemBuffer   = "1.3.6.1.4.1.2021.4.14.0"
	oidMemCached   = "1.3.6.1.4.1.2021.4.15.0"
	oidSsCPUIdle   = "1.3.6.1.4.1.2021.11.11.0"
	oidSsCPUUser   = "1.3.6.1.4.1.2021.11.9.0"
	oidSsCPUSystem = "1.3.6.1.4.1.2021.11.10.0"
	oidUCDLoad     = "1.3.6.1.4.1.2021.10.1"

	// CISCO-PROCESS-MIB / CISCO-MEMORY-POOL-MIB / CISCO-ENVMON-MIB
	oidCiscoCPU5min     = "1.3.6.1.4.1.9.9.109.1.1.1.1.8"
	oidCiscoCPU1min     = "1.3.6.1.4.1.9.9.109.1.1.1.1.7"
	oidCiscoMemName     = "1.3.6.1.4.1.9.9.48.1.1.1.2"
	oidCiscoMemUsed     = "1.3.6.1.4.1.9.9.48.1.1.1.5"
	oidCiscoMemFree     = "1.3.6.1.4.1.9.9.48.1.1.1.6"
	oidCiscoMemTable    = "1.3.6.1.4.1.9.9.48.1.1.1"
	oidCiscoEnvTemp     = "1.3.6.1.4.1.9.9.13.1.3.1"
	oidCiscoEnvFan      = "1.3.6.1.4.1.9.9.13.1.4.1"
	oidCiscoEnvSupply   = "1.3.6.1.4.1.9.9.13.1.5.1"
	oidCiscoProcessCPUs = "1.3.6.1.4.1.9.9.109.1.1.1.1"
)

// Enterprise prefixes of sysObjectID, used to pick the vendor branch.
const (
	entCisco    = "1.3.6.1.4.1.9."
	entUbiquiti = "1.3.6.1.4.1.41112."
	entEdgecore = "1.3.6.1.4.1.259."
	entNetSNMP  = "1.3.6.1.4.1.8072." // EdgeOS and every other net-snmp host
)
