package protocol

import (
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Limits. The gateway enforces the same numbers.
const (
	MaxSeries     = 5000
	MaxResults    = 2000
	MaxItems      = 2000
	MaxLabels     = 16
	MaxPerf       = 32
	MaxValues     = 32
	MaxSummary    = 500 // host_services.summary is VARCHAR(500)
	MaxItemLen    = 255
	MaxLabelValue = 256
	MaxShortText  = 255
	// MaxSources bounds one satellite's assignment. A poller needs a socket
	// and a goroutine per device; beyond this a second satellite is the
	// answer, not a bigger list.
	MaxSources = 500
)

var (
	metricNameRE = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,127}$`)
	labelKeyRE   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	pluginRE     = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,63}$`)
	kindRE       = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	sha256RE     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	epochRE      = regexp.MustCompile(`^[0-9a-f]{16}$`)
	machineIDRE  = regexp.MustCompile(`^[0-9a-f]{32}$`)
	brandKeyRE   = regexp.MustCompile(`^[a-z][a-z0-9-]{1,22}[a-z0-9]$`)
	// public_id of a host or a source — 24 hex characters (shared/src/publicId.ts).
	publicIDRE = regexp.MustCompile(`^[0-9a-f]{24}$`)
	// A poll target is an address, never a URL: hostname or IP literal.
	addressRE = regexp.MustCompile(`^[0-9a-zA-Z._:\[\]-]{1,255}$`)
	// versionRE is strict because the version ends up as an apt argument
	// (<package>=<version>).
	versionRE = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]{1,32})?$`)
)

// ---------------------------------------------------------------- agent → gateway

// Hello opens every connection.
type Hello struct {
	Protocol     int         `json:"protocol"`
	AgentVersion string      `json:"agentVersion"`
	Brand        string      `json:"brand"`
	Hostname     string      `json:"hostname"`
	MachineID    string      `json:"machineId"`
	OS           OSInfo      `json:"os"`
	Local        LocalOptIns `json:"local"`
	Time         int64       `json:"time"` // agent clock, unix ms — the gateway derives skew
	// SeqEpoch identifies the agent's sequence counter. It changes when the
	// agent's state is lost (reinstall, wiped /var/lib): seq then restarts
	// at 1, and the gateway must not drop those frames as duplicates of the
	// old counter.
	SeqEpoch string `json:"seqEpoch"`
}

// OSInfo describes the host.
type OSInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Kernel  string `json:"kernel"`
	Arch    string `json:"arch"`
}

// LocalOptIns mirror agent.conf [local]; the gateway can read but never set them.
type LocalOptIns struct {
	Satellite   bool `json:"satellite"`
	LocalChecks bool `json:"localChecks"`
}

// Validate implements Message.
func (m *Hello) Validate() error {
	if m.Protocol != Version {
		return fmt.Errorf("protocol %d not supported", m.Protocol)
	}
	if m.AgentVersion != "dev" && !versionRE.MatchString(m.AgentVersion) {
		return fmt.Errorf("agentVersion %q invalid", m.AgentVersion)
	}
	if !brandKeyRE.MatchString(m.Brand) {
		return fmt.Errorf("brand %q invalid", m.Brand)
	}
	if !epochRE.MatchString(m.SeqEpoch) {
		return errors.New("seqEpoch must be 16 lowercase hex characters")
	}
	if err := hostIdentity(m.Hostname, m.MachineID, m.OS); err != nil {
		return err
	}
	return positiveTime(m.Time)
}

func hostIdentity(hostname, machineID string, os OSInfo) error {
	if !machineIDRE.MatchString(machineID) {
		return errors.New("machineId must be 32 lowercase hex characters")
	}
	return errs(
		text("hostname", hostname, 1, MaxShortText),
		text("os.name", os.Name, 1, MaxShortText),
		text("os.version", os.Version, 0, MaxShortText),
		text("os.kernel", os.Kernel, 0, MaxShortText),
		text("os.arch", os.Arch, 1, 32),
	)
}

// Metrics is one collection tick: every series shares the timestamp.
//
// Target names the host the data belongs to when a SATELLITE reports for a
// device it polled (the device's public_id). Empty means "this host" — the
// normal case. The gateway only accepts a target that is really assigned to
// the sending satellite; see the gateway's session handling.
type Metrics struct {
	Time   int64    `json:"t"`
	Target string   `json:"target,omitempty"`
	Series []Sample `json:"series"`
}

// Sample is one value of one series.
type Sample struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels,omitempty"`
	Value  float64           `json:"value"`
}

// Validate implements Message.
func (m *Metrics) Validate() error {
	if err := positiveTime(m.Time); err != nil {
		return err
	}
	if err := target(m.Target); err != nil {
		return err
	}
	if len(m.Series) == 0 || len(m.Series) > MaxSeries {
		return fmt.Errorf("series: need 1..%d entries, got %d", MaxSeries, len(m.Series))
	}
	for i, s := range m.Series {
		if !metricNameRE.MatchString(s.Name) {
			return fmt.Errorf("series[%d].name %q invalid", i, s.Name)
		}
		if err := labels(fmt.Sprintf("series[%d].labels", i), s.Labels); err != nil {
			return err
		}
		if err := finite(fmt.Sprintf("series[%d].value", i), s.Value); err != nil {
			return err
		}
	}
	return nil
}

// State is a check verdict.
type State int

// Checkmk-compatible states.
const (
	StateOK      State = 0
	StateWarn    State = 1
	StateCrit    State = 2
	StateUnknown State = 3
)

// Checks carries check results of one tick. Target as in Metrics.
type Checks struct {
	Time    int64         `json:"t"`
	Target  string        `json:"target,omitempty"`
	Results []CheckResult `json:"results"`
}

// CheckResult is one service. State is set only when the check judged
// itself (local checks, MRPE); otherwise the gateway judges Values and Perf
// against its rules — including local checks with state "P".
type CheckResult struct {
	Plugin  string             `json:"plugin"`
	Item    string             `json:"item,omitempty"`
	State   *State             `json:"state,omitempty"`
	Summary string             `json:"summary,omitempty"`
	Values  map[string]float64 `json:"values,omitempty"`
	Perf    []Perf             `json:"perf,omitempty"`
}

// Perf is one performance datum in Nagios/Checkmk terms.
type Perf struct {
	Name  string   `json:"name"`
	Value float64  `json:"value"`
	Unit  string   `json:"unit,omitempty"`
	Warn  *float64 `json:"warn,omitempty"`
	Crit  *float64 `json:"crit,omitempty"`
	Min   *float64 `json:"min,omitempty"`
	Max   *float64 `json:"max,omitempty"`
}

// Validate implements Message.
func (m *Checks) Validate() error {
	if err := positiveTime(m.Time); err != nil {
		return err
	}
	if err := target(m.Target); err != nil {
		return err
	}
	if len(m.Results) == 0 || len(m.Results) > MaxResults {
		return fmt.Errorf("results: need 1..%d entries, got %d", MaxResults, len(m.Results))
	}
	for i, r := range m.Results {
		p := fmt.Sprintf("results[%d]", i)
		if err := pluginItem(p, r.Plugin, r.Item); err != nil {
			return err
		}
		if r.State != nil && (*r.State < StateOK || *r.State > StateUnknown) {
			return fmt.Errorf("%s.state %d out of range", p, *r.State)
		}
		if err := multiline(p+".summary", r.Summary, MaxSummary); err != nil {
			return err
		}
		if len(r.Values) > MaxValues {
			return fmt.Errorf("%s.values: at most %d entries", p, MaxValues)
		}
		for k, v := range r.Values {
			if !labelKeyRE.MatchString(k) {
				return fmt.Errorf("%s.values key %q invalid", p, k)
			}
			if err := finite(p+".values."+k, v); err != nil {
				return err
			}
		}
		if len(r.Perf) > MaxPerf {
			return fmt.Errorf("%s.perf: at most %d entries", p, MaxPerf)
		}
		for j, pd := range r.Perf {
			pp := fmt.Sprintf("%s.perf[%d]", p, j)
			if err := errs(text(pp+".name", pd.Name, 1, 64), text(pp+".unit", pd.Unit, 0, 16)); err != nil {
				return err
			}
			for name, v := range map[string]*float64{"value": &pd.Value, "warn": pd.Warn, "crit": pd.Crit, "min": pd.Min, "max": pd.Max} {
				if v != nil {
					if err := finite(pp+"."+name, *v); err != nil {
						return err
					}
				}
			}
		}
		if r.State == nil && len(r.Values) == 0 && len(r.Perf) == 0 {
			return fmt.Errorf("%s: needs state, values or perf", p)
		}
	}
	return nil
}

// Discovery is the complete list of items the agent can check right now.
// Anything the gateway knows but is missing here counts as vanished.
type Discovery struct {
	Time   int64            `json:"t"`
	Target string           `json:"target,omitempty"`
	Items  []DiscoveredItem `json:"items"`
}

// DiscoveredItem is one checkable service.
type DiscoveredItem struct {
	Plugin      string `json:"plugin"`
	Item        string `json:"item,omitempty"`
	Description string `json:"description,omitempty"`
}

// Validate implements Message.
func (m *Discovery) Validate() error {
	if err := positiveTime(m.Time); err != nil {
		return err
	}
	if err := target(m.Target); err != nil {
		return err
	}
	if len(m.Items) > MaxItems {
		return fmt.Errorf("items: at most %d entries", MaxItems)
	}
	seen := make(map[[2]string]bool, len(m.Items))
	for i, it := range m.Items {
		p := fmt.Sprintf("items[%d]", i)
		if err := pluginItem(p, it.Plugin, it.Item); err != nil {
			return err
		}
		if err := text(p+".description", it.Description, 0, MaxShortText); err != nil {
			return err
		}
		key := [2]string{it.Plugin, it.Item}
		if seen[key] {
			return fmt.Errorf("%s: duplicate %s/%s", p, it.Plugin, it.Item)
		}
		seen[key] = true
	}
	return nil
}

// Inventory is a snapshot of one kind (processes, ports, packages, …), sent
// only when Hash changed.
type Inventory struct {
	Time int64          `json:"t"`
	Kind string         `json:"kind"`
	Hash string         `json:"hash"` // sha256 hex of Data
	Data jsontext.Value `json:"data"`
}

// Validate implements Message.
func (m *Inventory) Validate() error {
	if err := positiveTime(m.Time); err != nil {
		return err
	}
	if !kindRE.MatchString(m.Kind) {
		return fmt.Errorf("kind %q invalid", m.Kind)
	}
	if !sha256RE.MatchString(m.Hash) {
		return errors.New("hash must be lowercase sha256 hex")
	}
	if len(m.Data) == 0 {
		return errors.New("data missing")
	}
	return nil
}

// UpdateResult reports the outcome of an update message.
type UpdateResult struct {
	Version string `json:"version"`
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
}

// Validate implements Message.
func (m *UpdateResult) Validate() error {
	if !versionRE.MatchString(m.Version) {
		return fmt.Errorf("version %q invalid", m.Version)
	}
	if m.OK && m.Error != "" {
		return errors.New("error set on success")
	}
	return multiline("error", m.Error, MaxSummary)
}

// SourceStatus reports how the last poll of ONE source went. It is the only
// way a source's `last_error` is ever filled: a device that cannot be reached
// produces no checks at all, so silence alone would be indistinguishable from
// a satellite that is simply idle.
type SourceStatus struct {
	Time   int64  `json:"t"`
	Source string `json:"source"` // host_sources.public_id
	Target string `json:"target"` // the polled host's public_id
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
	// What the poll learned about the device — only on success.
	SysName     string `json:"sysName,omitempty"`
	SysObjectID string `json:"sysObjectId,omitempty"`
	Vendor      string `json:"vendor,omitempty"`
}

// Validate implements Message.
func (m *SourceStatus) Validate() error {
	if err := positiveTime(m.Time); err != nil {
		return err
	}
	if !publicIDRE.MatchString(m.Source) {
		return fmt.Errorf("source %q must be 24 hex characters", m.Source)
	}
	if !publicIDRE.MatchString(m.Target) {
		return fmt.Errorf("target %q must be 24 hex characters", m.Target)
	}
	if m.OK && m.Error != "" {
		return errors.New("a successful poll carries no error")
	}
	if !m.OK && m.Error == "" {
		return errors.New("a failed poll must say why")
	}
	return errs(
		multiline("error", m.Error, MaxSummary),
		text("sysName", m.SysName, 0, MaxShortText),
		text("sysObjectId", m.SysObjectID, 0, MaxShortText),
		text("vendor", m.Vendor, 0, 32),
	)
}

// target checks the optional piggyback field of the data frames.
func target(t string) error {
	if t == "" || publicIDRE.MatchString(t) {
		return nil
	}
	return fmt.Errorf("target %q must be 24 hex characters", t)
}

// ---------------------------------------------------------------- gateway → agent

// Welcome answers hello.
type Welcome struct {
	Protocol   int    `json:"protocol"`
	HostID     string `json:"hostId"` // the host's public_id
	ServerTime int64  `json:"serverTime"`
}

// Validate implements Message.
func (m *Welcome) Validate() error {
	if m.Protocol != Version {
		return fmt.Errorf("protocol %d not supported", m.Protocol)
	}
	if err := text("hostId", m.HostID, 1, 64); err != nil {
		return err
	}
	return positiveTime(m.ServerTime)
}

// AgentConfig is the portal-controlled part of the configuration. It can
// tune intervals and switch collectors off — nothing more.
type AgentConfig struct {
	Version            int64     `json:"version"`
	Intervals          Intervals `json:"intervals"`
	DisabledCollectors []string  `json:"disabledCollectors,omitempty"`
	// Sources are the devices this host polls as a satellite, credentials
	// included: the portal keeps them and hands them over on the TLS
	// connection; the agent holds them in memory only and never writes them
	// to disk. Empty for a normal host — the
	// gateway sends none unless the agent announced `satellite` in hello.
	Sources []SourceConfig `json:"sources,omitempty"`
}

// Intervals in seconds.
type Intervals struct {
	MetricsS   int `json:"metricsS"`
	ChecksS    int `json:"checksS"`
	DiscoveryS int `json:"discoveryS"`
	InventoryS int `json:"inventoryS"`
}

// Validate implements Message.
func (m *AgentConfig) Validate() error {
	if m.Version < 1 {
		return errors.New("version must be >= 1")
	}
	if err := errs(
		between("intervals.metricsS", m.Intervals.MetricsS, 5, 300),
		between("intervals.checksS", m.Intervals.ChecksS, 10, 3600),
		between("intervals.discoveryS", m.Intervals.DiscoveryS, 300, 86400),
		between("intervals.inventoryS", m.Intervals.InventoryS, 300, 86400),
	); err != nil {
		return err
	}
	if len(m.DisabledCollectors) > 64 {
		return errors.New("disabledCollectors: at most 64 entries")
	}
	for i, c := range m.DisabledCollectors {
		if !pluginRE.MatchString(c) {
			return fmt.Errorf("disabledCollectors[%d] %q invalid", i, c)
		}
	}
	if len(m.Sources) > MaxSources {
		return fmt.Errorf("sources: at most %d entries", MaxSources)
	}
	for i, src := range m.Sources {
		if err := src.validate(fmt.Sprintf("sources[%d]", i)); err != nil {
			return err
		}
	}
	return nil
}

// SourceConfig is one device a satellite polls. It mirrors a `host_sources`
// row with the credentials unsealed.
type SourceConfig struct {
	ID      string `json:"id"`     // host_sources.public_id
	Target  string `json:"target"` // the polled host's public_id
	Kind    string `json:"kind"`   // "snmp" today; ipmi/redfish later
	Address string `json:"address"`
	Port    int    `json:"port"`
	// IntervalS is how often this device is polled — independent of the
	// agent's own check interval, because 500 devices at 60 s is a different
	// load than one host at 60 s.
	IntervalS int `json:"intervalS"`
	TimeoutMS int `json:"timeoutMs"`
	Retries   int `json:"retries"`

	SNMPVersion   string `json:"snmpVersion,omitempty"` // "2c" | "3"
	SNMPCommunity string `json:"snmpCommunity,omitempty"`
	SNMPUser      string `json:"snmpUser,omitempty"`
	SNMPAuthProto string `json:"snmpAuthProto,omitempty"`
	SNMPAuthKey   string `json:"snmpAuthKey,omitempty"`
	SNMPPrivProto string `json:"snmpPrivProto,omitempty"`
	SNMPPrivKey   string `json:"snmpPrivKey,omitempty"`
	SNMPContext   string `json:"snmpContext,omitempty"`
}

func (s SourceConfig) validate(path string) error {
	if !publicIDRE.MatchString(s.ID) {
		return fmt.Errorf("%s.id %q must be 24 hex characters", path, s.ID)
	}
	if !publicIDRE.MatchString(s.Target) {
		return fmt.Errorf("%s.target %q must be 24 hex characters", path, s.Target)
	}
	if !kindRE.MatchString(s.Kind) {
		return fmt.Errorf("%s.kind %q invalid", path, s.Kind)
	}
	if !addressRE.MatchString(s.Address) {
		return fmt.Errorf("%s.address %q invalid", path, s.Address)
	}
	if err := errs(
		between(path+".port", s.Port, 1, 65535),
		between(path+".intervalS", s.IntervalS, 10, 3600),
		between(path+".timeoutMs", s.TimeoutMS, 200, 30000),
		between(path+".retries", s.Retries, 0, 5),
	); err != nil {
		return err
	}
	if s.Kind != "snmp" {
		return nil
	}
	switch s.SNMPVersion {
	case "2c":
		if s.SNMPCommunity == "" {
			return fmt.Errorf("%s: v2c needs a community", path)
		}
	case "3":
		if s.SNMPUser == "" || s.SNMPAuthProto == "" || s.SNMPAuthKey == "" {
			return fmt.Errorf("%s: v3 needs user, auth protocol and auth key", path)
		}
		// authNoPriv is fine; half a privacy configuration is not.
		if (s.SNMPPrivProto == "") != (s.SNMPPrivKey == "") {
			return fmt.Errorf("%s: privacy needs protocol and key together", path)
		}
	default:
		return fmt.Errorf("%s.snmpVersion %q invalid", path, s.SNMPVersion)
	}
	return errs(
		text(path+".snmpCommunity", s.SNMPCommunity, 0, MaxShortText),
		text(path+".snmpUser", s.SNMPUser, 0, 64),
		text(path+".snmpAuthProto", s.SNMPAuthProto, 0, 16),
		text(path+".snmpAuthKey", s.SNMPAuthKey, 0, MaxShortText),
		text(path+".snmpPrivProto", s.SNMPPrivProto, 0, 16),
		text(path+".snmpPrivKey", s.SNMPPrivKey, 0, MaxShortText),
		text(path+".snmpContext", s.SNMPContext, 0, 64),
	)
}

// Live switches the fast metrics mode. It ends by itself after TTLS unless
// the gateway renews it, so a lost "off" can never leave a host in live mode.
type Live struct {
	On         bool `json:"on"`
	IntervalMs int  `json:"intervalMs"`
	TTLS       int  `json:"ttlS"`
}

// Validate implements Message.
func (m *Live) Validate() error {
	if !m.On {
		if m.IntervalMs != 0 || m.TTLS != 0 {
			return errors.New("off must not carry intervalMs/ttlS")
		}
		return nil
	}
	return errs(between("intervalMs", m.IntervalMs, 500, 10000), between("ttlS", m.TTLS, 1, 300))
}

// Update asks the agent to install one released version of its own package
// from its configured repository — the only action the gateway can trigger.
type Update struct {
	Version string `json:"version"`
}

// Validate implements Message.
func (m *Update) Validate() error {
	if !versionRE.MatchString(m.Version) {
		return fmt.Errorf("version %q invalid", m.Version)
	}
	return nil
}

// Ack confirms every agent message up to and including Seq.
type Ack struct {
	Seq uint64 `json:"seq"`
}

// Validate implements Message.
func (m *Ack) Validate() error {
	if m.Seq == 0 {
		return errors.New("seq must be >= 1")
	}
	return nil
}

// ---------------------------------------------------------------- enrollment
//
// POST <gateway>/v1/enroll is plain JSON, not an envelope: it happens once,
// before the agent has a host token.

// EnrollRequest trades a short-lived enroll token for a host token.
type EnrollRequest struct {
	EnrollToken  string `json:"enrollToken"`
	AgentVersion string `json:"agentVersion"`
	Brand        string `json:"brand"`
	Hostname     string `json:"hostname"`
	MachineID    string `json:"machineId"`
	OS           OSInfo `json:"os"`
	// UpdateChannel is the channel the setup chose for this host; empty
	// leaves the decision to the portal (its default for new hosts). A
	// re-enrollment with an empty value keeps the channel the host has.
	UpdateChannel string `json:"updateChannel"`
}

// UpdateChannels are the values EnrollRequest.UpdateChannel accepts besides
// the empty string. keep in sync: UPDATE_CHANNELS (api/src/hosts/routes.ts),
// the enum in agent-gateway/src/protocol/schemas.ts.
var UpdateChannels = []string{"stable", "testing", "off"}

// ValidUpdateChannel reports whether s is empty or one of UpdateChannels.
func ValidUpdateChannel(s string) bool {
	return s == "" || slices.Contains(UpdateChannels, s)
}

// Validate implements Message.
func (m *EnrollRequest) Validate() error {
	if err := text("enrollToken", m.EnrollToken, 16, 128); err != nil {
		return err
	}
	if m.AgentVersion != "dev" && !versionRE.MatchString(m.AgentVersion) {
		return fmt.Errorf("agentVersion %q invalid", m.AgentVersion)
	}
	if !brandKeyRE.MatchString(m.Brand) {
		return fmt.Errorf("brand %q invalid", m.Brand)
	}
	if !ValidUpdateChannel(m.UpdateChannel) {
		return fmt.Errorf("updateChannel %q invalid", m.UpdateChannel)
	}
	return hostIdentity(m.Hostname, m.MachineID, m.OS)
}

// EnrollResponse carries the host token. It is shown to nobody but the
// agent, which stores it in agent.conf; the gateway keeps only its hash.
type EnrollResponse struct {
	HostID    string `json:"hostId"`
	HostToken string `json:"hostToken"`
}

// Validate implements Message.
func (m *EnrollResponse) Validate() error {
	return errs(text("hostId", m.HostID, 1, 64), text("hostToken", m.HostToken, 32, 128))
}

// DecodeEnrollRequest parses and validates an enroll request body.
func DecodeEnrollRequest(b []byte) (*EnrollRequest, error) {
	return decodePlain(b, new(EnrollRequest))
}

// DecodeEnrollResponse parses and validates an enroll response body.
func DecodeEnrollResponse(b []byte) (*EnrollResponse, error) {
	return decodePlain(b, new(EnrollResponse))
}

// ---------------------------------------------------------------- helpers

func errs(list ...error) error {
	for _, err := range list {
		if err != nil {
			return err
		}
	}
	return nil
}

func positiveTime(ms int64) error {
	if ms <= 0 {
		return errors.New("time must be a positive unix ms timestamp")
	}
	return nil
}

func between(name string, v, lo, hi int) error {
	if v < lo || v > hi {
		return fmt.Errorf("%s %d outside %d..%d", name, v, lo, hi)
	}
	return nil
}

func finite(name string, v float64) error {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return fmt.Errorf("%s is not finite", name)
	}
	return nil
}

// text: single line, no control characters, length in runes.
func text(name, s string, minLen, maxLen int) error {
	if n := utf8.RuneCountInString(s); n < minLen || n > maxLen {
		return fmt.Errorf("%s: length %d outside %d..%d", name, n, minLen, maxLen)
	}
	if strings.IndexFunc(s, unicode.IsControl) >= 0 {
		return fmt.Errorf("%s contains control characters", name)
	}
	return nil
}

// multiline: like text but newlines and tabs are allowed (check output).
func multiline(name, s string, maxLen int) error {
	if n := utf8.RuneCountInString(s); n > maxLen {
		return fmt.Errorf("%s: length %d above %d", name, n, maxLen)
	}
	if strings.IndexFunc(s, func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\t' }) >= 0 {
		return fmt.Errorf("%s contains control characters", name)
	}
	return nil
}

func pluginItem(prefix, plugin, item string) error {
	if !pluginRE.MatchString(plugin) {
		return fmt.Errorf("%s.plugin %q invalid", prefix, plugin)
	}
	return text(prefix+".item", item, 0, MaxItemLen)
}

func labels(name string, l map[string]string) error {
	if len(l) > MaxLabels {
		return fmt.Errorf("%s: at most %d labels", name, MaxLabels)
	}
	for k, v := range l {
		if !labelKeyRE.MatchString(k) {
			return fmt.Errorf("%s key %q invalid", name, k)
		}
		if err := text(name+"."+k, v, 0, MaxLabelValue); err != nil {
			return err
		}
	}
	return nil
}
