// Package snmp polls a network device over SNMP and turns its MIB tables into
// the same check results the agent reports for a local host — an interface is
// an `if` service, a CPU is `cpu.util`, and so on. The server-side judgement
// (shared/src/hostChecks) therefore needs no special case for SNMP.
//
// Only reads: this package sends GET and GETBULK, never SET. A device that
// answers slowly must never hold up the satellite, so every call carries the
// caller's context and the session's own timeout.
package snmp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

// Version selects the SNMP protocol version of a source. The portal stores the
// same two values (`host_sources.snmp_version`).
type Version string

const (
	V2c Version = "2c"
	V3  Version = "3"
)

// Config mirrors one `host_sources` row. The portal hands it over already
// unsealed — this package never sees the database.
type Config struct {
	Address   string
	Port      uint16
	Version   Version
	Community string
	// v3 only. An empty PrivProto means authNoPriv.
	User       string
	AuthProto  string
	AuthKey    string
	PrivProto  string
	PrivKey    string
	Context    string
	Timeout    time.Duration
	Retries    int
	MaxRepeats uint8
}

// Session is the narrow view of a device the collectors use. It exists so the
// tests can replay a recorded walk (`snmpsim/data/*/public.snmprec`) instead of
// opening a socket — the same files the simulator serves.
type Session interface {
	// Get returns the varbinds for the given OIDs, in order. Missing instances
	// come back as NoSuchObject/NoSuchInstance rather than an error.
	Get(ctx context.Context, oids []string) ([]gosnmp.SnmpPDU, error)
	// Walk returns the whole subtree below root.
	Walk(ctx context.Context, root string) ([]gosnmp.SnmpPDU, error)
	Close() error
}

var authProtos = map[string]gosnmp.SnmpV3AuthProtocol{
	"MD5":    gosnmp.MD5,
	"SHA":    gosnmp.SHA,
	"SHA224": gosnmp.SHA224,
	"SHA256": gosnmp.SHA256,
	"SHA384": gosnmp.SHA384,
	"SHA512": gosnmp.SHA512,
}

var privProtos = map[string]gosnmp.SnmpV3PrivProtocol{
	"DES":    gosnmp.DES,
	"AES":    gosnmp.AES,
	"AES192": gosnmp.AES192,
	"AES256": gosnmp.AES256,
}

// Dial opens a session. It does not talk to the device yet for v2c; for v3 the
// handshake (engine discovery) happens here, so an unreachable device or wrong
// credentials fail immediately with a usable message.
func Dial(cfg Config) (Session, error) {
	g, err := params(cfg)
	if err != nil {
		return nil, err
	}
	if err := g.Connect(); err != nil {
		return nil, fmt.Errorf("connect %s:%d: %w", cfg.Address, cfg.Port, err)
	}
	return &liveSession{g: g}, nil
}

func params(cfg Config) (*gosnmp.GoSNMP, error) {
	if cfg.Address == "" {
		return nil, errors.New("snmp: no address")
	}
	port := cfg.Port
	if port == 0 {
		port = 161
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	repeats := cfg.MaxRepeats
	if repeats == 0 {
		// 10 rows per request keeps a bulk response inside a typical 1500-byte
		// MTU for the wide tables (ifXTable rows carry names and aliases), so a
		// switch with 48 ports needs no IP fragmentation to answer.
		repeats = 10
	}
	g := &gosnmp.GoSNMP{
		Target:             cfg.Address,
		Port:               port,
		Timeout:            timeout,
		Retries:            cfg.Retries,
		MaxRepetitions:     uint32(repeats),
		ContextName:        cfg.Context,
		ExponentialTimeout: false,
	}
	switch cfg.Version {
	case V3:
		if cfg.User == "" {
			return nil, errors.New("snmp: v3 without user")
		}
		auth, ok := authProtos[strings.ToUpper(cfg.AuthProto)]
		if !ok {
			return nil, fmt.Errorf("snmp: unknown auth protocol %q", cfg.AuthProto)
		}
		usm := &gosnmp.UsmSecurityParameters{
			UserName:                 cfg.User,
			AuthenticationProtocol:   auth,
			AuthenticationPassphrase: cfg.AuthKey,
			PrivacyProtocol:          gosnmp.NoPriv,
		}
		level := gosnmp.AuthNoPriv
		if cfg.PrivProto != "" {
			priv, ok := privProtos[strings.ToUpper(cfg.PrivProto)]
			if !ok {
				return nil, fmt.Errorf("snmp: unknown privacy protocol %q", cfg.PrivProto)
			}
			usm.PrivacyProtocol = priv
			usm.PrivacyPassphrase = cfg.PrivKey
			level = gosnmp.AuthPriv
		}
		g.Version = gosnmp.Version3
		g.SecurityModel = gosnmp.UserSecurityModel
		g.MsgFlags = level
		g.SecurityParameters = usm
	case V2c, "":
		if cfg.Community == "" {
			return nil, errors.New("snmp: v2c without community")
		}
		g.Version = gosnmp.Version2c
		g.Community = cfg.Community
	default:
		return nil, fmt.Errorf("snmp: unknown version %q", cfg.Version)
	}
	return g, nil
}

type liveSession struct{ g *gosnmp.GoSNMP }

func (s *liveSession) Get(ctx context.Context, oids []string) ([]gosnmp.SnmpPDU, error) {
	if len(oids) == 0 {
		return nil, nil
	}
	s.g.Context = ctx
	// A GET may carry at most as many varbinds as fit one packet; 24 is well
	// inside every device's limit and keeps the scalar reads to one round trip.
	var out []gosnmp.SnmpPDU
	for start := 0; start < len(oids); start += 24 {
		end := min(start+24, len(oids))
		res, err := s.g.Get(oids[start:end])
		if err != nil {
			return nil, err
		}
		out = append(out, res.Variables...)
	}
	return out, nil
}

func (s *liveSession) Walk(ctx context.Context, root string) ([]gosnmp.SnmpPDU, error) {
	s.g.Context = ctx
	pdus, err := s.g.BulkWalkAll(root)
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", root, err)
	}
	return pdus, nil
}

func (s *liveSession) Close() error {
	if s.g.Conn == nil {
		return nil
	}
	return s.g.Conn.Close()
}
