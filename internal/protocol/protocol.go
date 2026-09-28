// Package protocol defines the agent ↔ gateway wire format (v1).
//
// Every frame is one JSON envelope {"type": …, "seq": …, "data": {…}}. The
// set of message types is closed per direction: the agent accepts only what
// the gateway may send (welcome, config, live, update, ack) and nothing in
// that set executes arbitrary commands. The shared fixtures in testdata/ are
// the contract — the gateway's TypeScript schema loads the very same files.
//
// encoding/json/v2 is used on purpose: member names match case-sensitively
// and duplicate names are rejected, which is how the gateway parses too.
package protocol

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
)

// Version is the protocol version sent in hello and welcome.
const Version = 1

// MaxMessageBytes bounds a single frame (inventory snapshots are the largest).
const MaxMessageBytes = 4 << 20

// Type names a message.
type Type string

// Agent → gateway.
const (
	TypeHello        Type = "hello"
	TypeMetrics      Type = "metrics"
	TypeChecks       Type = "checks"
	TypeDiscovery    Type = "discovery"
	TypeInventory    Type = "inventory"
	TypeUpdateResult Type = "update_result"
	TypeSourceStatus Type = "source_status"
)

// Gateway → agent.
const (
	TypeWelcome Type = "welcome"
	TypeConfig  Type = "config"
	TypeLive    Type = "live"
	TypeUpdate  Type = "update"
	TypeAck     Type = "ack"
)

// Errors a caller may want to tell apart.
var (
	ErrTooLarge    = errors.New("message too large")
	ErrUnknownType = errors.New("unknown message type")
)

// Envelope is the frame on the wire.
//
// Seq numbers agent → gateway data messages (1, 2, …, monotonic across
// restarts because buffered messages are resent); hello carries 0. The
// gateway acknowledges with ack{seq} = highest seq it has stored, and the
// agent drops everything up to it from its buffer. Gateway → agent frames
// carry no seq.
type Envelope struct {
	Type Type           `json:"type"`
	Seq  uint64         `json:"seq,omitzero"`
	Data jsontext.Value `json:"data"`
}

// Message is any typed payload.
type Message interface {
	Validate() error
}

var fromAgent = map[Type]func() Message{
	TypeHello:        func() Message { return new(Hello) },
	TypeMetrics:      func() Message { return new(Metrics) },
	TypeChecks:       func() Message { return new(Checks) },
	TypeDiscovery:    func() Message { return new(Discovery) },
	TypeInventory:    func() Message { return new(Inventory) },
	TypeUpdateResult: func() Message { return new(UpdateResult) },
	TypeSourceStatus: func() Message { return new(SourceStatus) },
}

var fromGateway = map[Type]func() Message{
	TypeWelcome: func() Message { return new(Welcome) },
	TypeConfig:  func() Message { return new(AgentConfig) },
	TypeLive:    func() Message { return new(Live) },
	TypeUpdate:  func() Message { return new(Update) },
	TypeAck:     func() Message { return new(Ack) },
}

// DecodeFromAgent parses and validates a frame the agent sent.
func DecodeFromAgent(b []byte) (Envelope, Message, error) {
	env, msg, err := decode(b, fromAgent)
	if err != nil {
		return env, nil, err
	}
	if env.Type == TypeHello && env.Seq != 0 {
		return env, nil, errors.New("hello must not carry seq")
	}
	if env.Type != TypeHello && env.Seq == 0 {
		return env, nil, fmt.Errorf("%s requires seq", env.Type)
	}
	return env, msg, nil
}

// DecodeFromGateway parses and validates a frame the gateway sent. An
// unknown type yields ErrUnknownType: the agent logs and ignores it, it never
// guesses what a newer gateway meant.
func DecodeFromGateway(b []byte) (Envelope, Message, error) {
	env, msg, err := decode(b, fromGateway)
	if err != nil {
		return env, nil, err
	}
	if env.Seq != 0 {
		return env, nil, errors.New("gateway frames carry no seq")
	}
	return env, msg, nil
}

func decode(b []byte, allowed map[Type]func() Message) (Envelope, Message, error) {
	var env Envelope
	if len(b) > MaxMessageBytes {
		return env, nil, ErrTooLarge
	}
	if err := json.Unmarshal(b, &env); err != nil {
		return env, nil, fmt.Errorf("envelope: %w", err)
	}
	newMsg, ok := allowed[env.Type]
	if !ok {
		return env, nil, fmt.Errorf("%w: %q", ErrUnknownType, env.Type)
	}
	if len(env.Data) == 0 || env.Data.Kind() != '{' {
		return env, nil, fmt.Errorf("%s: data must be an object", env.Type)
	}
	msg := newMsg()
	if err := json.Unmarshal(env.Data, msg); err != nil {
		return env, nil, fmt.Errorf("%s: %w", env.Type, err)
	}
	if err := msg.Validate(); err != nil {
		return env, nil, fmt.Errorf("%s: %w", env.Type, err)
	}
	return env, msg, nil
}

func decodePlain[T Message](b []byte, msg T) (T, error) {
	var zero T
	if len(b) > MaxMessageBytes {
		return zero, ErrTooLarge
	}
	if err := json.Unmarshal(b, msg); err != nil {
		return zero, err
	}
	if err := msg.Validate(); err != nil {
		return zero, err
	}
	return msg, nil
}

// Encode validates msg and wraps it in an envelope.
func Encode(t Type, seq uint64, msg Message) ([]byte, error) {
	if err := msg.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", t, err)
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", t, err)
	}
	b, err := json.Marshal(Envelope{Type: t, Seq: seq, Data: data})
	if err != nil {
		return nil, err
	}
	if len(b) > MaxMessageBytes {
		return nil, ErrTooLarge
	}
	return b, nil
}
