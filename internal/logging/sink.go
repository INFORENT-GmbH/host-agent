package logging

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
)

// A Sink takes one finished log line and its level. It exists for log
// destinations that are not a byte stream — the Windows event log wants the
// severity as an argument, not as text inside the line (eventlog_windows.go).
//
// The handler below is deliberately kept out of the tagged file: this is the
// formatting every Windows log entry goes through, and keeping it untagged
// lets the tests here exercise it on every platform.
type Sink func(level slog.Level, line string)

// NewSinkLogger returns a logger that hands every record to sink.
func NewSinkLogger(sink Sink, level slog.Level) *slog.Logger {
	return slog.New(&sinkHandler{level: level, sink: sink})
}

type sinkHandler struct {
	level  slog.Level
	sink   Sink
	attrs  []slog.Attr
	groups []string
}

func (h *sinkHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.level }

// Handle renders "message key=value …". No timestamp and no level: the event
// log records both itself, the same reason the journal handler drops the
// time attribute.
func (h *sinkHandler) Handle(_ context.Context, r slog.Record) error {
	var sb strings.Builder
	sb.WriteString(r.Message)
	for _, a := range h.attrs {
		appendAttr(&sb, h.groups, a)
	}
	r.Attrs(func(a slog.Attr) bool {
		appendAttr(&sb, h.groups, a)
		return true
	})
	h.sink(r.Level, sb.String())
	return nil
}

func (h *sinkHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := *h
	out.attrs = append(append([]slog.Attr(nil), h.attrs...), attrs...)
	return &out
}

func (h *sinkHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	out := *h
	out.groups = append(append([]string(nil), h.groups...), name)
	return &out
}

func appendAttr(sb *strings.Builder, groups []string, a slog.Attr) {
	a.Value = a.Value.Resolve()
	if a.Equal(slog.Attr{}) {
		return
	}
	if a.Value.Kind() == slog.KindGroup {
		for _, g := range a.Value.Group() {
			appendAttr(sb, append(groups, a.Key), g)
		}
		return
	}
	sb.WriteByte(' ')
	for _, g := range groups {
		sb.WriteString(g)
		sb.WriteByte('.')
	}
	sb.WriteString(a.Key)
	sb.WriteByte('=')
	v := a.Value.String()
	if strings.ContainsAny(v, " \"") {
		_, _ = fmt.Fprintf(sb, "%q", v)
		return
	}
	sb.WriteString(v)
}
