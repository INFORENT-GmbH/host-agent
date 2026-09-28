// Package localchecks runs Checkmk-compatible local checks and MRPE
// entries, so existing check scripts keep working without changes.
//
// Local check line:  <state> <service> <metrics> <detail>
//
//	state    0|1|2|3, or P (the gateway judges the metrics' levels)
//	service  one word, or "double quoted" when it contains spaces
//	metrics  "-" or name=value;warn;crit;min;max joined by "|"
//	detail   free text; a literal \n starts a new line
//
// MRPE runs Nagios plugins: the exit code is the state, the first output
// line is "text | perfdata".
package localchecks

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

// ParseLocalLine parses one line of local check output.
func ParseLocalLine(line string) (protocol.CheckResult, error) {
	rest := strings.TrimSpace(line)
	stateTok, rest, _ := strings.Cut(rest, " ")
	rest = strings.TrimLeft(rest, " ")

	var name string
	if strings.HasPrefix(rest, `"`) {
		end := strings.Index(rest[1:], `"`)
		if end < 0 {
			return protocol.CheckResult{}, errors.New("unterminated quoted service name")
		}
		name, rest = rest[1:end+1], strings.TrimLeft(rest[end+2:], " ")
	} else {
		name, rest, _ = strings.Cut(rest, " ")
		rest = strings.TrimLeft(rest, " ")
	}
	if name == "" {
		return protocol.CheckResult{}, errors.New("service name missing")
	}

	metricsTok, detail, _ := strings.Cut(rest, " ")
	r := protocol.CheckResult{Plugin: "local", Item: name, Summary: strings.ReplaceAll(detail, `\n`, "\n")}

	if metricsTok != "-" && metricsTok != "" {
		perf, err := parseLocalMetrics(metricsTok)
		if err != nil {
			return protocol.CheckResult{}, fmt.Errorf("%s: %w", name, err)
		}
		r.Perf = perf
	}

	switch stateTok {
	case "0", "1", "2", "3":
		s := protocol.State(stateTok[0] - '0')
		r.State = &s
	case "P":
		if len(r.Perf) == 0 {
			return protocol.CheckResult{}, fmt.Errorf("%s: state P needs metrics with levels", name)
		}
	default:
		return protocol.CheckResult{}, fmt.Errorf("%s: invalid state %q", name, stateTok)
	}
	return r, nil
}

// parseLocalMetrics parses "a=1;2;3;0;10|b=5".
func parseLocalMetrics(s string) ([]protocol.Perf, error) {
	var out []protocol.Perf
	for _, part := range strings.Split(s, "|") {
		if part == "" {
			continue
		}
		name, spec, ok := strings.Cut(part, "=")
		if !ok || name == "" {
			return nil, fmt.Errorf("metric %q: want name=value", part)
		}
		p, err := parsePerfSpec(name, spec)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// ParseNagiosOutput turns plugin output and exit code into a result.
// Exit codes outside 0..3 are UNKNOWN, as Nagios defines.
func ParseNagiosOutput(name string, out []byte, exitCode int) protocol.CheckResult {
	text := strings.TrimRight(string(out), "\n")
	first, long, _ := strings.Cut(text, "\n")
	summary, perfText, _ := strings.Cut(first, "|")
	summary = strings.TrimSpace(summary)
	if long = strings.TrimSpace(long); long != "" {
		// Long output may carry more perfdata after its own "|".
		longText, morePerf, _ := strings.Cut(long, "|")
		summary += "\n" + strings.TrimSpace(longText)
		perfText += " " + morePerf
	}
	state := protocol.StateUnknown
	if exitCode >= 0 && exitCode <= 3 {
		state = protocol.State(exitCode)
	}
	r := protocol.CheckResult{Plugin: "mrpe", Item: name, State: &state, Summary: summary}
	// A malformed perfdata token only loses that metric, never the state.
	r.Perf, _ = parseNagiosPerf(perfText)
	return r
}

// parseNagiosPerf parses "'label one'=10ms;20;30;0;100 load=0.5".
func parseNagiosPerf(s string) ([]protocol.Perf, error) {
	var (
		out  []protocol.Perf
		errs []error
	)
	s = strings.TrimSpace(s)
	for s != "" {
		var label string
		if strings.HasPrefix(s, "'") {
			// '' inside a quoted label is an escaped quote.
			i := 1
			var sb strings.Builder
			for i < len(s) {
				if s[i] == '\'' {
					if i+1 < len(s) && s[i+1] == '\'' {
						sb.WriteByte('\'')
						i += 2
						continue
					}
					break
				}
				sb.WriteByte(s[i])
				i++
			}
			if i >= len(s) || i+1 >= len(s) || s[i+1] != '=' {
				errs = append(errs, errors.New("unterminated quoted perfdata label"))
				break
			}
			label, s = sb.String(), s[i+2:]
		} else {
			eq := strings.IndexByte(s, '=')
			if eq <= 0 {
				errs = append(errs, fmt.Errorf("perfdata %q: want label=value", s))
				break
			}
			label, s = s[:eq], s[eq+1:]
		}
		spec, rest, _ := strings.Cut(s, " ")
		s = strings.TrimLeft(rest, " ")
		p, err := parsePerfSpec(label, spec)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, p)
	}
	return out, errors.Join(errs...)
}

// parsePerfSpec parses "value[unit];warn;crit;min;max". Range levels
// ("10:20", "@5:10") are not representable in the protocol's single
// warn/crit numbers; such a level is dropped rather than misread as a
// plain threshold.
func parsePerfSpec(name, spec string) (protocol.Perf, error) {
	fields := strings.Split(spec, ";")
	value, unit, err := valueUnit(fields[0])
	if err != nil {
		return protocol.Perf{}, fmt.Errorf("metric %s: %w", name, err)
	}
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return protocol.Perf{}, fmt.Errorf("metric %s: value is not finite", name)
	}
	p := protocol.Perf{Name: name, Value: value, Unit: unit}
	targets := []**float64{&p.Warn, &p.Crit, &p.Min, &p.Max}
	for i, f := range fields[1:] {
		if i >= len(targets) {
			break
		}
		f = strings.TrimSpace(f)
		if f == "" || strings.ContainsAny(f, ":@~") {
			continue
		}
		v, err := strconv.ParseFloat(f, 64)
		if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
			return protocol.Perf{}, fmt.Errorf("metric %s: level %q is not a finite number", name, f)
		}
		*targets[i] = &v
	}
	return p, nil
}

func valueUnit(s string) (float64, string, error) {
	s = strings.TrimSpace(s)
	end := len(s)
	for end > 0 && !strings.ContainsRune("0123456789.", rune(s[end-1])) {
		end--
	}
	v, err := strconv.ParseFloat(s[:end], 64)
	if err != nil {
		return 0, "", fmt.Errorf("value %q is not a number", s)
	}
	return v, s[end:], nil
}
