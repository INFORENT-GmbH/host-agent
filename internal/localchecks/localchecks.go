package localchecks

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/INFORENT-GmbH/host-agent/internal/brand"
	"github.com/INFORENT-GmbH/host-agent/internal/checks"
	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

// DefaultTimeout bounds one script run.
const DefaultTimeout = 60 * time.Second

// maxParallel scripts run at the same time.
const maxParallel = 4

// Check runs local check scripts and MRPE entries. It implements
// checks.Check; results carry plugin "local" or "mrpe".
type Check struct {
	LocalDirs   []string
	MRPEFiles   []string
	Timeout     time.Duration
	RequireRoot bool

	mu    sync.Mutex
	cache map[string]cached // key: script path or "mrpe:"+name
	last  []protocol.CheckResult
}

type cached struct {
	at      time.Time
	results []protocol.CheckResult
}

// New returns a check reading Checkmk's paths plus the brand's own
// (<config dir>/local.d and <config dir>/mrpe.cfg).
func New(b brand.Brand) *Check {
	localDir, mrpeFile := checkmkPaths(b.Root)
	return &Check{
		LocalDirs:   []string{localDir, filepath.Join(b.ConfigDir(), "local.d")},
		MRPEFiles:   []string{mrpeFile, filepath.Join(b.ConfigDir(), "mrpe.cfg")},
		Timeout:     DefaultTimeout,
		RequireRoot: runningPrivileged(),
	}
}

var _ checks.Check = (*Check)(nil)

// Plugin implements checks.Check.
func (*Check) Plugin() string { return "local" }

// Discover returns the services the scripts produced on their latest run
// (running them first if they never ran). Local checks name their own
// services, so there is no other way to know them.
func (c *Check) Discover(ctx context.Context) ([]protocol.DiscoveredItem, error) {
	c.mu.Lock()
	last := c.last
	c.mu.Unlock()
	var err error
	if last == nil {
		last, err = c.Run(ctx, time.Now())
	}
	items := make([]protocol.DiscoveredItem, 0, len(last))
	for _, r := range last {
		items = append(items, protocol.DiscoveredItem{Plugin: r.Plugin, Item: r.Item})
	}
	return items, err
}

type job struct {
	key      string
	interval time.Duration
	run      func(ctx context.Context) ([]protocol.CheckResult, error)
}

// Run executes every script and MRPE entry that is due and returns the
// results of all of them (cached ones included). Duplicate service names
// keep the first occurrence.
func (c *Check) Run(ctx context.Context, now time.Time) ([]protocol.CheckResult, error) {
	jobs, errs := c.jobs()

	c.mu.Lock()
	if c.cache == nil {
		c.cache = map[string]cached{}
	}
	c.mu.Unlock()

	sem := make(chan struct{}, maxParallel)
	var (
		wg     sync.WaitGroup
		errMu  sync.Mutex
		fresh  = make([][]protocol.CheckResult, len(jobs))
		useOld = make([]bool, len(jobs))
	)
	for i, j := range jobs {
		c.mu.Lock()
		prev, ok := c.cache[j.key]
		c.mu.Unlock()
		if ok && j.interval > 0 && now.Sub(prev.at) < j.interval {
			useOld[i] = true
			fresh[i] = prev.results
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res, err := j.run(ctx)
			if err != nil {
				errMu.Lock()
				errs = append(errs, fmt.Errorf("%s: %w", j.key, err))
				errMu.Unlock()
			}
			fresh[i] = res
		}()
	}
	wg.Wait()

	seen := map[[2]string]bool{}
	var out []protocol.CheckResult
	c.mu.Lock()
	for i, j := range jobs {
		if !useOld[i] {
			c.cache[j.key] = cached{at: now, results: fresh[i]}
		}
		for _, r := range fresh[i] {
			key := [2]string{r.Plugin, r.Item}
			if seen[key] {
				errs = append(errs, fmt.Errorf("%s: duplicate service %q ignored", j.key, r.Item))
				continue
			}
			seen[key] = true
			out = append(out, r)
		}
	}
	c.last = out
	c.mu.Unlock()
	return out, errors.Join(errs...)
}

// jobs lists everything to run. Scripts in a numeric subdirectory
// (local/300/check) run at most every that many seconds, as in Checkmk.
func (c *Check) jobs() ([]job, []error) {
	var (
		jobs []job
		errs []error
	)
	for _, dir := range c.LocalDirs {
		entries, err := os.ReadDir(dir)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, e := range entries {
			path := filepath.Join(dir, e.Name())
			if e.IsDir() {
				secs, err := strconv.Atoi(e.Name())
				if err != nil || secs <= 0 {
					continue
				}
				sub, err := os.ReadDir(path)
				if err != nil {
					errs = append(errs, err)
					continue
				}
				for _, se := range sub {
					if !se.IsDir() && runnable(se.Name()) {
						jobs = append(jobs, c.scriptJob(dir, filepath.Join(path, se.Name()), time.Duration(secs)*time.Second))
					}
				}
				continue
			}
			if runnable(e.Name()) {
				jobs = append(jobs, c.scriptJob(dir, path, 0))
			}
		}
	}
	for _, file := range c.MRPEFiles {
		entries, err := c.mrpeEntries(file)
		if err != nil {
			errs = append(errs, err)
		}
		for _, m := range entries {
			jobs = append(jobs, job{
				key:      "mrpe:" + m.Name,
				interval: m.Interval,
				run: func(ctx context.Context) ([]protocol.CheckResult, error) {
					out, code, err := runCommand(ctx, c.timeout(), "/bin/sh", "-c", m.Command)
					if err != nil {
						s := protocol.StateUnknown
						return []protocol.CheckResult{{Plugin: "mrpe", Item: m.Name, State: &s, Summary: checks.Summary(err.Error())}}, nil
					}
					return []protocol.CheckResult{sanitize(ParseNagiosOutput(m.Name, out, code))}, nil
				},
			})
		}
	}
	slices.SortFunc(jobs, func(a, b job) int { return strings.Compare(a.key, b.key) })
	return jobs, errs
}

func (c *Check) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return DefaultTimeout
}

// runnable skips hidden files and package manager leftovers.
func runnable(name string) bool {
	if strings.HasPrefix(name, ".") || strings.HasSuffix(name, "~") {
		return false
	}
	for _, suffix := range []string{".dpkg-old", ".dpkg-new", ".dpkg-dist", ".rpmsave", ".rpmnew", ".bak", ".swp"} {
		if strings.HasSuffix(name, suffix) {
			return false
		}
	}
	return true
}

// scriptJob: a script failing to run (timeout, not executable, insecure)
// yields no results and an error — its services go stale and the gateway
// marks them UNKNOWN, exactly like a script that silently stopped printing.
func (c *Check) scriptJob(base, path string, interval time.Duration) job {
	return job{
		key:      path,
		interval: interval,
		run: func(ctx context.Context) ([]protocol.CheckResult, error) {
			info, err := os.Stat(path)
			if err != nil {
				return nil, err
			}
			if !isExecutableScript(path, info) {
				return nil, nil // not executable: silently skipped, like Checkmk
			}
			chain := []string{path}
			for d := filepath.Dir(path); ; d = filepath.Dir(d) {
				chain = append(chain, d)
				if d == base || d == filepath.Dir(d) {
					break
				}
			}
			if err := checkSecure(c.RequireRoot, chain...); err != nil {
				return nil, err
			}
			out, _, err := runCommand(ctx, c.timeout(), path)
			if err != nil {
				return nil, err
			}
			var (
				results []protocol.CheckResult
				errs    []error
			)
			sc := bufio.NewScanner(bytes.NewReader(out))
			sc.Buffer(make([]byte, 64*1024), maxOutput)
			for sc.Scan() {
				line := sc.Text()
				if strings.TrimSpace(line) == "" {
					continue
				}
				r, err := ParseLocalLine(line)
				if err != nil {
					errs = append(errs, err)
					continue
				}
				results = append(results, sanitize(r))
			}
			return results, errors.Join(errs...)
		},
	}
}

type mrpeEntry struct {
	Name     string
	Interval time.Duration
	Command  string
}

var mrpeOptionsRE = regexp.MustCompile(`^\(([^)]*)\)\s+`)

func (c *Check) mrpeEntries(file string) ([]mrpeEntry, error) {
	b, err := os.ReadFile(file) // #nosec G304 -- configured MRPE file, checked below
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := checkSecure(c.RequireRoot, file, filepath.Dir(file)); err != nil {
		return nil, err
	}
	return parseMRPE(string(b))
}

// parseMRPE reads "Name [(interval=N:...)] command" lines.
func parseMRPE(s string) ([]mrpeEntry, error) {
	var (
		out  []mrpeEntry
		errs []error
	)
	for n, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, rest, ok := strings.Cut(line, " ")
		rest = strings.TrimSpace(rest)
		if !ok || rest == "" {
			errs = append(errs, fmt.Errorf("mrpe line %d: want 'name command'", n+1))
			continue
		}
		e := mrpeEntry{Name: name}
		if m := mrpeOptionsRE.FindStringSubmatch(rest); m != nil {
			rest = rest[len(m[0]):]
			for _, opt := range strings.Split(m[1], ":") {
				if k, v, ok := strings.Cut(opt, "="); ok && k == "interval" {
					if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
						e.Interval = time.Duration(secs) * time.Second
					}
				}
			}
		}
		e.Command = rest
		out = append(out, e)
	}
	return out, errors.Join(errs...)
}

// sanitize fits a result into protocol limits instead of dropping it: one
// odd character in a script's output must not invalidate the whole checks
// message of the host.
func sanitize(r protocol.CheckResult) protocol.CheckResult {
	r.Item = singleLine(r.Item, protocol.MaxItemLen)
	r.Summary = checks.Summary(r.Summary)
	if len(r.Perf) > protocol.MaxPerf {
		r.Perf = r.Perf[:protocol.MaxPerf]
	}
	for i := range r.Perf {
		r.Perf[i].Name = singleLine(r.Perf[i].Name, 64)
		r.Perf[i].Unit = singleLine(r.Perf[i].Unit, 16)
	}
	return r
}

// singleLine replaces control characters (the protocol's rule is
// unicode.IsControl) and cuts to maxRunes.
func singleLine(s string, maxRunes int) string {
	s = strings.Map(func(ch rune) rune {
		if unicode.IsControl(ch) {
			return ' '
		}
		return ch
	}, s)
	if utf8.RuneCountInString(s) > maxRunes {
		s = string([]rune(s)[:maxRunes])
	}
	return s
}
