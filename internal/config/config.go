// Package config reads and writes agent.conf. The file carries the host
// token, so it must be owned by root and unreadable for anyone else — a
// looser file is refused rather than silently used.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// ErrInsecure means agent.conf is readable or writable by someone other than
// its owner, or not owned by root while the agent runs as root.
var ErrInsecure = errors.New("insecure config file")

// Config is the whole agent.conf.
type Config struct {
	Server Server `toml:"server"`
	Local  Local  `toml:"local"`
	Log    Log    `toml:"log"`
}

// Server is written by `enroll`.
type Server struct {
	// URL is the gateway's base URL, https://host. The WebSocket
	// (wss://host/v1/ws) and push (https://host/v1/push) endpoints derive from it.
	URL string `toml:"url"`
	// Token is the per-host bearer token. Only its hash exists server-side.
	Token string `toml:"token"`
	// PackageBase is the HTTPS base the Windows self-update fetches its
	// manifest and MSI from (https://apt.<brand>). The Windows install script
	// writes it; on Linux it is empty and unused (apt uses its own source).
	PackageBase string `toml:"package_base,omitempty"`
}

// Local holds the opt-ins that only the host operator can grant — the portal
// can never switch these on remotely.
type Local struct {
	// Satellite allows polling other targets (SNMP, IPMI, …) on the portal's behalf.
	Satellite bool `toml:"satellite"`
	// LocalChecks runs local check scripts and MRPE entries.
	LocalChecks bool `toml:"local_checks"`
}

// Log controls agent logging.
type Log struct {
	Level string `toml:"level"`
}

// Default is the configuration of a freshly installed, not yet enrolled agent.
func Default() Config {
	return Config{
		Local: Local{Satellite: false, LocalChecks: true},
		Log:   Log{Level: "info"},
	}
}

// Enrolled reports whether the agent has a gateway and a token.
func (c Config) Enrolled() bool {
	return c.Server.URL != "" && c.Server.Token != ""
}

// Validate checks values that TOML decoding cannot.
func (c Config) Validate() error {
	if c.Server.URL != "" {
		u, err := url.Parse(c.Server.URL)
		if err != nil {
			return fmt.Errorf("server.url: %w", err)
		}
		if u.Scheme != "https" {
			return fmt.Errorf("server.url: scheme must be https, got %q", u.Scheme)
		}
		if u.Host == "" {
			return errors.New("server.url: host missing")
		}
	}
	if (c.Server.URL == "") != (c.Server.Token == "") {
		return errors.New("server.url and server.token must be set together")
	}
	switch strings.ToLower(c.Log.Level) {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log.level: unknown level %q", c.Log.Level)
	}
	return nil
}

// Load reads path. A missing file is returned as an error wrapping
// os.ErrNotExist so callers can treat "not installed/enrolled" separately.
// Unknown keys are rejected: a typo must not silently fall back to a default.
func Load(path string) (Config, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Config{}, err
	}
	if err := checkSecure(path, info); err != nil {
		return Config{}, err
	}
	cfg := Default()
	md, err := toml.DecodeFile(path, &cfg)
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for i, k := range undecoded {
			keys[i] = k.String()
		}
		return Config{}, fmt.Errorf("%s: unknown keys: %s", path, strings.Join(keys, ", "))
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// Save writes cfg atomically with mode 0600: temp file in the same
// directory, fsync, rename, fsync the directory. A crash leaves either the
// old or the new file, never a truncated one.
func Save(path string, cfg Config) (err error) {
	if err := cfg.Validate(); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".agent.conf.*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp.Name())
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := toml.NewEncoder(tmp).Encode(cfg); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(dir) // #nosec G304 -- directory of our own config path
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// checkSecure asks the platform whether agent.conf — which holds the host
// token — can be read or written by anyone but the agent's own account. What
// that means differs: Unix looks at mode bits and the owning uid, Windows at
// the file's owner SID, because Go reports a meaningless 0666 there.
func checkSecure(path string, info os.FileInfo) error {
	return checkFileSecurity(path, info)
}
