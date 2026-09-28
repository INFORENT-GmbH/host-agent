# host-agent

[![CI](https://github.com/INFORENT-GmbH/host-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/INFORENT-GmbH/host-agent/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/INFORENT-GmbH/host-agent.svg)](https://pkg.go.dev/github.com/INFORENT-GmbH/host-agent)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

The server monitoring agent of the INFORENT portal. It runs on Linux and Windows
servers, collects metrics and service checks, and reports them to the portal's
monitoring gateway over a single outbound TLS connection.

This repository contains the complete source of the agent that is shipped to
customer servers — the same code, the same build flags, the same packaging
templates. It is published so that anyone who installs the agent can read
exactly what runs on their machine.

## Features

- **Metrics** — CPU, memory, filesystems, disk I/O, network throughput, link
  state and time synchronisation. Collectors report raw values; thresholds and
  states are evaluated server-side.
- **Service checks with discovery** — filesystems, network interfaces, systemd
  units or Windows services, load, CPU, memory, uptime, time sync, pending
  (security) updates and required reboots.
- **Checkmk-compatible local checks and MRPE** — existing scripts from
  `/usr/lib/check_mk_agent/local` and `/etc/check_mk/mrpe.cfg` (or the Checkmk
  Windows equivalents) keep working without changes, including the
  `MK_*` environment variables and cached (`local/<seconds>/`) checks.
- **SNMP satellite mode** — optionally polls network devices (interfaces,
  storage, sensors, load) on the portal's behalf. Only enabled locally, never
  remotely.
- **Loses nothing on outages** — outgoing data is buffered on disk until the
  gateway acknowledges it, within size and age limits.
- **Works through restrictive networks** — WebSocket first, HTTPS push as a
  fallback when WebSockets are blocked; honours `HTTPS_PROXY`.
- **Self-update** — through the brand's own signed apt repository on Linux and
  a checksummed MSI on Windows, on the update channel chosen at enrollment
  (`stable`, `testing` or `off`).
- **White-label** — one build serves every brand: the binary derives its name
  and all paths from the name it is installed under (`/usr/bin/<brand>-agent`,
  `/etc/<brand>-agent/`, `/var/lib/<brand>-agent/`).

## Security model

The agent runs with elevated privileges on servers it does not own, so its
design keeps the portal's reach deliberately small:

- **Nothing listens on the host.** All traffic is one outbound connection to
  the gateway, authenticated with a per-host token.
- **The server cannot run commands.** The protocol is a closed set of message
  types. The gateway can adjust collection intervals, switch collectors off,
  request live mode and trigger an update to a released version — nothing
  else. Anything outside the protocol is rejected.
- **Updates come only from the brand's own package source** — apt verifies the
  repository signature; on Windows the MSI must match the SHA-256 from the
  release manifest.
- **Configuration and scripts are permission-checked.** `agent.conf` carries
  the host token and is refused unless it is owned by root (or SYSTEM and
  Administrators on Windows) and unreadable for others. Local check scripts
  and their directories must not be writable by unprivileged users, or they
  are not executed. No command prints the host token.
- **Sandboxed service.** The systemd unit uses `ProtectSystem=strict`,
  `NoNewPrivileges`, `PrivateTmp` and memory/CPU limits.
- **Secrets stay in memory.** SNMP credentials handed over in satellite mode
  are never written to disk.

The static analysis gate includes `gosec`. See [SECURITY.md](SECURITY.md) for
how to report a vulnerability.

## Supported platforms

| Platform | Architectures | Packaging |
|---|---|---|
| Debian, Ubuntu (systemd) | amd64, arm64 | `.deb` from the brand's apt repository |
| Windows Server 2016+ / Windows 10+ | amd64 | MSI, Windows service |

## Usage

The agent is installed and enrolled with the setup command shown in the
portal (*Monitoring → Servers → Add server*). The CLI:

```
<brand>-agent enroll -url https://<gateway> -token <token>   # register this host
<brand>-agent status                                         # configuration and enrollment state
<brand>-agent dump                                           # collect once, print, send nothing
<brand>-agent version
```

`dump` is the quickest way to see exactly what the agent would transmit.

## Building from source

Requires the Go version from [`go.mod`](go.mod).

```sh
go build -trimpath \
  -ldflags "-s -w -X github.com/INFORENT-GmbH/host-agent/internal/buildinfo.Version=$(cat VERSION)" \
  -o acme-agent ./cmd/agent
./acme-agent dump
```

The brand comes from the binary name (`acme-agent` → brand `acme`); for
`go run` set `AGENT_BRAND=acme` instead. `packaging/build.sh <brand>` builds a
`.deb` locally with [nfpm](https://nfpm.goreleaser.com/). Release builds use
exactly these flags with `CGO_ENABLED=0`; the version comes from
[`VERSION`](VERSION).

## Repository layout

```
cmd/agent/            CLI: enroll, run, dump, status, service handling
internal/agent/       main loop, scheduling, satellite mode
internal/collect/     metric collectors
internal/checks/      service discovery and checks
internal/localchecks/ Checkmk-compatible local checks and MRPE
internal/poll/snmp/   SNMP polling for satellite mode
internal/protocol/    wire format v1 — testdata/ holds the shared fixtures
internal/transport/   WebSocket + HTTPS push transport
internal/buffer/      on-disk send buffer
internal/update/      self-update (apt / MSI)
internal/config/      agent.conf (TOML) with permission checks
internal/winsec/      Windows ACL checks
packaging/            systemd unit, deb scripts, MSI, install scripts
```

The protocol fixtures in `internal/protocol/testdata` are the contract with
the gateway: the gateway's test suite accepts every valid fixture and rejects
every invalid one.

## Development

This repository is a read-only mirror: development happens in the portal's
internal repository and is synced here on every change, with a tag per agent
version. See [CONTRIBUTING.md](CONTRIBUTING.md) for issues and pull requests.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
