# Contributing

Thank you for looking into the agent.

## How this repository works

This repository is a **mirror**. The agent is developed together with the
portal and its gateway in an internal repository, because protocol changes
must land on both sides at once. Every change is synced here automatically,
and every agent version is tagged (`v<version>`).

- **Issues** are welcome — bug reports, platform quirks, feature requests.
- **Pull requests** are welcome, too. We review them here and, once accepted,
  apply them in the internal repository with you as the commit author; the
  change then arrives here with the next sync and the pull request is closed
  with a reference to it.
- **Security problems**: see [SECURITY.md](SECURITY.md) — please not as a
  public issue.

## Development

Requires the Go version from [`go.mod`](go.mod). The same gates run in CI:

```sh
go mod tidy -diff
go vet ./...
golangci-lint run          # configuration: .golangci.yml
go test ./...
GOOS=windows go vet ./...  # Windows build incl. tests
```

To try the agent locally without installing it:

```sh
AGENT_BRAND=dev go run ./cmd/agent dump   # collects once, prints, sends nothing
```

Guidelines:

- Collectors and checks report raw values; thresholds belong to the server.
- Every new message type or field needs fixtures in
  `internal/protocol/testdata` (valid and invalid).
- Platform-specific code goes behind `_linux.go`/`_windows.go`/`_unix.go`;
  keep the logic in untagged files so it is tested on every platform.
- The agent must never gain a way to execute commands on the server's behalf.
