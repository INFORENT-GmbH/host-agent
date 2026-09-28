// Package buildinfo holds the values stamped into the binary at link time.
package buildinfo

// Version is the agent release, set by the build via
// -ldflags "-X github.com/INFORENT-GmbH/host-agent/internal/buildinfo.Version=<version>".
// A plain `go build` reports "dev".
var Version = "dev"
