#!/usr/bin/env bash
# Builds a brand's deb package locally:
#   packaging/build.sh <brand> [version] [arch]   (version: defaults to VERSION)
# Example: packaging/build.sh acme 1.0.0 amd64
# The portal's release pipeline uses the same templates; signing happens
# there, not here.
set -euo pipefail
cd "$(dirname "$0")/.."

NFPM_VERSION=v2.47.0

BRAND="${1:?usage: packaging/build.sh <brand> [version] [arch]}"
# Without an argument, take the version from VERSION (as the release build does).
VERSION="${2:-$(tr -d ' \r\n' < VERSION)}"
ARCH="${3:-amd64}"

# keep in sync: BRAND_KEY_RE (api/src/settings/brands.ts), keyRE (internal/brand)
[[ "$BRAND" =~ ^[a-z][a-z0-9-]{1,22}[a-z0-9]$ ]] || { echo "invalid brand key: $BRAND" >&2; exit 2; }
# Same pattern as versionRE (internal/protocol) — the version becomes an apt argument.
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]{1,32})?$ ]] || { echo "invalid version: $VERSION" >&2; exit 2; }

export BRAND VERSION ARCH
export MAINTAINER="${MAINTAINER:-$BRAND-agent packaging}"

mkdir -p dist
GOOS=linux GOARCH="$ARCH" CGO_ENABLED=0 \
    go build -trimpath -ldflags "-s -w -X github.com/INFORENT-GmbH/host-agent/internal/buildinfo.Version=$VERSION" \
    -o "dist/$BRAND-agent-$ARCH" ./cmd/agent

# We render ${…} ourselves — nfpm's own env substitution does not apply everywhere.
render() { sed -e "s/\${BRAND}/$BRAND/g" -e "s/\${VERSION}/$VERSION/g" \
    -e "s/\${ARCH}/$ARCH/g" -e "s/\${MAINTAINER}/$MAINTAINER/g" "$1" > "$2"; }
for f in agent.service postinstall.sh preremove.sh postremove.sh; do
    render "packaging/$f.in" "dist/$f"
done
render packaging/nfpm.yaml dist/nfpm.yaml

go run "github.com/goreleaser/nfpm/v2/cmd/nfpm@$NFPM_VERSION" package \
    -f dist/nfpm.yaml -p deb -t dist/
