#!/bin/sh
set -eu
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
mkdir -p "$ROOT/dist" "$ROOT/agent-dist"
for arch in amd64 arm64; do
  (cd "$ROOT/agent" && GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$ROOT/dist/kvnradar-agent-linux-$arch" .)
  cp "$ROOT/dist/kvnradar-agent-linux-$arch" "$ROOT/agent-dist/kvnradar-agent-linux-$arch"
done
(cd "$ROOT/agent-dist" && sha256sum kvnradar-agent-linux-amd64 kvnradar-agent-linux-arm64 > SHA256SUMS)
echo 'Built Linux amd64/arm64 agents and agent-dist SHA256SUMS.'
