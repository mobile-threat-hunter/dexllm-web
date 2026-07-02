#!/usr/bin/env bash
# Refresh the embedded static bundle from the repo root and cross-compile
# the Windows launcher to dist/dexllm-web.exe (and a native binary alongside
# main.go for local smoke-test).
#
# Run this after any of the deployed artifacts at the repo root change:
#   index.html / worker.js / dexllm.js / dexllm.wasm / perm_api.json / perm_levels.json
# The exe embeds them at build time, so the binary needs a refresh whenever
# the GitHub Pages bundle does.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"

# Pull the deployed bundle into static/ for go:embed
mkdir -p "$here/static"
for f in index.html worker.js dexllm.js dexllm.wasm perm_api.json perm_levels.json loop.mp4 trans.mp4; do
  cp "$root/$f" "$here/static/"
done

cd "$here"

# Native build — quick smoke test target. -s -w strips debug info; -trimpath
# wipes local paths from the binary so it doesn't leak the build machine.
go build -ldflags="-s -w" -trimpath -o dexllm-web

# Windows cross-build — what users actually download. Console subsystem
# (no -H windowsgui) so the URL + Ctrl+C hint print to a visible window.
mkdir -p "$root/dist"
GOOS=windows GOARCH=amd64 go build \
  -ldflags="-s -w" -trimpath \
  -o "$root/dist/dexllm-web.exe"

native_size=$(stat -c %s dexllm-web)
win_size=$(stat -c %s "$root/dist/dexllm-web.exe")
printf "\nBuilt:\n"
printf "  %-40s %d bytes\n" "$(realpath dexllm-web)" "$native_size"
printf "  %-40s %d bytes\n" "$root/dist/dexllm-web.exe" "$win_size"
