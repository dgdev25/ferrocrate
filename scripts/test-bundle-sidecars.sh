#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d /tmp/ferrocrate-sidecars.XXXXXX)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/target/test-triple/release" "$tmp/out"
printf '#!/bin/sh\n' >"$tmp/target/test-triple/release/ferro-cli"
printf '#!/bin/sh\n' >"$tmp/target/test-triple/release/ferro-desktop"
chmod +x "$tmp/target/test-triple/release/ferro-cli" "$tmp/target/test-triple/release/ferro-desktop"

CARGO_TARGET_DIR="$tmp/target" FERROCRATE_SIDECAR_DIR="$tmp/out" \
  bash "$repo_root/scripts/bundle-sidecars.sh" test-triple

cmp "$tmp/target/test-triple/release/ferro-cli" "$tmp/out/ferrocrate-test-triple"
cmp "$tmp/target/test-triple/release/ferro-desktop" "$tmp/out/ferro-desktop-sidecar-test-triple"
echo "sidecar staging regression passed"
