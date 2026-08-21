#!/usr/bin/env bash
set -euo pipefail

# Bounded native cross-target probe. This intentionally checks the portable
# networking crate first; the complete CLI remains a separate gate until the
# higher-level core modules have non-Linux implementations.
target="${1:-x86_64-pc-windows-gnu}"
toolchain="${FERROCRATE_CROSS_TOOLCHAIN:-nightly-2026-02-11}"
repo_root="$(cd "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

if ! rustup target list --toolchain "$toolchain" --installed | grep -Fxq "$target"; then
  echo "SKIP: Rust target is not installed: $target" >&2
  exit 77
fi

target_dir="$(mktemp -d /tmp/ferrocrate-cross-target.XXXXXX)"
trap 'rm -rf "$target_dir"' EXIT

/usr/bin/timeout --foreground "${FERROCRATE_CROSS_TIMEOUT_SECONDS:-240}s" \
  env CARGO_TARGET_DIR="$target_dir" \
  cargo "+$toolchain" check -p ferro-net --lib --target "$target"

echo "native cross-target ferro-net check passed: $target"
