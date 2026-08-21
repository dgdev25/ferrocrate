#!/usr/bin/env bash
set -euo pipefail

# Bounded native cross-target probe. The networking crate, shared core library,
# and CLI binary are checked independently so a foreign target cannot silently
# regress back to Linux-only compile assumptions. Runtime execution remains a
# separate native-host qualification.
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

/usr/bin/timeout --foreground "${FERROCRATE_CROSS_TIMEOUT_SECONDS:-240}s" \
  env CARGO_TARGET_DIR="$target_dir" \
  cargo "+$toolchain" check -p ferro-core --lib --target "$target"

/usr/bin/timeout --foreground "${FERROCRATE_CROSS_TIMEOUT_SECONDS:-240}s" \
  env CARGO_TARGET_DIR="$target_dir" \
  cargo "+$toolchain" check -p ferro-cli --target "$target"

echo "native cross-target ferro-net, ferro-core, and ferro-cli checks passed: $target"
