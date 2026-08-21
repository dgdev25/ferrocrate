#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

# A host without the requested Rust target must fail before packaging a
# mislabeled host binary. macOS is intentionally not installed on this Linux
# worker, so this is a deterministic preflight assertion rather than a native
# macOS qualification claim.
if PATH="$repo_root/scripts/test-fixtures:$PATH" \
  bash "$repo_root/scripts/build-release-artifacts.sh" \
    --version v0.0.1 --channel public --target-os macos --target-arch aarch64 \
    --target-dir "$tmp_dir/target" --output-dir "$tmp_dir/release" \
    >"$tmp_dir/output.txt" 2>&1; then
  echo "uninstalled macOS target unexpectedly produced an artifact" >&2
  exit 1
fi
grep -q 'Rust target is not installed: aarch64-apple-darwin' "$tmp_dir/output.txt"
test ! -e "$tmp_dir/release/ferrocrate-v0.0.1-macos-aarch64.tar.gz"

echo "cross-platform release target preflight passed"
