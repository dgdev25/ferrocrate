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
  FERROCRATE_TEST_RUSTUP_TARGETS="" \
  bash "$repo_root/scripts/build-release-artifacts.sh" \
    --version v0.0.1 --channel public --target-os macos --target-arch aarch64 \
    --target-dir "$tmp_dir/target" --output-dir "$tmp_dir/release" \
    >"$tmp_dir/output.txt" 2>&1; then
  echo "uninstalled macOS target unexpectedly produced an artifact" >&2
  exit 1
fi
grep -q 'Rust target is not installed: aarch64-apple-darwin' "$tmp_dir/output.txt"
test ! -e "$tmp_dir/release/ferrocrate-v0.0.1-macos-aarch64.tar.gz"

# With a hermetic Cargo/rustup fixture, exercise every supported target tuple
# through packaging, checksums, and provenance generation. This validates the
# mapping and archive naming without pretending that Linux can execute native
# Windows/macOS workloads.
targets=(
  "linux x86_64 x86_64-unknown-linux-gnu tar.gz"
  "linux aarch64 aarch64-unknown-linux-gnu tar.gz"
  "macos x86_64 x86_64-apple-darwin tar.gz"
  "macos aarch64 aarch64-apple-darwin tar.gz"
  "windows x86_64 x86_64-pc-windows-gnu zip"
  "windows aarch64 aarch64-pc-windows-gnullvm zip"
)
for target in "${targets[@]}"; do
  read -r os arch triple format <<<"$target"
  output_dir="$tmp_dir/matrix/$os-$arch"
  PATH="$repo_root/scripts/test-fixtures:$PATH" \
    FERROCRATE_TEST_RUSTUP_TARGETS="$triple" \
    bash "$repo_root/scripts/build-release-artifacts.sh" \
      --version v0.0.1 --channel public --target-os "$os" --target-arch "$arch" \
      --target-dir "$tmp_dir/target-$os-$arch" --output-dir "$output_dir" \
      >"$tmp_dir/$os-$arch.txt" 2>&1
  archive="$output_dir/ferrocrate-v0.0.1-$os-$arch.$format"
  test -s "$archive"
  test -s "$output_dir/ferrocrate-v0.0.1-checksums.txt"
  test -s "$archive.provenance.json"
done

echo "cross-platform release target preflight and six-target packaging matrix passed"
