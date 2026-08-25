#!/usr/bin/env bash
# Adapted from block/buzz (Apache-2.0), scripts/bundle-sidecars.sh.
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
host="$(rustc -vV | sed -n 's/^host: //p')"
target="${1:-$host}"
target_dir="${CARGO_TARGET_DIR:-$repo_root/target}"
source_dir="$target_dir/release"
[[ -z "${1:-}" ]] || source_dir="$target_dir/$target/release"
destination_dir="${FERROCRATE_SIDECAR_DIR:-$repo_root/apps/ferro-desktop-ui/src-tauri/binaries}"
extension=""
[[ "$target" != *windows* ]] || extension=".exe"

for output in ferrocrate ferro-desktop; do
  source_name="$output"
  [[ "$output" != "ferrocrate" ]] || source_name="ferro-cli"
  source="$source_dir/${source_name}$extension"
  [[ -x "$source" || ( "$extension" == ".exe" && -f "$source" ) ]] || {
    echo "bundle-sidecars: missing $source; build ferro-cli and ferro-desktop for $target first" >&2
    exit 1
  }
done
mkdir -p "$destination_dir"
for output in ferrocrate ferro-desktop; do
  source_name="$output"
  [[ "$output" != "ferrocrate" ]] || source_name="ferro-cli"
  install -m 0755 "$source_dir/${source_name}$extension" \
    "$destination_dir/${output}-${target}${extension}"
done
echo "staged FerroCrate sidecars for $target"
