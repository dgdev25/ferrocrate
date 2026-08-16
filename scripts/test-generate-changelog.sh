#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname -- "$0")/.." && pwd)"
temp_dir="$(mktemp -d)"
trap 'rm -rf -- "$temp_dir"' EXIT
output="$temp_dir/CHANGELOG.md"
FERROCRATE_RELEASE_VERSION=v0.1.0 \
  "$repo_root/scripts/generate-changelog.sh" --from HEAD~8 --to HEAD --output "$output" >/dev/null
grep -q '^# Ferrocrate v0.1.0$' "$output"
grep -q 'Generated .*HEAD~8..HEAD' "$output"
grep -Eq '^## (Features|Fixes|Documentation|Maintenance|Other)$' "$output"

if "$repo_root/scripts/generate-changelog.sh" --from does-not-exist --output "$temp_dir/nope" >/dev/null 2>&1; then
  printf 'changelog test: invalid ref unexpectedly passed\n' >&2
  exit 1
fi
printf 'changelog tests passed\n'
