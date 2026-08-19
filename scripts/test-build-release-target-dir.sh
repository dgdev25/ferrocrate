#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

PATH="$repo_root/scripts/test-fixtures:$PATH" \
  bash "$repo_root/scripts/build-release-artifacts.sh" \
    --version v0.0.1 \
    --channel public \
    --target-os linux \
    --target-arch x86_64 \
    --target-dir "$tmp_dir/custom-target" \
    --output-dir "$tmp_dir/release"

test -x "$tmp_dir/custom-target/release/ferro-cli"
test -f "$tmp_dir/release/ferrocrate-v0.0.1-linux-x86_64.tar.gz"
test -f "$tmp_dir/release/ferrocrate-v0.0.1-linux-x86_64.tar.gz.provenance.json"

bash "$repo_root/scripts/verify-release-channel-artifacts.sh" \
  --channel public --version v0.0.1 --artifact-dir "$tmp_dir/release"

echo "release target-directory builder regression passed"
