#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

for run in one two; do
  PATH="$repo_root/scripts/test-fixtures:$PATH" \
    bash "$repo_root/scripts/build-release-artifacts.sh" \
      --version v0.0.1 --channel public --target-os linux --target-arch x86_64 \
      --target-dir "$tmp_dir/target-$run" --output-dir "$tmp_dir/release-$run" >/dev/null
done

first="$tmp_dir/release-one/ferrocrate-v0.0.1-linux-x86_64.tar.gz"
second="$tmp_dir/release-two/ferrocrate-v0.0.1-linux-x86_64.tar.gz"
cmp "$first" "$second"
test "$(sha256sum "$first" | awk '{print $1}')" = "$(sha256sum "$second" | awk '{print $1}')"

echo "reproducible release artifact fixture passed"
