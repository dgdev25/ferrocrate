#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname -- "$0")/.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$tmp_dir"' EXIT

printf '%s:200000:65536\n' "$(id -u)" >"$tmp_dir/subuid"
printf '%s:200000:65536\n' "$(id -g)" >"$tmp_dir/subgid"
XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-$tmp_dir/runtime}"
mkdir -p "$XDG_RUNTIME_DIR"

output="$tmp_dir/output"
FERROCRATE_ROOTLESS_SUBUID_FILE="$tmp_dir/subuid" \
FERROCRATE_ROOTLESS_SUBGID_FILE="$tmp_dir/subgid" \
XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" \
FERROCRATE_ROOTLESS_STRICT=0 \
bash "$repo_root/scripts/verify-rootless.sh" >"$output" 2>&1

grep -q '^rootless.subuid=pass$' "$output"
grep -q '^rootless.subgid=pass$' "$output"
echo "rootless numeric subid diagnostic regression passed"
