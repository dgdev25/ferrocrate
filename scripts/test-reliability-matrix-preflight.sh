#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname -- "$0")/.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$tmp_dir"' EXIT

file_path="$tmp_dir/not-a-directory"
printf '%s\n' fixture >"$file_path"
if FERROCRATE_RELIABILITY_OUTPUT_DIR="$file_path" \
  bash "$repo_root/scripts/reliability-matrix.sh" >"$tmp_dir/output" 2>&1; then
  echo "reliability matrix accepted a regular-file output path" >&2
  exit 1
fi
grep -q 'output path is not a directory' "$tmp_dir/output"
echo "reliability matrix output preflight regression passed"
