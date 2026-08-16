#!/usr/bin/env bash
set -euo pipefail

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/.." && pwd)}"
output="$(mktemp)"
trap 'rm -f "$output"' EXIT

if ! bash "$repo_root/scripts/shell-out-audit.sh" >"$output" 2>&1; then
  cat "$output" >&2
  exit 1
fi

grep -q '^shell-out audit: pass$' "$output"
! grep -q 'Command::new' "$output"
printf '%s\n' 'shell-out audit regression test: pass'
