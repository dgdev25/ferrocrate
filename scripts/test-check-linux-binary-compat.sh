#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname -- "$0")/.." && pwd)"
checker="$repo_root/scripts/check-linux-binary-compat.sh"
binary="/bin/true"

[[ -x "$binary" ]] || { echo "fixture missing: $binary" >&2; exit 1; }
highest="$(readelf --version-info "$binary" 2>/dev/null \
  | grep -oE 'GLIBC_[0-9]+\.[0-9]+' \
  | sed 's/^GLIBC_//' | sort -Vu | tail -n 1)"
[[ -n "$highest" ]] || { echo "fixture has no dynamic GLIBC requirement" >&2; exit 1; }

bash "$checker" "$binary" "$highest" >/dev/null
if bash "$checker" "$binary" 0.0 >/dev/null 2>&1; then
  echo "ABI checker accepted an impossible baseline" >&2
  exit 1
fi
if bash "$checker" "$binary" not-a-version >/dev/null 2>&1; then
  echo "ABI checker accepted malformed baseline" >&2
  exit 1
fi

echo "linux binary compatibility checker regression passed"
