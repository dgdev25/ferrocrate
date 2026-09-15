#!/usr/bin/env bash
set -euo pipefail

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/../.." && pwd)}"
register="$repo_root/docs/evidence/performance/benchmark-register.md"
if [[ ! -f "$register" ]]; then
  echo "benchmark register gate skipped: private register not present"
  exit 0
fi
bash "$repo_root/scripts/perf/check-benchmark-register.sh" \
  "$register" >/dev/null

tmp="$(mktemp -d /tmp/ferrocrate-benchmark-register-gate.XXXXXX)"
trap 'rm -rf "$tmp"' EXIT
broken="$tmp/register.md"
cp "$register" "$broken"
current_report="$(sed -n 's/.*\[iptables\](\([^)]*\.md\)).*/\1/p' "$broken" | head -n 1)"
[[ -n "$current_report" ]] || { echo "benchmark register fixture has no current report" >&2; exit 1; }
sed -i "0,/${current_report//\//\\/}/s//missing-report.md/" "$broken"
if bash "$repo_root/scripts/perf/check-benchmark-register.sh" "$broken" >/dev/null 2>&1; then
  echo "benchmark register gate accepted a missing report link" >&2
  exit 1
fi

sed -i 's/Latest benchmark-relevant implementation head: `[^`]*`/Latest benchmark-relevant implementation head: `deadbeef`/' "$broken"
if bash "$repo_root/scripts/perf/check-benchmark-register.sh" "$broken" >/dev/null 2>&1; then
  echo "benchmark register gate accepted a stale snapshot head" >&2
  exit 1
fi
echo "benchmark register gate checks passed"
