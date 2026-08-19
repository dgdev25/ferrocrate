#!/usr/bin/env bash
set -euo pipefail

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/../.." && pwd)}"
bash "$repo_root/scripts/perf/check-benchmark-register.sh" \
  "$repo_root/docs/evidence/performance/benchmark-register.md" >/dev/null

tmp="$(mktemp -d /tmp/ferrocrate-benchmark-register-gate.XXXXXX)"
trap 'rm -rf "$tmp"' EXIT
broken="$tmp/register.md"
cp "$repo_root/docs/evidence/performance/benchmark-register.md" "$broken"
sed -i '0,/2026-08-18-docker-comparison-current-head-80e1b421-iptables.md/s//missing-report.md/' "$broken"
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
