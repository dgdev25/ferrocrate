#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
runner="$ROOT_DIR/scripts/perf/run-suite.sh"
bash -n "$runner"
grep -Fq 'setsid "$@"' "$runner"
grep -Fq 'kill -TERM -- "-$command_pid"' "$runner"
grep -Fq 'kill -KILL -- "-$command_pid"' "$runner"
mapfile -t names < <("$runner" --list)
[[ "${#names[@]}" -ge 10 ]]
printf '%s\n' "${names[@]}" | grep -qx 'startup'
printf '%s\n' "${names[@]}" | grep -qx 'ai-latency'

report="$(mktemp)"
trap 'rm -f "$report"' EXIT
"$runner" --dry-run --timeout 7 --output "$report" startup ai-latency
grep -q '| startup | planned |' "$report"
grep -q '| ai-latency | planned |' "$report"
grep -q 'Privileged probes: not run' "$report"
echo "benchmark suite runner tests passed"
