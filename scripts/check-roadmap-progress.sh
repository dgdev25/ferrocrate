#!/usr/bin/env bash
set -euo pipefail

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/.." && pwd)}"
roadmap="${1:-$repo_root/docs/ROADMAP.md}"
if [[ ! -f "$roadmap" ]]; then
  echo "roadmap not found: $roadmap" >&2
  exit 2
fi

completed=$(rg -c '^\s*- \[x\] ' "$roadmap" || true)
open=$(rg -c '^\s*- \[ \] ' "$roadmap" || true)
total=$((completed + open))
if (( total == 0 )); then
  echo "roadmap progress failed: no checklist rows found" >&2
  exit 1
fi

printf 'roadmap progress: %d complete / %d open / %d total (%d%% complete)\n' \
  "$completed" "$open" "$total" "$((completed * 100 / total))"

if [[ "${FERROCRATE_ROADMAP_EXPECTED_EPICS:-15}" != "15" ]]; then
  echo "roadmap progress failed: expected epic count is fixed at 15" >&2
  exit 1
fi
epics=$(rg -c '^### [0-9]+\.' "$roadmap" || true)
if (( epics != 15 )); then
  echo "roadmap progress failed: expected 15 epic headings, found $epics" >&2
  exit 1
fi

if [[ "${FERROCRATE_SKIP_BENCHMARK_REGISTER:-0}" != "1" ]]; then
  bash "$repo_root/scripts/perf/check-benchmark-register.sh" \
    "$repo_root/docs/evidence/performance/benchmark-register.md"
fi
