#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
runs="${RUNS:-5}"
max_regression_pct="${MAX_REGRESSION_PCT:-20}"

measure_backend() {
  local backend="$1"
  local samples=()
  local i

  for ((i = 1; i <= runs; i++)); do
    start="$(date +%s%N)"
    FERROCRATE_AI_BACKEND="$backend" cargo test -q -p ferro-mind backend_parity_workload --features rvf-persistence -- --exact >/dev/null
    end="$(date +%s%N)"
    samples+=( $(( (end - start) / 1000000 )) )
  done

  printf '%s\n' "${samples[@]}" | sort -n >"$tmp_dir/${backend}.times"
  median_idx=$(( (runs + 1) / 2 ))
  median="$(sed -n "${median_idx}p" "$tmp_dir/${backend}.times")"
  echo "$median"
}

echo "Benchmarking RVF backend..."
rvf_ms="$(measure_backend rvf)"

echo "Benchmarking legacy backend..."
legacy_ms="$(measure_backend legacy)"

echo "Workload: backend_parity_workload"
echo "Runs per backend: ${runs}"
echo "RVF median elapsed: ${rvf_ms}ms"
echo "Legacy median elapsed: ${legacy_ms}ms"
if [[ "$legacy_ms" -gt 0 ]]; then
  regression_pct=$(( ( (rvf_ms - legacy_ms) * 100 ) / legacy_ms ))
  if [[ "$regression_pct" -lt 0 ]]; then
    regression_pct=0
  fi
  echo "RVF regression vs legacy: ${regression_pct}% (max allowed ${max_regression_pct}%)"
  if [[ "$regression_pct" -gt "$max_regression_pct" ]]; then
    echo "error: RVF regression exceeded threshold"
    exit 1
  fi
fi
echo "Done."
