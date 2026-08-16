#!/usr/bin/env bash
set -euo pipefail

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/../.." && pwd)}"
output_dir="${FERROCRATE_PERF_OUTPUT_DIR:-$repo_root/target/perf-baseline}"
mkdir -p "$output_dir"
metadata="$output_dir/metadata.txt"
{
  printf 'timestamp_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'kernel=%s\n' "$(uname -r)"
  printf 'architecture=%s\n' "$(uname -m)"
  printf 'distribution=%s\n' "$(. /etc/os-release && printf '%s' "${PRETTY_NAME:-unknown}")"
} >"$metadata"

run_benchmark() {
  local name="$1" script="$2"
  echo "running $name"
  bash "$repo_root/$script" >"$output_dir/$name.txt" 2>&1
}

run_benchmark startup scripts/perf/startup.sh
run_benchmark oci-compat scripts/perf/oci-compat.sh
run_benchmark rootless scripts/verify-rootless.sh
echo "performance baseline written to $output_dir"
