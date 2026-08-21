#!/usr/bin/env bash
set -euo pipefail

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/../.." && pwd)}"
output_dir="${FERROCRATE_PERF_OUTPUT_DIR:-$repo_root/target/perf-baseline}"
mkdir -p "$output_dir"
metadata="$output_dir/metadata.txt"
manifest="$output_dir/manifest.tsv"
{
  printf 'timestamp_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'kernel=%s\n' "$(uname -r)"
  printf 'architecture=%s\n' "$(uname -m)"
  printf 'distribution=%s\n' "$(. /etc/os-release && printf '%s' "${PRETTY_NAME:-unknown}")"
} >"$metadata"
: >"$manifest"

# Baseline collection records measurements even on hosts that cannot satisfy a
# privileged SLO. Individual scripts emit an explicit skip reason; the later
# verifier decides whether that absence is acceptable for a release row.
baseline_allow_skip="${FERROCRATE_PERF_ALLOW_SKIP:-1}"
baseline_enforce="${FERROCRATE_PERF_ENFORCE:-0}"
baseline_timeout="${FERROCRATE_PERF_BASELINE_TIMEOUT_SECONDS:-120}"
if ! [[ "$baseline_timeout" =~ ^[1-9][0-9]*$ && "$baseline_timeout" -le 900 ]]; then
  echo "FERROCRATE_PERF_BASELINE_TIMEOUT_SECONDS must be 1..900" >&2
  exit 2
fi

run_benchmark() {
  local name="$1" script="$2"
  echo "running $name"
  local rc=0
  FERROCRATE_PERF_ALLOW_SKIP="$baseline_allow_skip" \
    FERROCRATE_PERF_ENFORCE="$baseline_enforce" \
    timeout --foreground --signal=TERM --kill-after=10s "$baseline_timeout" \
      bash "$repo_root/$script" >"$output_dir/$name.txt" 2>&1 || rc=$?
  case "$rc" in
    0)
    printf '%s\tpass\n' "$name" >>"$manifest"
      ;;
    77)
      printf '%s\tskip\n' "$name" >>"$manifest"
      echo "baseline: $name skipped; see $output_dir/$name.txt" >&2
      ;;
    *)
    printf '%s\tfail\n' "$name" >>"$manifest"
    echo "baseline: $name failed; see $output_dir/$name.txt" >&2
      ;;
  esac
}

run_benchmark startup scripts/perf/startup.sh
run_benchmark pull scripts/perf/pull.sh
run_benchmark build scripts/perf/build.sh
run_benchmark idle-daemon scripts/perf/idle-daemon.sh
run_benchmark idle-no-daemon scripts/perf/idle-no-daemon.sh
run_benchmark per-container scripts/perf/per-container.sh
run_benchmark binary-size scripts/perf/binary-size.sh
run_benchmark ai-latency scripts/perf/ai-latency.sh
run_benchmark ai-overhead scripts/perf/ai-overhead.sh
run_benchmark docker-api scripts/perf/docker-api-compat.sh
run_benchmark oci-compat scripts/perf/oci-compat.sh
run_benchmark oci-conformance scripts/oci-conformance.sh
run_benchmark rootless scripts/verify-rootless.sh
echo "performance baseline written to $output_dir (manifest: $manifest; per-benchmark timeout: ${baseline_timeout}s)"
