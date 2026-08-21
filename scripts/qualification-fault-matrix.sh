#!/usr/bin/env bash
set -euo pipefail

# Roadmap item 21: bounded 100-container resource/fault qualification.
#
# Runs each scenario as one narrowly scoped cargo test with a hard outer
# timeout, an isolated Cargo target directory, and guaranteed cleanup. A
# failing or timing-out scenario is recorded as evidence in the manifest;
# the script never retries to force a pass.
#
# Environment:
#   FERROCRATE_QUAL_TARGET_DIR  isolated target dir (default /tmp owned path)
#   FERROCRATE_QUAL_KEEP_TARGET keep the target dir on exit (default 0)

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/.." && pwd)}"
target_root="${FERROCRATE_QUAL_TARGET_DIR:-$(mktemp -d /tmp/ferrocrate-qual.XXXXXX)}"
keep_target="${FERROCRATE_QUAL_KEEP_TARGET:-0}"
output_dir="${FERROCRATE_QUAL_OUTPUT_DIR:-$target_root/results}"

for required in cargo timeout setsid; do
  if ! command -v "$required" >/dev/null 2>&1; then
    echo "qualification matrix blocked: required command is unavailable: $required" >&2
    exit 77
  fi
done

mkdir -p "$output_dir"
manifest="$output_dir/manifest.tsv"
: >"$manifest"

cleanup() {
  if [[ "$keep_target" == "1" ]]; then
    echo "qualification matrix kept target dir: $target_root" >&2
  else
    rm -rf "$target_root"
  fi
}
trap cleanup EXIT

# name timeout_seconds
run_case() {
  local name="$1"
  local timeout_seconds="$2"
  echo "running $name (bound ${timeout_seconds}s)"
  if timeout --foreground --kill-after=10s "${timeout_seconds}s" \
    env CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}" CARGO_INCREMENTAL=0 \
    CARGO_TARGET_DIR="$target_root/target" \
    cargo test -p ferro-cli --offline --test qualification_fault_matrix "$name" \
    -- --ignored --exact --test-threads=1 --nocapture \
    >"$output_dir/$name.log" 2>&1; then
    printf '%s\tpass\n' "$name" >>"$manifest"
  else
    local rc=$?
    if (( rc == 124 || rc == 137 )); then
      printf '%s\ttimeout\n' "$name" >>"$manifest"
    else
      printf '%s\tfail\n' "$name" >>"$manifest"
    fi
    echo "qualification: $name failed (rc=$rc); see $output_dir/$name.log" >&2
  fi
  # Free per-scenario disk between cases; the shared build cache persists
  # in the isolated target dir until the trap removes it.
}

run_case qual_hundred_container_lifecycle_with_rss_sampling 900
run_case qual_resource_exhaustion_memory_oom_isolated 420
run_case qual_resource_exhaustion_cpu_quota_fail_closed 420
run_case qual_resource_exhaustion_pids_limit_fail_closed 180
run_case qual_daemon_crash_mid_lifecycle_reconciliation 420
run_case qual_interrupted_network_emulated_recovery 300
run_case qual_disk_pressure_rlimit_fsize_fail_closed_and_recovery 420

echo
echo "qualification matrix manifest:"
cat "$manifest"
if grep -qE $'\t(fail|timeout)$' "$manifest"; then
  echo "qualification matrix has failing rows; inspect $output_dir" >&2
  exit 1
fi
echo "qualification matrix passed: $manifest"
