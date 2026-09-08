#!/usr/bin/env bash
set -euo pipefail

# Roadmap item 21: bounded 100-container resource/fault qualification.
#
# Runs each scenario as one narrowly scoped cargo test with a hard outer
# timeout, an isolated Cargo target directory, and process-group cleanup. A
# failing or timing-out scenario is recorded as evidence in the manifest;
# the script never retries to force a pass.
#
# Environment:
#   FERROCRATE_QUAL_TARGET_DIR  isolated target dir (default /tmp owned path)
#   FERROCRATE_QUAL_KEEP_TARGET keep the target dir on exit (default 0)
#   FERROCRATE_QUAL_OUTPUT_DIR  persistent evidence directory (separate default)
#   FERROCRATE_QUAL_ROOT        1 = run only the root-gated rows (must be
#                               executed as root; default 0 = unprivileged rows)

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/.." && pwd)}"
cd "$repo_root"
owned_target=0
if [[ -n "${FERROCRATE_QUAL_TARGET_DIR:-}" ]]; then
  target_root="$FERROCRATE_QUAL_TARGET_DIR"
else
  target_root="$(mktemp -d /tmp/ferrocrate-qual.XXXXXX)"
  owned_target=1
fi
keep_target="${FERROCRATE_QUAL_KEEP_TARGET:-0}"
# Evidence must outlive disposable build storage.
output_dir="${FERROCRATE_QUAL_OUTPUT_DIR:-$repo_root/target/qualification-evidence/$(date -u +%Y%m%dT%H%M%SZ)-$$}"
cleanup() {
  if (( owned_target )) && [[ "$keep_target" != 1 ]]; then
    rm -rf -- "$target_root"
  else
    echo "qualification matrix retained caller-owned or requested target: $target_root" >&2
  fi
}
trap cleanup EXIT

for required in cargo timeout grep git sha256sum; do
  if ! command -v "$required" >/dev/null 2>&1; then
    echo "qualification matrix blocked: required command is unavailable: $required" >&2
    exit 77
  fi
done
mkdir -p "$target_root" "$output_dir"
target_root="$(cd "$target_root" && pwd -P)"
output_dir="$(cd "$output_dir" && pwd -P)"
case "$output_dir/" in "$target_root/"*) keep_target=1 ;; esac
manifest="$output_dir/manifest.tsv"
: >"$manifest"
{
  printf 'started_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'source_commit=%s\n' "$(git -C "$repo_root" rev-parse HEAD)"
  if [[ -n "$(git -C "$repo_root" status --porcelain)" ]]; then
    printf 'source_dirty=true\n'
  else
    printf 'source_dirty=false\n'
  fi
  printf 'tracked_diff_sha256=%s\n' "$(git -C "$repo_root" diff HEAD --binary | sha256sum | awk '{print $1}')"
  printf 'harness_sha256=%s\n' "$(sha256sum "$repo_root/scripts/qualification-fault-matrix.sh" | awk '{print $1}')"
  printf 'host=%s\n' "$(uname -srmo)"
  printf 'effective_uid=%s\n' "${EUID:-$(id -u)}"
  printf 'root_mode=%s\n' "${FERROCRATE_QUAL_ROOT:-0}"
  printf 'manifest_columns=case,status,exit_code,test_filter\n'
} >"$output_dir/provenance.txt"

run_test() {
  local name="$1" timeout_seconds="$2" qualified_name="$3"
  shift 3
  local rc=0 status=pass
  echo "running $name (bound ${timeout_seconds}s)"
  # timeout owns a process group so a deadline also terminates descendants.
  # --foreground would disable that descendant cleanup.
  timeout --kill-after=10s "${timeout_seconds}s" \
    env CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}" CARGO_INCREMENTAL=0 \
    CARGO_TARGET_DIR="$target_root/target" \
    cargo test "$@" --offline "$qualified_name" \
    -- --ignored --exact --test-threads=1 --nocapture \
    >"$output_dir/$name.log" 2>&1 || rc=$?
  if (( rc == 124 || rc == 137 )); then
    status=timeout
  elif (( rc != 0 )); then
    status=fail
  elif ! grep -Eq '^test result: ok\. 1 passed; 0 failed; 0 ignored;' "$output_dir/$name.log"; then
    status=harness-error
    echo 'expected exactly one executed passing test; zero tests cannot qualify' >>"$output_dir/$name.log"
  fi
  printf '%s\t%s\t%s\t%s\n' "$name" "$status" "$rc" "$qualified_name" >>"$manifest"
  if [[ "$status" != pass ]]; then
    echo "qualification: $name $status (rc=$rc); see $output_dir/$name.log" >&2
  fi
}

run_case() {
  run_test "$1" "$2" "$1" -p ferro-cli --test qualification_fault_matrix
}

run_core_case() {
  run_test "$1" "$2" "dockerfile_build::tests::$1" -p ferro-core --lib
}

root_mode="${FERROCRATE_QUAL_ROOT:-0}"
if [[ "$root_mode" == "1" ]]; then
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "root mode blocked: FERROCRATE_QUAL_ROOT=1 requires root (mount/tmpfs and cgroup writes)" >&2
    exit 77
  fi
  for required in mount umount; do
    if ! command -v "$required" >/dev/null 2>&1; then
      echo "root mode blocked: required command is unavailable: $required" >&2
      exit 77
    fi
  done
  run_case qual_root_enospc_tmpfs_fail_closed_and_recovery 420
  run_case qual_root_cgroup_oom_group_teardown 420
  run_case qual_root_cpu_throttle_measured 420
  run_core_case qual_root_buildkit_insecure_devices_and_loop_whitelist 420
else
  run_case qual_hundred_container_lifecycle_with_rss_sampling 900
  run_case qual_resource_exhaustion_memory_oom_isolated 420
  run_case qual_resource_exhaustion_cpu_quota_fail_closed 420
  run_case qual_resource_exhaustion_pids_limit_fail_closed 180
  run_case qual_daemon_crash_mid_lifecycle_reconciliation 420
  run_case qual_interrupted_network_emulated_recovery 300
  run_case qual_disk_pressure_rlimit_fsize_fail_closed_and_recovery 420
fi

echo
echo "qualification matrix manifest:"
cat "$manifest"
if grep -qE $'\t(fail|timeout|harness-error)\t' "$manifest"; then
  echo "qualification matrix has failing rows; inspect $output_dir" >&2
  exit 1
fi
echo "qualification matrix passed: $manifest"
