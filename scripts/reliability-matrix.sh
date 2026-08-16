#!/usr/bin/env bash
set -u

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/.." && pwd)}"
output_dir="${FERROCRATE_RELIABILITY_OUTPUT_DIR:-$repo_root/target/reliability-matrix}"
mkdir -p "$output_dir"
manifest="$output_dir/manifest.tsv"
: >"$manifest"

run_case() {
  local name="$1"
  shift
  echo "running $name"
  if (cd "$repo_root" && "$@") >"$output_dir/$name.log" 2>&1; then
    printf '%s\tpass\n' "$name" >>"$manifest"
  else
    printf '%s\tfail\n' "$name" >>"$manifest"
    echo "reliability: $name failed; see $output_dir/$name.log" >&2
  fi
}

run_case authorization-crash-matrix \
  cargo test -p ferro-core --offline --test runtime_authorization -- --test-threads=1
run_case witness-disk-fault-matrix \
  cargo test -p ferro-core --offline --test witness_journal -- --test-threads=1
run_case witness-checkpoint-recovery \
  cargo test -p ferro-core --offline --test witness_checkpoint -- --test-threads=1
run_case network-recovery-matrix \
  cargo test -p ferro-cli --offline --bin ferro-cli network_lifecycle -- --test-threads=1
run_case cri-restart-and-wire \
  cargo test -p ferro-cri --offline --test socket_integration -- --test-threads=1
run_case helper-grant-recovery \
  cargo test -p ferro-netd --offline --test transaction_fault_matrix -- --test-threads=1
run_case sustained-process-lifecycle \
  env FERROCRATE_SUSTAINED_COUNT="${FERROCRATE_SUSTAINED_COUNT:-100}" \
  cargo test -p ferro-core --offline --test container_lifecycle \
  lifecycle_handles_100_concurrent_processes -- --ignored --exact --test-threads=1

if rg -q $'\tfail$' "$manifest"; then
  echo "reliability matrix failed; inspect $output_dir" >&2
  exit 1
fi
echo "reliability matrix passed: $manifest"
