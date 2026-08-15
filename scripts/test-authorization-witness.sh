#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
export LIBRARY_PATH="${LIBRARY_PATH:-$repo_root/.superpowers/toolchain/lib}"
export FERRO_AUTHORIZATION_QUALIFICATION_CANARY="qualification-secret-canary-8d219"

qualification_dir="$(mktemp -d)"
trap 'rm -rf -- "$qualification_dir"' EXIT
qualification_log="$qualification_dir/qualification.log"

run() {
  printf 'qualification: %s\n' "$1"
  shift
  "$@" 2>&1 | tee -a "$qualification_log"
}

run metrics-and-matrices cargo test -p ferro-core --test authorization_faults
run inventory-and-bypass cargo test -p ferro-core --test authorization_gate
run policy-reload-failure cargo test -p ferro-core --test authorization_policy
run journal-enospc-corruption-reserve cargo test -p ferro-core --test witness_journal -- --test-threads=1
run checkpoint-key-loss-grace cargo test -p ferro-core --test witness_checkpoint -- --test-threads=1
run runtime-kill-points cargo test -p ferro-core --test runtime_authorization -- --test-threads=1

# Every external channel in the mutation inventory must retain authenticated
# attribution and independently mediated child/executor identity.
run cli-attribution cargo test -p ferro-cli --test authorization_surfaces
run compose-attribution cargo test -p ferro-compose --test authorization_fanout
run cri-attribution cargo test -p ferro-cri --test authorization_identity
run managed-networking-attribution cargo test -p ferro-mgr --test authorization_cross_stack -- --test-threads=1

# Task 8 helper grants are intentionally tested in both the ordinary build and
# the feature-gated adversarial/test-support configuration.
run helper-grants cargo test -p ferro-netd --test authorization_grants -- --test-threads=1
run helper-grants-test-support cargo test -p ferro-netd --features test-support --test authorization_grants -- --test-threads=1

inventory_count="$(sed -n '/pub const MUTATION_INVENTORY/,/^];/p' ferro-core/src/authorization/inventory.rs | grep -c 'entry(')"
if [[ "$inventory_count" -ne 17 ]]; then
  printf 'qualification failed: mutation inventory coverage is %s/17\n' "$inventory_count" >&2
  exit 1
fi

if grep -Fq -- "$FERRO_AUTHORIZATION_QUALIFICATION_CANARY" "$qualification_log"; then
  printf 'qualification failed: secret canary appeared in logs/errors/metrics\n' >&2
  exit 1
fi

printf 'authorization witness qualification passed: inventory=17/17 attribution=100%% bypasses=0 canaries=0\n'
