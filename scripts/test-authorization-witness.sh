#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
export LIBRARY_PATH="${LIBRARY_PATH:-$repo_root/.superpowers/toolchain/lib}"
export FERRO_AUTHORIZATION_QUALIFICATION_CANARY="qualification-secret-canary-8d219"

qualification_dir="$(mktemp -d)"
trap 'rm -rf -- "$qualification_dir"' EXIT
qualification_log="$qualification_dir/qualification.log"
inventory_json="$qualification_dir/inventory.json"
results_json="$qualification_dir/evidence.json"

run() {
  printf 'qualification: %s\n' "$1"
  shift
  "$@" 2>&1 | tee -a "$qualification_log"
}

run metrics-and-matrices cargo test -p ferro-core --test authorization_faults
run production-canary-scan cargo test -p ferro-core --lib production_surface_canary_is_absent_from_witness_mirror_errors_logs_and_metrics
run inventory-and-bypass cargo test -p ferro-core --test authorization_gate
run policy-source-validation cargo test -p ferro-core --test authorization_policy
run policy-reload-retains-last-valid cargo test -p ferro-core --lib reload_rejects_generation_rollback_and_keeps_the_active_snapshot
run journal-enospc-corruption-reserve cargo test -p ferro-core --test witness_journal -- --test-threads=1
run checkpoint-key-loss-grace cargo test -p ferro-core --test witness_checkpoint -- --test-threads=1
run runtime-checkpoint-grace cargo test -p ferro-core --lib missing_or_stale_checkpoint_denies_user_cleanup_without_reserved_authority
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

cargo run --quiet -p ferro-core --example authorization_inventory > "$inventory_json"
jq -e 'length > 0 and (map(.id) | length == (unique | length))' "$inventory_json" >/dev/null

passed=0
total="$(jq 'length' "$inventory_json")"
while IFS= read -r test_name; do
  symbol_log="$qualification_dir/symbol-$passed.log"
  if cargo test --workspace "$test_name" -- --test-threads=1 >"$symbol_log" 2>&1 \
      && grep -Eq 'test result: ok\. [1-9][0-9]* passed' "$symbol_log"; then
    passed=$((passed + 1))
    cat "$symbol_log" >> "$qualification_log"
  else
    cat "$symbol_log" >&2
    printf 'qualification failed: inventory test symbol did not pass: %s\n' "$test_name" >&2
    exit 1
  fi
done < <(jq -r '.[].mediation_test' "$inventory_json")

bypasses=$((total - passed))
jq -n --argjson total "$total" --argjson passed "$passed" \
  --argjson bypasses "$bypasses" \
  '{inventory_total:$total, inventory_passed:$passed, attributed_percent:(if $total == 0 then 0 else (($passed * 100) / $total) end), successful_bypasses:$bypasses}' \
  > "$results_json"

jq -e '.inventory_total == .inventory_passed and .attributed_percent == 100 and .successful_bypasses == 0' "$results_json" >/dev/null

if grep -Fq -- "$FERRO_AUTHORIZATION_QUALIFICATION_CANARY" "$qualification_log"; then
  printf 'qualification failed: secret canary appeared in logs/errors/metrics\n' >&2
  exit 1
fi

printf 'authorization witness qualification passed: %s canaries=0\n' "$(jq -c . "$results_json")"
