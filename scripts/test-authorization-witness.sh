#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
export LIBRARY_PATH="${LIBRARY_PATH:-$repo_root/.superpowers/toolchain/lib}"
export FERRO_AUTHORIZATION_QUALIFICATION_CANARY="qualification-secret-canary-$$-8d219"

qualification_dir="$(mktemp -d)"
trap 'rm -rf -- "$qualification_dir"' EXIT
qualification_log="$qualification_dir/qualification.log"
export FERRO_AUTHORIZATION_QUALIFICATION_OUTPUT="$qualification_dir/persisted"
mkdir -p "$FERRO_AUTHORIZATION_QUALIFICATION_OUTPUT"
inventory_json="$qualification_dir/inventory.json"
results_json="$qualification_dir/evidence.json"

run() {
  printf 'qualification: %s\n' "$1"
  shift
  "$@" 2>&1 | tee -a "$qualification_log"
}

verify_bypass_artifact() {
  jq -e '.bypass_probe_total > 0 and .successful_bypass_total == 0 and .bypass_detected_total > 0' "$1" >/dev/null
}

run metrics-and-matrices cargo test -p ferro-core --test authorization_faults
run compatibility-promotion cargo test -p ferro-cli --test authorization_compatibility
run bypass-regression-diagnostic cargo test -p ferro-core --lib authorization::surface::tests::diagnostic_broken_comparator_records_a_successful_bypass -- --exact
run production-canary-scan cargo test -p ferro-core --lib production_surface_canary_is_absent_from_witness_mirror_errors_logs_and_metrics
run inventory-and-bypass cargo test -p ferro-core --test authorization_gate
run policy-source-validation cargo test -p ferro-core --test authorization_policy
run policy-reload-retains-last-valid cargo test -p ferro-core --lib reload_rejects_generation_rollback_and_keeps_the_active_snapshot
run journal-enospc-corruption-reserve cargo test -p ferro-core --test witness_journal -- --test-threads=1
run journal-mirror-corrupt-chain cargo test -p ferro-core --lib witness::journal::epoch_lock_tests::read_only_mirror_rejects_a_broken_record_hash_chain -- --exact
run journal-mirror-corrupt-gap cargo test -p ferro-core --lib witness::journal::epoch_lock_tests::read_mirror_rotates_bounded_segments_and_reader_rejects_a_gap -- --exact
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
surface_results="$qualification_dir/surface-results.ndjson"
: > "$surface_results"
while IFS= read -r entry; do
  surface_id="$(jq -r '.id' <<<"$entry")"
  test_name="$(jq -r '.mediation_test' <<<"$entry")"
  if [[ -z "$surface_id" || -z "$test_name" || "$surface_id" == null || "$test_name" == null ]]; then
    printf 'qualification failed: empty inventory ID or exact test symbol\n' >&2
    exit 1
  fi
  symbol_log="$qualification_dir/symbol-$passed.log"
  if cargo test --workspace "$test_name" -- --exact --test-threads=1 >"$symbol_log" 2>&1 \
      && [[ "$(grep -Ec 'test result: ok\. 1 passed' "$symbol_log")" -eq 1 ]]; then
    passed=$((passed + 1))
    cat "$symbol_log" >> "$qualification_log"
    jq -cn --arg id "$surface_id" --arg test "$test_name" '{id:$id, mediation_test:$test, passed:true}' >> "$surface_results"
  else
    cat "$symbol_log" >&2
    printf 'qualification failed: inventory test symbol did not pass: %s\n' "$test_name" >&2
    exit 1
  fi
done < <(jq -c '.[]' "$inventory_json")

metric_artifact="$FERRO_AUTHORIZATION_QUALIFICATION_OUTPUT/metrics.json"
bad_metric_artifact="$qualification_dir/intentionally-broken-bypass-metrics.json"
jq '.successful_bypass_total = 1' "$metric_artifact" > "$bad_metric_artifact"
if verify_bypass_artifact "$bad_metric_artifact"; then
  printf 'qualification failed: quality gate accepted an intentional successful bypass artifact\n' >&2
  exit 1
fi
verify_bypass_artifact "$metric_artifact"
bypasses="$(jq '.successful_bypass_total' "$metric_artifact")"
probes="$(jq '.bypass_probe_total' "$metric_artifact")"
jq -n --argjson total "$total" --argjson passed "$passed" \
  --argjson bypasses "$bypasses" --argjson probes "$probes" \
  --slurpfile surfaces "$surface_results" \
  '{inventory_total:$total, inventory_passed:$passed, attributed_percent:(if $total == 0 then 0 else (($passed * 100) / $total) end), bypass_probes:$probes, successful_bypasses:$bypasses, surfaces:$surfaces}' \
  > "$results_json"

jq -e '.inventory_total == .inventory_passed and .attributed_percent == 100 and .successful_bypasses == 0' "$results_json" >/dev/null

if grep -R -a -Fq -- "$FERRO_AUTHORIZATION_QUALIFICATION_CANARY" "$qualification_dir"; then
  printf 'qualification failed: secret canary appeared in persisted witness/sled/mirror/JSON/log/error/metrics output\n' >&2
  exit 1
fi

printf 'authorization witness qualification passed: %s canaries=0\n' "$(jq -c . "$results_json")"
