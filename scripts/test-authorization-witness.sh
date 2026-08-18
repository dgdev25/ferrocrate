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

verify_mode_artifact() {
  local mode="$1"
  local artifact="$2"
  jq -e '
    .classification == "actual-fixture"
    and ([.attributed_delta, .unknown_principal_delta, .would_deny_delta, .enforced_denial_delta, .bypass_probe_delta, .bypass_detected_delta, .successful_bypass_delta] | all(type == "number"))
    and .successful_bypass_delta == 0
  ' "$artifact" >/dev/null
  case "$mode" in
    shadow) jq -e '.attributed_delta > 0 and .unknown_principal_delta == 0' "$artifact" >/dev/null ;;
    enforce) jq -e '.attributed_delta > 0 and .unknown_principal_delta == 0 and .enforced_denial_delta > 0' "$artifact" >/dev/null ;;
    disabled) ;;
    *) printf 'qualification failed: unknown rollout mode: %s\n' "$mode" >&2; exit 1 ;;
  esac
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

# Public-channel mutation proof. These tests invoke the externally exposed
# command, Unix socket, tonic UDS client, real rootless user namespace child,
# and managed-overlay client/server. They deliberately do not call a
# test-only authorization adapter. The rootless test consumes an exact
# `rootless.mapping` permit before it can write a mapping.
run public-network cargo test -p ferro-cli --test docker_compat_integration network_
run public-cli-mutation env FERRO_AUTHORIZATION_QUALIFICATION_FIXTURE=cli cargo test -p ferro-cli --test cli_integration public_cli_volume_mutation_preserves_disabled_shadow_and_enforce_contracts -- --exact
run public-docker-mutation env FERRO_AUTHORIZATION_QUALIFICATION_FIXTURE=docker cargo test -p ferro-cli --test docker_compat_integration docker_compat_volume_mutation_preserves_disabled_shadow_and_enforce_contracts -- --exact
run public-compose-mutation env FERRO_AUTHORIZATION_QUALIFICATION_FIXTURE=compose cargo test -p ferro-cli --test compose_down_integration public_compose_down_preserves_disabled_shadow_and_enforce_contracts -- --exact
run public-cri-delegation cargo test -p ferro-cri --test socket_integration cri_wire_delegation_accepts_once_and_rejects_replay_expiry_and_tampering -- --exact --test-threads=1
run public-cri-mutation cargo test -p ferro-cri --test socket_integration public_cri_pull_preserves_disabled_shadow_and_enforce_contracts -- --exact --test-threads=1
# FerroCrate creates the user namespace first and applies subordinate maps via
# the authenticated newuidmap/newgidmap path inside the fixture. Do not use
# util-linux's `-Ur` shortcut here; it exercises a different mapping path and
# is denied on hosts where the production helper flow is valid. Keep mount
# propagation unchanged so the probe remains side-effect free.
if ! unshare --user --mount --fork --propagation unchanged true >/dev/null 2>&1; then
  printf 'authorization qualification blocked: user+mount namespaces are unavailable for the rootless public fixture\n' >&2
  exit 77
fi
run public-rootless-mutation cargo test -p ferro-core --test rootless_isolation rootless_configuration_mutates_the_real_runtime_namespaces -- --exact
run public-managed-overlay-shadow cargo test -p ferro-mgr --test authorization_cross_stack enforcing_controller_agent_and_local_api_attach_cleanup_replay_and_bypass -- --exact --test-threads=1
run public-managed-overlay-disabled-enforce cargo test -p ferro-mgr --test authorization_cross_stack public_managed_overlay_disabled_compatibility_and_enforce_denial_are_stable -- --exact --test-threads=1

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

negative_control="$FERRO_AUTHORIZATION_QUALIFICATION_OUTPUT/fixture-negative-control.json"
if ! jq -e '
  .fixture == "negative-control.broken-comparator"
  and .classification == "expected-negative-control"
  and .bypass_probe_delta > 0
  and .successful_bypass_delta > 0
' "$negative_control" >/dev/null; then
  printf 'qualification failed: negative control did not record its expected successful bypass\n' >&2
  exit 1
fi

channels=(cli docker compose cri rootless managed-overlay)
modes=(disabled shadow enforce)
fixture_artifacts=()
for channel in "${channels[@]}"; do
  for mode in "${modes[@]}"; do
    artifact="$FERRO_AUTHORIZATION_QUALIFICATION_OUTPUT/fixture-${channel}-${mode}.json"
    if [[ ! -f "$artifact" ]] || ! verify_mode_artifact "$mode" "$artifact"; then
      printf 'qualification failed: channel×mode evidence is missing or unsafe: %s\n' "$artifact" >&2
      exit 1
    fi
    fixture_artifacts+=("$artifact")
  done
done
[[ "${#fixture_artifacts[@]}" -eq 18 ]] || {
  printf 'qualification failed: expected exactly 18 channel×mode artifacts\n' >&2
  exit 1
}
bypasses="$(jq -s '[.[].successful_bypass_delta] | add' "${fixture_artifacts[@]}")"
probes="$(jq -s '[.[].bypass_probe_delta] | add' "${fixture_artifacts[@]}")"
attributed="$(jq -s '[.[].attributed_delta] | add' "${fixture_artifacts[@]}")"
unknown="$(jq -s '[.[].unknown_principal_delta] | add' "${fixture_artifacts[@]}")"
jq -n --argjson total "$total" --argjson passed "$passed" \
  --argjson bypasses "$bypasses" --argjson probes "$probes" \
  --argjson attributed "$attributed" --argjson unknown "$unknown" \
  --slurpfile surfaces "$surface_results" \
  '{inventory_total:$total, inventory_passed:$passed, attributed_mutations:$attributed, unknown_principals:$unknown, attributed_percent:(if ($attributed + $unknown) == 0 then 0 else (($attributed * 100) / ($attributed + $unknown)) end), bypass_probes:$probes, successful_bypasses:$bypasses, surfaces:$surfaces}' \
  > "$results_json"

jq -e '.inventory_total == .inventory_passed and .attributed_percent == 100 and .successful_bypasses == 0' "$results_json" >/dev/null

channel_e2e_json="$qualification_dir/channel-e2e.json"
jq -s '{fixtures: map({fixture,classification,attributed_delta,unknown_principal_delta,would_deny_delta,enforced_denial_delta,bypass_probe_delta,bypass_detected_delta,successful_bypass_delta})}' \
  "${fixture_artifacts[@]}" > "$channel_e2e_json"
jq -e '(.fixtures | length == 18) and all(.fixtures[]; .classification == "actual-fixture" and .successful_bypass_delta == 0) and ([.fixtures[] | select(.fixture | endswith("-shadow"))] | length == 6) and ([.fixtures[] | select(.fixture | endswith("-enforce"))] | length == 6)' "$channel_e2e_json" >/dev/null

if grep -R -a -Fq -- "$FERRO_AUTHORIZATION_QUALIFICATION_CANARY" "$qualification_dir"; then
  printf 'qualification failed: secret canary appeared in persisted witness/sled/mirror/JSON/log/error/metrics output\n' >&2
  exit 1
fi

printf 'authorization witness qualification passed: %s channels=%s canaries=0\n' \
  "$(jq -c . "$results_json")" "$(jq -c . "$channel_e2e_json")"
