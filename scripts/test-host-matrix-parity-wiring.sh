#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname -- "$0")/.." && pwd)"
runner="$repo_root/scripts/run-host-matrix-row.sh"

[[ -x "$runner" ]] || { echo "missing executable row runner: $runner" >&2; exit 1; }

work_root="$(mktemp -d "${TMPDIR:-/tmp}/ferrocrate-host-matrix-parity.XXXXXX")"
trap 'rm -rf -- "$work_root"' EXIT
fixture_root="$work_root/repo"
fixture_scripts="$fixture_root/scripts"
fixture_bin="$work_root/bin"
evidence_dir="$fixture_root/docs/evidence/host-matrix/contract-row"
stub_state="$work_root/state"
mkdir -p "$fixture_scripts" "$fixture_root/docs/evidence/host-matrix" "$fixture_bin" "$stub_state"
cp "$runner" "$fixture_scripts/run-host-matrix-row.sh"

cat >"$fixture_bin/id" <<'STUB_ID'
#!/usr/bin/env bash
if [[ "${1:-}" == -u ]]; then
  printf '0\n'
  exit 0
fi
exec /usr/bin/id "$@"
STUB_ID
chmod +x "$fixture_bin/id"

cat >"$fixture_root/docs/evidence/host-matrix/rows.tsv" <<EOF
contract-row|contract-distribution|$(uname -r)|$(uname -m)|qualified
EOF

for supporting_script in \
  host-matrix-preflight.sh \
  host-matrix-supporting-checks.sh; do
  cat >"$fixture_scripts/$supporting_script" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
printf 'stub evidence\n' >"$1"
STUB
  chmod +x "$fixture_scripts/$supporting_script"
done

for privileged_script in \
  test-privileged-network-lifecycle.sh \
  test-managed-overlay-kernel.sh; do
  cat >"$fixture_scripts/$privileged_script" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
printf 'harmless privileged-check stub\n'
STUB
  chmod +x "$fixture_scripts/$privileged_script"
done

cat >"$fixture_scripts/docker-client-conformance.sh" <<'CONFORMANCE_STUB'
#!/usr/bin/env bash
set -euo pipefail

[[ "${1:-}" == --output && "${3:-}" == --log ]] || {
  echo "unexpected conformance arguments: $*" >&2
  exit 64
}
output="$2"
execution_log="$4"
printf 'DOCKER_BUILDKIT=%s\noutput=%s\nlog=%s\n' \
  "${DOCKER_BUILDKIT:-unset}" "$output" "$execution_log" \
  >"$STUB_STATE/conformance.invocation"

if [[ "${CONFORMANCE_STUB_SLEEP_SECONDS:-0}" != 0 ]]; then
  sleep "$CONFORMANCE_STUB_SLEEP_SECONDS"
fi

if [[ "${CONFORMANCE_STUB_WRITE_EVIDENCE:-1}" == 1 ]]; then
  mkdir -p "$(dirname -- "$output")" "$(dirname -- "$execution_log")"
  printf '# stub parity scoreboard\n' >"$output"
  printf 'sequence\tid\n1\tstub\n' >"$execution_log"
fi

exit "${CONFORMANCE_STUB_STATUS:-0}"
CONFORMANCE_STUB
chmod +x "$fixture_scripts/docker-client-conformance.sh"

run_row() {
  local case_name="$1" expected_status="$2"
  shift 2

  set +e
  FERROCRATE_REPO_ROOT="$fixture_root" \
    FERROCRATE_RUN_AUTHENTICATED_OVERLAY_ROW=0 \
    PATH="$fixture_bin:$PATH" \
    STUB_STATE="$stub_state" \
    env "$@" \
    bash "$fixture_scripts/run-host-matrix-row.sh" contract-row \
    >"$work_root/$case_name.log" 2>&1
  local status=$?
  set -e

  if [[ "$status" != "$expected_status" ]]; then
    echo "$case_name returned $status; expected $expected_status" >&2
    cat "$work_root/$case_name.log" >&2
    exit 1
  fi
}

parity_scoreboard="$evidence_dir/parity-scoreboard.md"
conformance_log="$evidence_dir/docker-client-conformance.log"

clear_current_evidence() {
  rm -f -- "$parity_scoreboard" "$conformance_log"
}

write_stale_evidence() {
  printf '# stale parity scoreboard\n' >"$parity_scoreboard"
  printf 'sequence\tid\nstale\tstale\n' >"$conformance_log"
}

assert_no_current_evidence() {
  [[ ! -e "$parity_scoreboard" && ! -e "$conformance_log" ]] || {
    echo "harness failure left current conformance evidence behind" >&2
    exit 1
  }
}

clear_current_evidence
run_row completed 0 \
  CONFORMANCE_STUB_STATUS=0 \
  CONFORMANCE_STUB_WRITE_EVIDENCE=1

[[ -s "$parity_scoreboard" ]] || {
  echo "qualified row did not archive the parity scoreboard" >&2
  exit 1
}
[[ -s "$conformance_log" ]] || {
  echo "qualified row did not archive the conformance execution log" >&2
  exit 1
}
grep -Fxq 'DOCKER_BUILDKIT=0' "$stub_state/conformance.invocation"
grep -Eq "^output=$evidence_dir/\\.parity-scoreboard\\.md\\.tmp\\." "$stub_state/conformance.invocation"
grep -Eq "^log=$evidence_dir/\\.docker-client-conformance\\.log\\.tmp\\." "$stub_state/conformance.invocation"

write_stale_evidence
run_row rerun_over_stale_evidence 0 \
  CONFORMANCE_STUB_STATUS=0 \
  CONFORMANCE_STUB_WRITE_EVIDENCE=1
grep -Fq '# stub parity scoreboard' "$parity_scoreboard"
! grep -Fq 'stale parity scoreboard' "$parity_scoreboard"
grep -Fq $'1\tstub' "$conformance_log"
! grep -Fq $'stale\tstale' "$conformance_log"

clear_current_evidence
run_row command_failure 1 \
  CONFORMANCE_STUB_STATUS=1 \
  CONFORMANCE_STUB_WRITE_EVIDENCE=1
[[ -s "$parity_scoreboard" && -s "$conformance_log" ]] || {
  echo "completed conformance failure did not preserve both evidence files" >&2
  exit 1
}
grep -Fq 'completed conformance evidence' "$work_root/command_failure.log"

write_stale_evidence
run_row command_failure_without_fresh_evidence 2 \
  CONFORMANCE_STUB_STATUS=1 \
  CONFORMANCE_STUB_WRITE_EVIDENCE=0
assert_no_current_evidence
grep -Fq 'conformance harness failure' "$work_root/command_failure_without_fresh_evidence.log"

write_stale_evidence
run_row success_without_fresh_evidence 2 \
  CONFORMANCE_STUB_STATUS=0 \
  CONFORMANCE_STUB_WRITE_EVIDENCE=0
assert_no_current_evidence
grep -Fq 'conformance harness failure' "$work_root/success_without_fresh_evidence.log"

write_stale_evidence
run_row harness_failure 2 \
  CONFORMANCE_STUB_STATUS=2 \
  CONFORMANCE_STUB_WRITE_EVIDENCE=0
assert_no_current_evidence
grep -Fq 'conformance harness failure' "$work_root/harness_failure.log"

write_stale_evidence
run_row timeout 2 \
  FERROCRATE_MATRIX_CONFORMANCE_TIMEOUT_SECONDS=1 \
  CONFORMANCE_STUB_SLEEP_SECONDS=2 \
  CONFORMANCE_STUB_STATUS=0 \
  CONFORMANCE_STUB_WRITE_EVIDENCE=1
assert_no_current_evidence
grep -Fq 'timed out after 1s' "$work_root/timeout.log"

run_row invalid_timeout 2 \
  FERROCRATE_MATRIX_CONFORMANCE_TIMEOUT_SECONDS=0
grep -Fq 'FERROCRATE_MATRIX_CONFORMANCE_TIMEOUT_SECONDS' "$work_root/invalid_timeout.log"

echo "host-matrix parity wiring tests passed"
