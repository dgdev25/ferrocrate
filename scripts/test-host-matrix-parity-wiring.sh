#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname -- "$0")/.." && pwd)"
runner="$repo_root/scripts/run-host-matrix-row.sh"

[[ -x "$runner" ]] || { echo "missing executable row runner: $runner" >&2; exit 1; }

work_root="$(mktemp -d "${TMPDIR:-/tmp}/ferrocrate-host-matrix-parity.XXXXXX")"
fixture_root="$work_root/repo"
fixture_scripts="$fixture_root/scripts"
fixture_bin="$work_root/bin"
evidence_dir="$fixture_root/docs/evidence/host-matrix/contract-row"
stub_state="$work_root/state"
mkdir -p "$fixture_scripts" "$fixture_root/docs/evidence/host-matrix" "$fixture_bin" "$stub_state"
cp "$runner" "$fixture_scripts/run-host-matrix-row.sh"
cp "$repo_root/scripts/process-tree-ownership.sh" "$fixture_scripts/process-tree-ownership.sh"

cleanup_contract_test() {
  local pid_file pid
  for pid_file in "$stub_state"/*.pid; do
    [[ -f "$pid_file" ]] || continue
    pid="$(cat "$pid_file" 2>/dev/null || true)"
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || continue
    kill -KILL "$pid" 2>/dev/null || true
  done
  [[ -z "${unrelated_pid:-}" ]] || kill -KILL "$unrelated_pid" 2>/dev/null || true
  rm -rf -- "$work_root"
}
trap cleanup_contract_test EXIT

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
  printf '%s\n' "$$" >"$STUB_STATE/harness.pid"
  if [[ "${CONFORMANCE_STUB_SPAWN_DESCENDANT:-0}" == 1 ]]; then
    setsid env -u FERROCRATE_CONFORMANCE_PROCESS_TOKEN \
      -u FERROCRATE_CONFORMANCE_WRAPPER_TOKEN \
      python3 - "$STUB_STATE/harness-descendant.pid" <<'PY' &
import os
import signal
import sys
import time

with open(sys.argv[1], "w", encoding="utf-8") as pid_file:
    pid_file.write(f"{os.getpid()}\n")
signal.signal(signal.SIGTERM, signal.SIG_IGN)
while True:
    time.sleep(1)
PY
    for _ in $(seq 1 100); do
      [[ -s "$STUB_STATE/harness-descendant.pid" ]] && break
      sleep 0.01
    done
  fi
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

setsid python3 - "$stub_state/unrelated.pid" <<'PY' &
import os
import signal
import sys
import time

with open(sys.argv[1], "w", encoding="utf-8") as pid_file:
    pid_file.write(f"{os.getpid()}\n")
signal.signal(signal.SIGTERM, signal.SIG_IGN)
while True:
    time.sleep(1)
PY
unrelated_pid=$!

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
  CONFORMANCE_STUB_SPAWN_DESCENDANT=1 \
  CONFORMANCE_STUB_STATUS=0 \
  CONFORMANCE_STUB_WRITE_EVIDENCE=1
assert_no_current_evidence
grep -Fq 'timed out after 1s' "$work_root/timeout.log"

assert_process_gone() {
  local label="$1" pid_file="$2" pid
  [[ -s "$pid_file" ]] || { echo "$label did not record its PID" >&2; exit 1; }
  pid="$(cat "$pid_file")"
  for _ in $(seq 1 100); do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.01
  done
  echo "$label survived host-wrapper timeout cleanup (pid=$pid)" >&2
  exit 1
}
assert_process_gone "conformance harness" "$stub_state/harness.pid"
assert_process_gone "escaped conformance descendant" "$stub_state/harness-descendant.pid"
kill -0 "$unrelated_pid" 2>/dev/null || {
  echo "host-wrapper cleanup touched an unrelated process" >&2
  exit 1
}

# TERM delivered to the wrapper itself must interrupt its wait immediately and
# reap the harness plus a marker-stripping setsid descendant. Supervisors often
# escalate promptly; deferring the trap until the timeout child returns is not
# a safe cleanup strategy.
rm -f -- "$stub_state/harness.pid" "$stub_state/harness-descendant.pid"
clear_current_evidence
set +e
FERROCRATE_REPO_ROOT="$fixture_root" \
  FERROCRATE_RUN_AUTHENTICATED_OVERLAY_ROW=0 \
  FERROCRATE_MATRIX_CONFORMANCE_TIMEOUT_SECONDS=30 \
  CONFORMANCE_STUB_SLEEP_SECONDS=30 \
  CONFORMANCE_STUB_SPAWN_DESCENDANT=1 \
  CONFORMANCE_STUB_STATUS=0 \
  CONFORMANCE_STUB_WRITE_EVIDENCE=1 \
  PATH="$fixture_bin:$PATH" \
  STUB_STATE="$stub_state" \
  bash "$fixture_scripts/run-host-matrix-row.sh" contract-row \
  >"$work_root/terminated.log" 2>&1 &
terminated_runner_pid=$!
set -e
for _ in $(seq 1 200); do
  [[ -s "$stub_state/harness.pid" && -s "$stub_state/harness-descendant.pid" ]] && break
  sleep 0.01
done
[[ -s "$stub_state/harness-descendant.pid" ]] || {
  echo "termination case did not start its descendant" >&2
  exit 1
}
kill -TERM "$terminated_runner_pid"
for _ in $(seq 1 200); do
  kill -0 "$terminated_runner_pid" 2>/dev/null || break
  sleep 0.01
done
if kill -0 "$terminated_runner_pid" 2>/dev/null; then
  kill -KILL "$terminated_runner_pid" 2>/dev/null || true
fi
set +e
wait "$terminated_runner_pid"
terminated_status=$?
set -e
[[ "$terminated_status" == 143 ]] || {
  echo "terminated wrapper returned $terminated_status; expected 143" >&2
  exit 1
}
assert_process_gone "terminated conformance harness" "$stub_state/harness.pid"
assert_process_gone "terminated escaped conformance descendant" "$stub_state/harness-descendant.pid"
assert_no_current_evidence
kill -0 "$unrelated_pid" 2>/dev/null || {
  echo "termination cleanup touched an unrelated process" >&2
  exit 1
}

run_row invalid_timeout 2 \
  FERROCRATE_MATRIX_CONFORMANCE_TIMEOUT_SECONDS=0
grep -Fq 'FERROCRATE_MATRIX_CONFORMANCE_TIMEOUT_SECONDS' "$work_root/invalid_timeout.log"

echo "host-matrix parity wiring tests passed"
