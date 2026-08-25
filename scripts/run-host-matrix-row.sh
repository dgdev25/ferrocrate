#!/usr/bin/env bash
set -euo pipefail

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/.." && pwd)}"
source "$repo_root/scripts/process-tree-ownership.sh"
manifest="$repo_root/docs/evidence/host-matrix/rows.tsv"
row_id="${1:-}"

[[ -n "$row_id" ]] || { echo "usage: $0 ROW_ID" >&2; exit 2; }
[[ "$row_id" != *[!a-zA-Z0-9._-]* ]] || { echo "invalid row id: $row_id" >&2; exit 2; }
[[ -r "$manifest" ]] || { echo "matrix manifest is missing: $manifest" >&2; exit 1; }

IFS='|' read -r _row_id distribution kernel architecture status < <(
  awk -F'|' -v wanted="$row_id" '$1 == wanted { print; exit }' "$manifest"
)
[[ "${_row_id:-}" == "$row_id" ]] || { echo "unknown matrix row: $row_id" >&2; exit 1; }

if [[ "$(uname -m)" != "$architecture" ]]; then
  echo "matrix row $row_id requires architecture $architecture, found $(uname -m)" >&2
  exit 77
fi
if ! uname -r | grep -Fq -- "$kernel"; then
  echo "matrix row $row_id requires kernel $kernel, found $(uname -r)" >&2
  exit 77
fi

# Check privilege before touching repository evidence. Existing qualified
# evidence may be owned by the operator that ran the privileged row, and an
# unprivileged probe must report blocked rather than fail on that directory.
if [[ "$(id -u)" != 0 ]]; then
  echo "matrix row $row_id requires root" >&2
  exit 77
fi

evidence_dir="$repo_root/docs/evidence/host-matrix/$row_id"
mkdir -p "$evidence_dir"
printf 'row_id=%s\ndistribution=%s\nkernel=%s\narchitecture=%s\nmanifest_status=%s\n' \
  "$row_id" "$distribution" "$kernel" "$architecture" "$status" \
  >"$evidence_dir/row.txt"

# A matrix row is evidence for the current checkout, so never allow the
# conformance harness to fall back to a pre-existing target/debug binary.
cargo build --release -p ferro-cli
ferrocrate_bin="$repo_root/target/release/ferro-cli"
[[ -x "$ferrocrate_bin" ]] || {
  echo "host matrix row $row_id failed to build $ferrocrate_bin" >&2
  exit 2
}
ferrocrate_commit="$(git -C "$repo_root" rev-parse HEAD)"
printf 'binary=%s\ncommit=%s\n' "$ferrocrate_bin" "$ferrocrate_commit" \
  >>"$evidence_dir/row.txt"
printf 'peer_authentication=%s\n' "${FERROCRATE_PEER_AUTH:-pidfd}" >>"$evidence_dir/row.txt"
printf 'host matrix binary: %s (commit %s)\n' "$ferrocrate_bin" "$ferrocrate_commit"

bash "$repo_root/scripts/host-matrix-preflight.sh" "$evidence_dir/preflight.txt"
bash "$repo_root/scripts/host-matrix-supporting-checks.sh" "$evidence_dir/supporting-checks.txt"

bash "$repo_root/scripts/test-privileged-network-lifecycle.sh" \
  >"$evidence_dir/bridge-ipv6-lifecycle.log" 2>&1
bash "$repo_root/scripts/test-managed-overlay-kernel.sh" \
  >"$evidence_dir/managed-overlay-kernel.log" 2>&1

if [[ "${FERROCRATE_RUN_AUTHENTICATED_OVERLAY_ROW:-1}" == 1 ]]; then
  bash "$repo_root/scripts/test-two-host-authenticated.sh" \
    >"$evidence_dir/authenticated-overlay.log" 2>&1
fi

conformance_timeout="${FERROCRATE_MATRIX_CONFORMANCE_TIMEOUT_SECONDS:-900}"
[[ "$conformance_timeout" =~ ^[1-9][0-9]*$ ]] && (( conformance_timeout <= 3600 )) || {
  echo "host matrix row $row_id conformance harness failure: FERROCRATE_MATRIX_CONFORMANCE_TIMEOUT_SECONDS must be an integer in 1..3600" >&2
  exit 2
}
command -v timeout >/dev/null 2>&1 || {
  echo "host matrix row $row_id conformance harness failure: timeout is required" >&2
  exit 2
}

parity_scoreboard="$evidence_dir/parity-scoreboard.md"
conformance_log="$evidence_dir/docker-client-conformance.log"
parity_scoreboard_tmp="$(mktemp "$evidence_dir/.parity-scoreboard.md.tmp.XXXXXX")" || {
  echo "host matrix row $row_id conformance harness failure: cannot create temporary scoreboard" >&2
  exit 2
}
conformance_log_tmp="$(mktemp "$evidence_dir/.docker-client-conformance.log.tmp.XXXXXX")" || {
  rm -f -- "$parity_scoreboard_tmp"
  echo "host matrix row $row_id conformance harness failure: cannot create temporary execution log" >&2
  exit 2
}
conformance_process_registry="$(mktemp "$evidence_dir/.conformance-processes.tmp.XXXXXX")" || {
  rm -f -- "$parity_scoreboard_tmp" "$conformance_log_tmp"
  echo "host matrix row $row_id conformance harness failure: cannot create process registry" >&2
  exit 2
}
conformance_supervisor_pid=""
conformance_tracker_pid=""

cleanup_conformance_temps() {
  rm -f -- "$parity_scoreboard_tmp" "$conformance_log_tmp" "$conformance_process_registry"
}

process_has_token() {
  local pid="$1" value="$2" entry
  [[ "$pid" =~ ^[1-9][0-9]*$ && -r "/proc/$pid/environ" ]] || return 1
  while IFS= read -r -d '' entry; do
    [[ "$entry" == "FERROCRATE_CONFORMANCE_WRAPPER_TOKEN=$value" ]] && return 0
  done <"/proc/$pid/environ" 2>/dev/null
  return 1
}

owned_conformance_processes() {
  local value="$1" environ_file pid
  grep -lFzx -- "FERROCRATE_CONFORMANCE_WRAPPER_TOKEN=$value" \
    /proc/[0-9]*/environ 2>/dev/null |
    while IFS= read -r environ_file; do
      pid="${environ_file#/proc/}"
      printf '%s\n' "${pid%/environ}"
    done
}

terminate_conformance_processes() {
  local value="$1" pid
  local -a pids=()
  mapfile -t pids < <(owned_conformance_processes "$value")
  for pid in "${pids[@]}"; do
    process_has_token "$pid" "$value" || continue
    kill -TERM "$pid" 2>/dev/null || true
  done
  for _ in $(seq 1 50); do
    mapfile -t pids < <(owned_conformance_processes "$value")
    ((${#pids[@]} == 0)) && return 0
    sleep 0.02
  done
  mapfile -t pids < <(owned_conformance_processes "$value")
  for pid in "${pids[@]}"; do
    process_has_token "$pid" "$value" || continue
    kill -KILL "$pid" 2>/dev/null || true
  done
}

conformance_process_token="ferrocrate-host-row-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"

cleanup_conformance_execution() {
  if [[ -n "$conformance_tracker_pid" ]]; then
    ferrocrate_terminate_process_tree "$conformance_tracker_pid" "$conformance_process_registry"
    conformance_tracker_pid=""
  fi
  terminate_conformance_processes "$conformance_process_token"
  cleanup_conformance_temps
}
trap cleanup_conformance_execution EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

remove_stale_conformance_evidence() {
  local artifact
  for artifact in "$parity_scoreboard" "$conformance_log"; do
    if [[ -L "$artifact" || -e "$artifact" ]]; then
      [[ -L "$artifact" || -f "$artifact" ]] || return 1
      rm -f -- "$artifact" || return 1
    fi
  done
}

if ! remove_stale_conformance_evidence; then
  cleanup_conformance_temps
  echo "host matrix row $row_id conformance harness failure: cannot safely remove stale conformance evidence" >&2
  exit 2
fi

set +e
timeout --signal=TERM --kill-after=5s "${conformance_timeout}s" \
  env FERROCRATE_CONFORMANCE_WRAPPER_TOKEN="$conformance_process_token" \
  FERROCRATE_PEER_AUTH="${FERROCRATE_PEER_AUTH:-pidfd}" \
  DOCKER_BUILDKIT=0 FERROCRATE_BIN="$ferrocrate_bin" \
  bash "$repo_root/scripts/docker-client-conformance.sh" \
  --output "$parity_scoreboard_tmp" \
  --log "$conformance_log_tmp" &
conformance_supervisor_pid=$!
if ! ferrocrate_start_process_tracker "$conformance_supervisor_pid" \
    "$conformance_process_registry" conformance_tracker_pid; then
  kill -TERM -- "-$conformance_supervisor_pid" 2>/dev/null ||
    kill -TERM "$conformance_supervisor_pid" 2>/dev/null || true
  wait "$conformance_supervisor_pid" 2>/dev/null || true
  echo "host matrix row $row_id conformance harness failure: cannot track conformance descendants" >&2
  exit 2
fi
wait "$conformance_supervisor_pid"
conformance_status=$?
set -e
ferrocrate_terminate_process_tree "$conformance_tracker_pid" "$conformance_process_registry"
conformance_tracker_pid=""
terminate_conformance_processes "$conformance_process_token"

if [[ "$conformance_status" == 124 ]]; then
  cleanup_conformance_temps
  echo "host matrix row $row_id conformance harness failure: timed out after ${conformance_timeout}s" >&2
  exit 2
fi
if [[ "$conformance_status" != 0 && "$conformance_status" != 1 ]]; then
  cleanup_conformance_temps
  echo "host matrix row $row_id conformance harness failure: exit=$conformance_status" >&2
  exit 2
fi
if [[ ! -s "$parity_scoreboard_tmp" || ! -s "$conformance_log_tmp" ]]; then
  cleanup_conformance_temps
  echo "host matrix row $row_id conformance harness failure: exit=$conformance_status without two fresh evidence files" >&2
  exit 2
fi
if ! mv -f -- "$parity_scoreboard_tmp" "$parity_scoreboard"; then
  cleanup_conformance_temps
  echo "host matrix row $row_id conformance harness failure: cannot publish parity scoreboard" >&2
  exit 2
fi
if ! mv -f -- "$conformance_log_tmp" "$conformance_log"; then
  rm -f -- "$parity_scoreboard"
  cleanup_conformance_temps
  echo "host matrix row $row_id conformance harness failure: cannot publish conformance execution log" >&2
  exit 2
fi

if [[ "$conformance_status" == 1 ]]; then
  echo "host matrix row $row_id completed conformance evidence with command failures: $parity_scoreboard, $conformance_log" >&2
  exit 1
fi

trap - EXIT INT TERM
cleanup_conformance_temps
printf 'host matrix row passed: %s\n' "$row_id"
