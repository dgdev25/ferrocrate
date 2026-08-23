#!/usr/bin/env bash
set -euo pipefail

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/.." && pwd)}"
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

cleanup_conformance_temps() {
  rm -f -- "$parity_scoreboard_tmp" "$conformance_log_tmp"
}

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
timeout --foreground --kill-after=5s "${conformance_timeout}s" \
  env DOCKER_BUILDKIT=0 bash "$repo_root/scripts/docker-client-conformance.sh" \
  --output "$parity_scoreboard_tmp" \
  --log "$conformance_log_tmp"
conformance_status=$?
set -e

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

printf 'host matrix row passed: %s\n' "$row_id"
