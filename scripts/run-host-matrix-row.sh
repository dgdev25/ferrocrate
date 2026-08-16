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

evidence_dir="$repo_root/docs/evidence/host-matrix/$row_id"
mkdir -p "$evidence_dir"
printf 'row_id=%s\ndistribution=%s\nkernel=%s\narchitecture=%s\nmanifest_status=%s\n' \
  "$row_id" "$distribution" "$kernel" "$architecture" "$status" \
  >"$evidence_dir/row.txt"

bash "$repo_root/scripts/host-matrix-preflight.sh" "$evidence_dir/preflight.txt"
bash "$repo_root/scripts/host-matrix-supporting-checks.sh" "$evidence_dir/supporting-checks.txt"

[[ "$(id -u)" == 0 ]] || { echo "privileged matrix row requires root" >&2; exit 77; }

bash "$repo_root/scripts/test-privileged-network-lifecycle.sh" \
  >"$evidence_dir/bridge-ipv6-lifecycle.log" 2>&1
bash "$repo_root/scripts/test-managed-overlay-kernel.sh" \
  >"$evidence_dir/managed-overlay-kernel.log" 2>&1

if [[ "${FERROCRATE_RUN_AUTHENTICATED_OVERLAY_ROW:-1}" == 1 ]]; then
  bash "$repo_root/scripts/test-two-host-authenticated.sh" \
    >"$evidence_dir/authenticated-overlay.log" 2>&1
fi

printf 'host matrix row passed: %s\n' "$row_id"
