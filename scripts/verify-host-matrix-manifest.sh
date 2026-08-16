#!/usr/bin/env bash
set -euo pipefail

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/.." && pwd)}"
manifest="$repo_root/docs/evidence/host-matrix/rows.tsv"
[[ -r "$manifest" ]] || { echo "matrix manifest is missing: $manifest" >&2; exit 1; }

failed=0
declare -A seen=()
while IFS='|' read -r row_id distribution kernel architecture status; do
  [[ -z "${row_id// }" || "$row_id" == \#* ]] && continue
  if [[ -n "${seen[$row_id]:-}" ]]; then
    echo "duplicate matrix row: $row_id" >&2
    failed=1
  fi
  seen["$row_id"]=1
  [[ "$row_id" != *[!a-zA-Z0-9._-]* && -n "$row_id" ]] || { echo "invalid row id: $row_id" >&2; failed=1; }
  [[ -n "$distribution" && -n "$kernel" && -n "$architecture" ]] || { echo "incomplete metadata for row: $row_id" >&2; failed=1; }
  case "$status" in
    candidate|qualified|blocked) ;;
    *) echo "invalid status for $row_id: $status" >&2; failed=1 ;;
  esac
done < "$manifest"

(( ${#seen[@]} > 0 )) || { echo "matrix manifest has no rows" >&2; failed=1; }
if (( failed )); then exit 1; fi
echo "host-matrix manifest is valid (${#seen[@]} rows)"
