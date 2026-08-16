#!/usr/bin/env bash
set -euo pipefail

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/.." && pwd)}"
manifest="$repo_root/docs/evidence/host-matrix/rows.tsv"
[[ -r "$manifest" ]] || { echo "matrix manifest is missing: $manifest" >&2; exit 1; }

failed=0
while IFS='|' read -r row_id distribution kernel architecture status; do
  [[ -z "${row_id// }" || "$row_id" == \#* ]] && continue
  if [[ "$status" != qualified ]]; then
    continue
  fi
  evidence_dir="$repo_root/docs/evidence/host-matrix/$row_id"
  for required in row.txt preflight.txt supporting-checks.txt bridge-ipv6-lifecycle.log managed-overlay-kernel.log authenticated-overlay.log; do
    if [[ ! -s "$evidence_dir/$required" ]]; then
      echo "qualified row $row_id is missing evidence: $required" >&2
      failed=1
    fi
  done
  if [[ -r "$evidence_dir/row.txt" ]] && ! grep -Fxq "row_id=$row_id" "$evidence_dir/row.txt"; then
    echo "qualified row $row_id has mismatched row metadata" >&2
    failed=1
  fi
done < "$manifest"

if (( failed )); then
  exit 1
fi
echo "qualified host-matrix rows have complete evidence"
