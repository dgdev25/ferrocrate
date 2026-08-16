#!/usr/bin/env bash
set -euo pipefail

# Run every declared host-matrix row and archive a machine-readable result.
# A row that cannot run on the current host is recorded as blocked (exit 77)
# rather than being misreported as a qualification failure or success. This
# keeps the supported-host claim tied to evidence from the matching kernel,
# architecture, privileges, and tools.

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/.." && pwd)}"
manifest="$repo_root/docs/evidence/host-matrix/rows.tsv"
output_dir="${FERROCRATE_MATRIX_OUTPUT:-$repo_root/target/host-matrix}"
runner="$repo_root/scripts/run-host-matrix-row.sh"

[[ -r "$manifest" ]] || { echo "matrix manifest is missing: $manifest" >&2; exit 1; }
[[ -x "$runner" ]] || { echo "matrix row runner is not executable: $runner" >&2; exit 1; }
mkdir -p "$output_dir"
summary="$output_dir/results.tsv"
printf 'row_id\tresult\texit_code\tlog\n' >"$summary"

failed=0
blocked=0
total=0
while IFS='|' read -r row_id _distribution _kernel _architecture _status; do
  [[ -n "${row_id:-}" && "$row_id" != \#* ]] || continue
  total=$((total + 1))
  log="$output_dir/$row_id.log"
  set +e
  "$runner" "$row_id" >"$log" 2>&1
  rc=$?
  set -e
  case "$rc" in
    0)
      result=qualified
      ;;
    77)
      result=blocked
      blocked=$((blocked + 1))
      ;;
    *)
      result=failed
      failed=$((failed + 1))
      ;;
  esac
  printf '%s\t%s\t%s\t%s\n' "$row_id" "$result" "$rc" "$log" >>"$summary"
  printf 'host-matrix row=%s result=%s exit=%s\n' "$row_id" "$result" "$rc"
done <"$manifest"

(( total > 0 )) || { echo "matrix manifest has no rows" >&2; exit 1; }
if (( failed > 0 )); then
  echo "host matrix completed with $failed failed row(s); see $summary" >&2
  exit 1
fi
if (( blocked > 0 )); then
  echo "host matrix has $blocked blocked row(s); no unsupported row was marked qualified" >&2
  exit 77
fi
echo "host matrix qualified all $total row(s)"
