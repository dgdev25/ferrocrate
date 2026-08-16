#!/usr/bin/env bash
set -euo pipefail

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/../.." && pwd)}"
output_dir="${FERROCRATE_PERF_OUTPUT_DIR:-$repo_root/target/perf-baseline}"
manifest="$output_dir/manifest.tsv"
require_all="${FERROCRATE_PERF_REQUIRE_ALL:-0}"

if [[ ! -f "$manifest" ]]; then
  echo "performance baseline manifest is missing: $manifest" >&2
  exit 1
fi

required=(startup pull build idle-daemon idle-no-daemon per-container binary-size ai-latency docker-api oci-conformance rootless)
failed=0
for name in "${required[@]}"; do
  status="$(awk -F '\t' -v name="$name" '$1 == name { print $2; found=1 } END { if (!found) print "missing" }' "$manifest" | tail -n1)"
  if [[ "$status" != "pass" ]]; then
    echo "baseline.$name=$status"
    failed=1
    continue
  fi
  log="$output_dir/$name.txt"
  if [[ ! -s "$log" ]]; then
    echo "baseline.$name=empty"
    failed=1
    continue
  fi
  if [[ "$require_all" == 1 ]] && rg -q '_skipped=1|rootless\.[A-Za-z0-9_]+=missing' "$log"; then
    echo "baseline.$name=skipped-prerequisite"
    failed=1
  else
    echo "baseline.$name=pass"
  fi
done

cp "$manifest" "$output_dir/verified-manifest.tsv"
if [[ "$failed" -ne 0 ]]; then
  echo "performance baseline verification failed; inspect $output_dir" >&2
  exit 1
fi
echo "performance baseline verification passed: $output_dir"
