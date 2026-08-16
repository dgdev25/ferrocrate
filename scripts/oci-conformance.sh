#!/usr/bin/env bash
set -euo pipefail

# Run the repository's OCI image, runtime, and distribution qualification
# fixtures as one deterministic gate. These are compatibility fixtures, not a
# claim of complete upstream OCI conformance.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

OUT_DIR="${ROOT_DIR}/target/compat/oci"
mkdir -p "$OUT_DIR"

run_case() {
  local name="$1"
  shift
  local log="${OUT_DIR}/${name}.log"
  if "$@" >"$log" 2>&1; then
    printf '%s=pass\n' "$name"
  else
    printf '%s=fail\n' "$name"
    return 1
  fi
}

status=0
run_case image bash scripts/perf/oci-compat.sh || status=1
run_case runtime bash scripts/perf/oci-runtime-compat.sh || status=1
run_case distribution bash scripts/perf/oci-distribution-compat.sh || status=1

if [[ "$status" -eq 0 ]]; then
  printf 'oci_conformance=pass\n'
else
  printf 'oci_conformance=fail\n' >&2
fi
exit "$status"
