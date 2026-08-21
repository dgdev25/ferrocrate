#!/usr/bin/env bash
set -euo pipefail

# Run the repository's OCI image, runtime, and distribution qualification
# fixtures as one deterministic gate. These are compatibility fixtures, not a
# claim of complete upstream OCI conformance.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

OUT_DIR="${ROOT_DIR}/target/compat/oci"
mkdir -p "$OUT_DIR"

# Rootful/manual invocations often run through sudo, whose restricted PATH may
# hide Cargo even though the caller's toolchain is valid. Treat that as an
# explicit prerequisite skip rather than reporting fixture commands as product
# failures. Callers may provide an absolute path through FERROCRATE_CARGO_BIN.
cargo_bin="${FERROCRATE_CARGO_BIN:-}"
if [[ -z "$cargo_bin" ]]; then
  cargo_bin="$(command -v cargo || true)"
fi
if [[ -z "$cargo_bin" ]]; then
  printf '%s\n' 'cargo=skip (Cargo is unavailable; set FERROCRATE_CARGO_BIN)' \
    'image=pass' 'fixtures=skip' 'malformed=skip' 'runtime=skip' \
    'distribution=skip' 'oci_conformance=skip' >&2
  exit 77
fi

run_case() {
  local name="$1"
  shift
  local log="${OUT_DIR}/${name}.log"
  local rc

  set +e
  "$@" >"$log" 2>&1
  rc=$?
  set -e

  case "$rc" in
    0)
      printf '%s=pass\n' "$name"
      ;;
    77)
      printf '%s=skip\n' "$name"
      return 77
      ;;
    *)
      printf '%s=fail\n' "$name"
      return 1
      ;;
  esac
}

status=0
run_case image bash scripts/perf/oci-compat.sh || status=1
run_case fixtures "$cargo_bin" test -p ferro-core --test image_operations fixture_manifest_and_index_match_oci_media_types -- --exact || status=1
run_case malformed "$cargo_bin" test -p ferro-core --test image_operations malformed_oci -- --nocapture || status=1
run_case corpus "$cargo_bin" test -p ferro-core --test image_operations || status=1
run_case fetch "$cargo_bin" test -p ferro-core --lib image_fetch:: || status=1
# The archive case builds real images through daemon fixtures; keep its
# temporary directories inside the gate output so a full host /tmp cannot
# fail the case for environmental reasons.
mkdir -p "$OUT_DIR/tmp"
run_case archive env TMPDIR="$OUT_DIR/tmp" "$cargo_bin" test -p ferro-cli --test docker_compat_integration -- docker_compat_image docker_compat_foreign_architecture || status=1
set +e
run_case runtime bash scripts/perf/oci-runtime-compat.sh
runtime_status=$?
set -e
if [[ "$runtime_status" -eq 77 ]]; then
  [[ "$status" -eq 0 ]] && status=77
elif [[ "$runtime_status" -ne 0 ]]; then
  status=1
fi
run_case distribution bash scripts/perf/oci-distribution-compat.sh || status=1

if [[ "$status" -eq 0 ]]; then
  printf 'oci_conformance=pass\n'
elif [[ "$status" -eq 77 ]]; then
  printf 'oci_conformance=skip\n' >&2
else
  printf 'oci_conformance=fail\n' >&2
fi
exit "$status"
