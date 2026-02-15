#!/usr/bin/env bash
set -euo pipefail

DOCKERFILE=${FERROCRATE_PERF_DOCKERFILE:-Dockerfile}
TAG=${FERROCRATE_PERF_TAG:-local/perf:test}
MAX_BUILD_MS=${FERROCRATE_PERF_BUILD_MAX_MS:-60000}
ENFORCE=${FERROCRATE_PERF_ENFORCE:-1}
ALLOW_SKIP=${FERROCRATE_PERF_ALLOW_SKIP:-0}

if [ ! -x ./target/release/ferro-cli ]; then
  cargo build -p ferro-cli --release
fi

start_ns=$(date +%s%N)
if ! ./target/release/ferro-cli build --tag "$TAG" --dockerfile "$DOCKERFILE" >/dev/null 2>&1; then
  if [ "${ALLOW_SKIP}" = "1" ]; then
    echo "perf.build_skipped=1"
    echo "perf.build_skip_reason=build_failed"
    exit 0
  fi
  echo "error: build benchmark failed (set FERROCRATE_PERF_ALLOW_SKIP=1 to skip unsupported environments)" >&2
  exit 1
fi
end_ns=$(date +%s%N)

elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))

echo "perf.build_ms=${elapsed_ms}"
echo "perf.build_max_ms_slo=${MAX_BUILD_MS}"

if [ "${ENFORCE}" = "1" ] && [ "${elapsed_ms}" -gt "${MAX_BUILD_MS}" ]; then
  echo "error: build time SLO violation (${elapsed_ms}ms > ${MAX_BUILD_MS}ms)" >&2
  exit 1
fi
