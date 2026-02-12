#!/usr/bin/env bash
set -euo pipefail

DOCKERFILE=${FERROCRATE_PERF_DOCKERFILE:-Dockerfile}
TAG=${FERROCRATE_PERF_TAG:-local/perf:test}

if [ ! -x ./target/release/ferro-cli ]; then
  cargo build -p ferro-cli --release
fi

start_ns=$(date +%s%N)
./target/release/ferro-cli build --tag "$TAG" --dockerfile "$DOCKERFILE" >/dev/null 2>&1
end_ns=$(date +%s%N)

elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))

echo "perf.build_ms=${elapsed_ms}"
