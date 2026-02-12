#!/usr/bin/env bash
set -euo pipefail

IMAGE=${FERROCRATE_PERF_IMAGE:-alpine:latest}

if [ ! -x ./target/release/ferro-cli ]; then
  cargo build -p ferro-cli --release
fi

start_ns=$(date +%s%N)
./target/release/ferro-cli pull "$IMAGE" >/dev/null 2>&1 || true
./target/release/ferro-cli run --rm "$IMAGE" true >/dev/null 2>&1
end_ns=$(date +%s%N)

elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))

echo "perf.startup_ms=${elapsed_ms}"
