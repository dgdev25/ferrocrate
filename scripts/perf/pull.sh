#!/usr/bin/env bash
set -euo pipefail

IMAGE=${FERROCRATE_PERF_IMAGE:-alpine:latest}
RUNTIME_DIR=${FERROCRATE_RUNTIME_DIR:-$HOME/.ferrocrate}
BLOB_DIR="$RUNTIME_DIR/images/blobs"

if [ ! -x ./target/release/ferro-cli ]; then
  cargo build -p ferro-cli --release
fi

mkdir -p "$BLOB_DIR"
before=$(du -sb "$BLOB_DIR" | awk '{print $1}')
start_ns=$(date +%s%N)
./target/release/ferro-cli pull "$IMAGE" >/dev/null
end_ns=$(date +%s%N)
after=$(du -sb "$BLOB_DIR" | awk '{print $1}')

bytes=$((after - before))
elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))
if [ "$elapsed_ms" -gt 0 ]; then
  mbps=$(( bytes * 1000 / 1024 / 1024 / elapsed_ms ))
else
  mbps=0
fi

echo "perf.pull_bytes=${bytes}"
echo "perf.pull_ms=${elapsed_ms}"
echo "perf.pull_mib_per_s=${mbps}"
