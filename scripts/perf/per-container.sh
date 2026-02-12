#!/usr/bin/env bash
set -euo pipefail

SOCK=${FERROCRATE_PERF_SOCKET:-/tmp/ferrocrate-perf.sock}
IMAGE=${FERROCRATE_PERF_IMAGE:-alpine:latest}

if [ ! -x ./target/release/ferro-cli ]; then
  cargo build -p ferro-cli --release
fi

./target/release/ferro-cli daemon --docker-compat --socket "$SOCK" >/dev/null 2>&1 &
PID=$!

sleep 1
base_rss=$(ps -o rss= -p "$PID" | awk '{print $1+0}')
./target/release/ferro-cli pull "$IMAGE" >/dev/null 2>&1 || true
./target/release/ferro-cli run --rm "$IMAGE" true >/dev/null 2>&1
sleep 1
post_rss=$(ps -o rss= -p "$PID" | awk '{print $1+0}')

kill "$PID" >/dev/null 2>&1 || true
rm -f "$SOCK"

delta=$((post_rss - base_rss))
if [ "$delta" -lt 0 ]; then delta=0; fi

echo "perf.per_container_overhead_rss_kb=${delta}"
