#!/usr/bin/env bash
set -euo pipefail

SOCK=${FERROCRATE_PERF_SOCKET:-/tmp/ferrocrate-perf.sock}

if [ ! -x ./target/release/ferro-cli ]; then
  cargo build -p ferro-cli --release
fi

./target/release/ferro-cli daemon --docker-compat --socket "$SOCK" >/dev/null 2>&1 &
PID=$!

sleep 1
rss_kb=$(ps -o rss= -p "$PID" | awk '{print $1+0}')

kill "$PID" >/dev/null 2>&1 || true
rm -f "$SOCK"

echo "perf.idle_daemon_rss_kb=${rss_kb}"
