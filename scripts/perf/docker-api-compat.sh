#!/usr/bin/env bash
set -euo pipefail

SOCK=${FERROCRATE_PERF_SOCKET:-/tmp/ferrocrate-docker.sock}

if [ ! -x ./target/release/ferro-cli ]; then
  cargo build -p ferro-cli --release
fi

./target/release/ferro-cli daemon --docker-compat --socket "$SOCK" >/dev/null 2>&1 &
PID=$!

sleep 1

curl --unix-socket "$SOCK" http://localhost/_ping >/dev/null
curl --unix-socket "$SOCK" http://localhost/version >/dev/null
curl --unix-socket "$SOCK" http://localhost/info >/dev/null

kill "$PID" >/dev/null 2>&1 || true
rm -f "$SOCK"

echo "perf.docker_api_compat=1"
