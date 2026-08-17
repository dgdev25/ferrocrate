#!/usr/bin/env bash
set -euo pipefail

SOCK=${FERROCRATE_PERF_SOCKET:-/tmp/ferrocrate-perf.sock}
IMAGE=${FERROCRATE_PERF_IMAGE:-alpine:latest}
NETWORK_BACKEND=${FERROCRATE_PERF_NETWORK_BACKEND:-iptables}
MAX_OVERHEAD_KB=${FERROCRATE_PERF_PER_CONTAINER_MAX_KB:-2048}
ENFORCE=${FERROCRATE_PERF_ENFORCE:-1}
ALLOW_SKIP=${FERROCRATE_PERF_ALLOW_SKIP:-0}

if [ ! -x ./target/release/ferro-cli ]; then
  cargo build -p ferro-cli --release
fi

./target/release/ferro-cli daemon --docker-compat --socket "$SOCK" >/dev/null 2>&1 &
PID=$!

sleep 1
if ! ps -p "$PID" >/dev/null 2>&1; then
  rm -f "$SOCK"
  if [ "${ALLOW_SKIP}" = "1" ]; then
    echo "perf.per_container_skipped=1"
    echo "perf.per_container_skip_reason=daemon_start_failed"
    exit 0
  fi
  echo "error: daemon did not start for per-container benchmark (set FERROCRATE_PERF_ALLOW_SKIP=1 to skip unsupported environments)" >&2
  exit 1
fi
base_rss=$(ps -o rss= -p "$PID" | awk '{print $1+0}')
./target/release/ferro-cli pull "$IMAGE" >/dev/null 2>&1 || true
if ! ./target/release/ferro-cli run --rm --network-backend "$NETWORK_BACKEND" "$IMAGE" true >/dev/null 2>&1; then
  kill "$PID" >/dev/null 2>&1 || true
  rm -f "$SOCK"
  if [ "${ALLOW_SKIP}" = "1" ]; then
    echo "perf.per_container_skipped=1"
    echo "perf.per_container_skip_reason=run_failed"
    exit 0
  fi
  echo "error: container run failed for per-container benchmark (set FERROCRATE_PERF_ALLOW_SKIP=1 to skip unsupported environments)" >&2
  exit 1
fi
sleep 1
post_rss=$(ps -o rss= -p "$PID" | awk '{print $1+0}')

kill "$PID" >/dev/null 2>&1 || true
rm -f "$SOCK"

delta=$((post_rss - base_rss))
if [ "$delta" -lt 0 ]; then delta=0; fi

echo "perf.per_container_overhead_rss_kb=${delta}"
echo "perf.per_container_max_kb_slo=${MAX_OVERHEAD_KB}"

if [ "${ENFORCE}" = "1" ] && [ "${delta}" -gt "${MAX_OVERHEAD_KB}" ]; then
  echo "error: per-container overhead SLO violation (${delta}KB > ${MAX_OVERHEAD_KB}KB)" >&2
  exit 1
fi
