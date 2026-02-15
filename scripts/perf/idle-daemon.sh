#!/usr/bin/env bash
set -euo pipefail

SOCK=${FERROCRATE_PERF_SOCKET:-/tmp/ferrocrate-perf.sock}
MAX_IDLE_DAEMON_KB=${FERROCRATE_PERF_IDLE_DAEMON_MAX_KB:-20480}
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
    echo "perf.idle_daemon_skipped=1"
    echo "perf.idle_daemon_skip_reason=daemon_start_failed"
    exit 0
  fi
  echo "error: daemon did not start for idle-daemon benchmark (set FERROCRATE_PERF_ALLOW_SKIP=1 to skip unsupported environments)" >&2
  exit 1
fi
rss_kb=$(ps -o rss= -p "$PID" | awk '{print $1+0}')

kill "$PID" >/dev/null 2>&1 || true
rm -f "$SOCK"

echo "perf.idle_daemon_rss_kb=${rss_kb}"
echo "perf.idle_daemon_max_kb_slo=${MAX_IDLE_DAEMON_KB}"

if [ "${ENFORCE}" = "1" ] && [ "${rss_kb}" -gt "${MAX_IDLE_DAEMON_KB}" ]; then
  echo "error: idle daemon memory SLO violation (${rss_kb}KB > ${MAX_IDLE_DAEMON_KB}KB)" >&2
  exit 1
fi
