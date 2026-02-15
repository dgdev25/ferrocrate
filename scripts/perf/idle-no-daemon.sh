#!/usr/bin/env bash
set -euo pipefail

MAX_IDLE_KB=${FERROCRATE_PERF_IDLE_NO_DAEMON_MAX_KB:-0}
ENFORCE=${FERROCRATE_PERF_ENFORCE:-1}

pids=$(pgrep -f "ferrocrate daemon" || true)
if [ -z "${pids}" ]; then
  rss_kb=0
else
  rss_kb=$(echo "${pids}" | xargs -r ps -o rss= -p | awk '{sum+=$1} END {print sum+0}')
fi

echo "perf.idle_no_daemon_rss_kb=${rss_kb}"
echo "perf.idle_no_daemon_max_kb_slo=${MAX_IDLE_KB}"

if [ "${ENFORCE}" = "1" ] && [ "${rss_kb}" -gt "${MAX_IDLE_KB}" ]; then
  echo "error: idle no-daemon memory SLO violation (${rss_kb}KB > ${MAX_IDLE_KB}KB)" >&2
  exit 1
fi
