#!/usr/bin/env bash
set -euo pipefail

rss_kb=$(pgrep -f "ferrocrate daemon" | xargs -r ps -o rss= -p | awk '{sum+=$1} END {print sum+0}')

echo "perf.idle_no_daemon_rss_kb=${rss_kb}"
