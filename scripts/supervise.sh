#!/usr/bin/env bash
set -euo pipefail

RUNTIME_DIR=${FERROCRATE_RUNTIME_DIR:-$HOME/.ferrocrate}
DB="$RUNTIME_DIR/containers.db"

if [ ! -f "$DB" ]; then
  echo "supervise: no containers db at $DB" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "supervise: jq required" >&2
  exit 1
fi

sled_dump() {
  strings "$DB" | jq -c 'select(startswith("{") and contains("\"id\""))'
}

while true; do
  mapfile -t records < <(sled_dump 2>/dev/null | jq -c '.')
  for rec in "${records[@]}"; do
    pid=$(echo "$rec" | jq -r '.pid')
    status=$(echo "$rec" | jq -r '.status')
    id=$(echo "$rec" | jq -r '.id')
    if [ "$status" = "running" ] && [ ! -d "/proc/$pid" ]; then
      echo "supervise: container $id lost pid $pid" >&2
    fi
  done
  sleep 2
done
