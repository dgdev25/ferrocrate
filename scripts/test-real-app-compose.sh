#!/usr/bin/env bash
set -euo pipefail

# Representative real-world application fixture (web/API/database/worker)
# for the local Docker-equivalence release gate. Bounded; uses the shared
# host loopback via rootless host networking.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
project="$repo_root/scripts/test-fixtures/real-app"
timeout_secs="${FERROCRATE_REAL_APP_TIMEOUT_SECONDS:-240}"
BIN="${FERROCRATE_BIN:-$repo_root/target/release/ferro-cli}"
runtime="$(mktemp -d)"
trap 'rm -rf -- "$runtime"' EXIT

if [[ ! -x "$BIN" ]]; then
  echo "real-app: build ferro-cli first (or set FERROCRATE_BIN)" >&2
  exit 2
fi

cd "$project"
export FERROCRATE_RUNTIME_DIR="$runtime"
export FERROCRATE_ROOTLESS_NETNS="${FERROCRATE_ROOTLESS_NETNS:-1}"
export FERROCRATE_NETWORK_BACKEND="${FERROCRATE_NETWORK_BACKEND:-iptables}"

cleanup() {
  timeout --foreground --kill-after=5s 60s "$BIN" compose --file compose.yml down \
    >/dev/null 2>&1 || true
}
trap cleanup EXIT

timeout --foreground --kill-after=10s "${timeout_secs}s" \
  "$BIN" compose --file compose.yml up --detach

# Web serves the static page.
web_body="$(curl -fsS --max-time 5 http://127.0.0.1:18091/ || true)"
if [[ "$web_body" != *"real-app web"* ]]; then
  echo "real-app: web service did not serve its page (got: $web_body)" >&2
  exit 1
fi

# API serves JSON.
api_body="$(curl -fsS --max-time 5 http://127.0.0.1:18092/index.json || true)"
if [[ "$api_body" != *'"status":"ok"'* ]]; then
  echo "real-app: api service did not serve JSON (got: $api_body)" >&2
  exit 1
fi

# Database answers commands (SET/GET round trip through redis-cli in the db
# container via exec).
db_id="$("$BIN" ps --all 2>/dev/null | sed -e 's/\x1b\[[0-9;]*m//g' | awk '/redis/ {print $1; exit}')"
if [[ -z "$db_id" ]]; then
  echo "real-app: database container not found" >&2
  exit 1
fi
timeout --foreground --kill-after=5s 60s "$BIN" exec "$db_id" \
  redis-cli -p 16399 set ferrocrate real-app-up >/dev/null
got="$(timeout --foreground --kill-after=5s 60s "$BIN" exec "$db_id" \
  redis-cli -p 16399 get ferrocrate)"
if [[ "$got" != *"real-app-up"* ]]; then
  echo "real-app: database SET/GET round trip failed (got: $got)" >&2
  exit 1
fi

# Worker heartbeats into the named volume.
vol_dir="$runtime/volumes"
hb_file="$(find "$vol_dir" -name heartbeat -mmin -1 2>/dev/null | head -1)"
if [[ -z "$hb_file" ]]; then
  echo "real-app: worker heartbeat not found in volume" >&2
  exit 1
fi

echo "real-app compose fixture passed (web/api/db/worker)"
