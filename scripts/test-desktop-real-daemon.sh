#!/usr/bin/env bash
# Real-socket desktop API regression: no mocks, no Docker daemon fallback.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
test_root="$(mktemp -d)"
runtime="$test_root/runtime"
socket="$runtime/ferrocrate.sock"
mkdir -p "$runtime"
export FERROCRATE_RUNTIME_DIR="$runtime"
export XDG_RUNTIME_DIR="$runtime"
export FERROCRATE_ROOTLESS_SOCKET="$socket"
export FERROCRATE_BIN="${FERROCRATE_BIN:-$root/target/release/ferro-cli}"
desktop_bin="${FERRO_DESKTOP_BIN:-$root/target/debug/ferro-desktop}"
daemon_pid=""
container_id=""

cleanup() {
  if [[ -n "$container_id" ]]; then
    curl -fsS --unix-socket "$socket" -X DELETE "http://localhost/containers/$container_id?force=true" >/dev/null 2>&1 || true
  fi
  if [[ -n "$daemon_pid" ]]; then
    kill "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
  fi
  rm -rf -- "$test_root"
}
trap cleanup EXIT

"$FERROCRATE_BIN" daemon --socket "$socket" --docker-compat >"$test_root/daemon.log" 2>&1 &
daemon_pid=$!
for _ in $(seq 1 100); do
  [[ -S "$socket" ]] && curl -fsS --unix-socket "$socket" http://localhost/_ping >/dev/null && break
  sleep 0.1
done
curl -fsS --unix-socket "$socket" http://localhost/_ping | grep -qx OK

# Lists and typed mutations use the same explicit Ferrocrate socket.
curl -fsS --unix-socket "$socket" 'http://localhost/containers/json?all=1' >/dev/null
curl -fsS --unix-socket "$socket" http://localhost/images/json >/dev/null
"$desktop_bin" volume-proxy --socket "$socket" create desktop-real-volume >/dev/null
"$desktop_bin" volume-proxy --socket "$socket" list | grep -q desktop-real-volume
"$desktop_bin" network-proxy --socket "$socket" create desktop-real-network --subnet 172.31.240.0/24 >/dev/null
"$desktop_bin" network-proxy --socket "$socket" list | grep -q desktop-real-network
"$desktop_bin" network-proxy --socket "$socket" inspect desktop-real-network | grep -q desktop-real-network

# Pull, create, inspect and stats are real daemon operations.
curl -fsS --unix-socket "$socket" -X POST 'http://localhost/images/create?fromImage=alpine&tag=latest' >/dev/null
create_json="$(curl -fsS --unix-socket "$socket" -H 'Content-Type: application/json' -d '{"Image":"alpine:latest","Cmd":["sh","-c","sleep 30"]}' http://localhost/containers/create?name=desktop-real-container)"
container_id="$(printf '%s' "$create_json" | jq -er '.Id')"
curl -fsS --unix-socket "$socket" -X POST "http://localhost/containers/$container_id/start" >/dev/null
"$desktop_bin" container-proxy --socket "$socket" inspect "$container_id" | grep -q "$container_id"
curl -fsS --unix-socket "$socket" "http://localhost/containers/$container_id/stats?stream=false" | jq -e '.stats' >/dev/null
printf 'desktop real-daemon paths passed via %s\n' "$socket"
