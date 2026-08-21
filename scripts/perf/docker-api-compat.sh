#!/usr/bin/env bash
set -euo pipefail

SOCK=${FERROCRATE_PERF_SOCKET:-"/tmp/ferrocrate-docker-api-compat.$$.$RANDOM.sock"}
TIMEOUT_SECONDS=${FERROCRATE_PERF_TIMEOUT_SECONDS:-20}
BUILD_TIMEOUT_SECONDS=${FERROCRATE_PERF_BUILD_TIMEOUT_SECONDS:-300}
PID=""

if ! [[ "$TIMEOUT_SECONDS" =~ ^[1-9][0-9]*$ && "$BUILD_TIMEOUT_SECONDS" =~ ^[1-9][0-9]*$ ]]; then
  echo "timeout values must be positive integers" >&2
  exit 2
fi

cleanup() {
  if [[ -n "$PID" ]] && kill -0 "$PID" 2>/dev/null; then
    kill "$PID" 2>/dev/null || true
    timeout --foreground --kill-after=2s 3s bash -c "while kill -0 '$PID' 2>/dev/null; do sleep 0.1; done" 2>/dev/null || true
  fi
  rm -f -- "$SOCK"
}
trap cleanup EXIT INT TERM

if ! command -v timeout >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
  echo "missing required command: timeout and curl" >&2
  exit 1
fi

if [ ! -x ./target/release/ferro-cli ]; then
  timeout --foreground --kill-after=10s "${BUILD_TIMEOUT_SECONDS}s" \
    cargo build -p ferro-cli --release
fi

timeout --foreground --kill-after=3s "${TIMEOUT_SECONDS}s" \
  ./target/release/ferro-cli daemon --docker-compat --socket "$SOCK" >/dev/null 2>&1 &
PID=$!

deadline=$((SECONDS + TIMEOUT_SECONDS))
until timeout --foreground --kill-after=1s 3s \
  curl --fail --silent --show-error --max-time 2 --unix-socket "$SOCK" \
  http://localhost/_ping >/dev/null 2>&1; do
  if (( SECONDS >= deadline )); then
    echo "docker API daemon did not become ready within ${TIMEOUT_SECONDS}s" >&2
    exit 1
  fi
  sleep 0.1
done

timeout --foreground --kill-after=2s "${TIMEOUT_SECONDS}s" \
  curl --fail --silent --show-error --max-time "$TIMEOUT_SECONDS" \
  --unix-socket "$SOCK" http://localhost/version >/dev/null
timeout --foreground --kill-after=2s "${TIMEOUT_SECONDS}s" \
  curl --fail --silent --show-error --max-time "$TIMEOUT_SECONDS" \
  --unix-socket "$SOCK" http://localhost/info >/dev/null

echo "perf.docker_api_compat=1 timeout_seconds=$TIMEOUT_SECONDS"
