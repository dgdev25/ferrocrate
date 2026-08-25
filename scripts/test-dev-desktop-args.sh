#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
launcher="$root/scripts/dev-desktop.sh"

expect_output() {
  local expected="$1"
  shift
  local output
  output="$(FERROCRATE_DEV_DESKTOP_PARSE_ONLY=1 "$launcher" "$@")"
  if [[ "$output" != "$expected" ]]; then
    printf 'unexpected parsed arguments for:' >&2
    printf ' %q' "$@" >&2
    printf '\nexpected:\n%s\nactual:\n%s\n' "$expected" "$output" >&2
    exit 1
  fi
}

expect_usage_error() {
  local output status
  set +e
  output="$(FERROCRATE_DEV_DESKTOP_PARSE_ONLY=1 "$launcher" "$@" 2>&1)"
  status=$?
  set -e
  if [[ $status -ne 2 || "$output" != usage:* ]]; then
    printf 'expected usage exit 2 for:' >&2
    printf ' %q' "$@" >&2
    printf '\nstatus: %s\noutput:\n%s\n' "$status" "$output" >&2
    exit 1
  fi
}

expect_output $'mode=native\nlisten=127.0.0.1:4190'
expect_output $'mode=native\nlisten=127.0.0.1:4190' native
expect_output $'mode=web\nlisten=127.0.0.1:4190' --web
expect_output $'mode=web\nlisten=127.0.0.1:4317' --web --listen 127.0.0.1:4317
expect_output $'mode=web\nlisten=127.0.0.1:4317' --listen 127.0.0.1:4317 --web

expect_usage_error --listen
expect_usage_error --listen 127.0.0.1:4317
expect_usage_error --web --listen localhost:4317
expect_usage_error --web --listen 0.0.0.0:4317
expect_usage_error --web --listen 127.0.0.1:0
expect_usage_error --web --listen 127.0.0.1:65536
expect_usage_error --web --listen '127.0.0.1:4317;echo unsafe'
expect_usage_error --web --unknown
expect_usage_error native native
expect_usage_error native --web
expect_usage_error --web native
expect_usage_error native --listen 127.0.0.1:4317
expect_usage_error --listen 127.0.0.1:4317 native
expect_usage_error --web --web
expect_usage_error --web --listen 127.0.0.1:4317 --listen 127.0.0.1:4318

if ! grep -Fq 'export PATH="$root/target/debug:$root/target/release:$PATH"' "$launcher"; then
  printf 'dev launcher must prefer the freshly built debug desktop proxy\n' >&2
  exit 1
fi

printf 'dev-desktop argument tests passed\n'
