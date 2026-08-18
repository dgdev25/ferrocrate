#!/usr/bin/env bash
set -euo pipefail

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/.." && pwd)}"
bin="${FERROCRATE_BIN:-$repo_root/target/release/ferro-cli}"
strict="${FERROCRATE_DOCKER_CLI_REQUIRED:-0}"

if ! command -v docker >/dev/null 2>&1; then
  if [[ "$strict" == "1" || "$strict" == "true" ]]; then
    echo "Docker CLI is required but not installed" >&2
    exit 1
  fi
  echo "docker CLI compatibility smoke skipped (docker not installed)"
  exit 0
fi
if [[ ! -x "$bin" ]]; then
  if [[ "$strict" == "1" || "$strict" == "true" ]]; then
    echo "Ferrocrate binary is required but missing: $bin" >&2
    exit 1
  fi
  echo "docker CLI compatibility smoke skipped (missing Ferrocrate binary: $bin)"
  exit 0
fi

runtime_dir="$(mktemp -d "${TMPDIR:-/tmp}/ferrocrate-docker-cli.XXXXXX")"
socket="$runtime_dir/docker.sock"
daemon_pid=""
cleanup() {
  if [[ -n "$daemon_pid" ]]; then
    kill "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
  fi
  rm -rf "$runtime_dir"
}
trap cleanup EXIT

FERROCRATE_RUNTIME_DIR="$runtime_dir" "$bin" daemon --docker-compat --socket "$socket" \
  >"$runtime_dir/daemon.stdout" 2>"$runtime_dir/daemon.stderr" &
daemon_pid=$!
for _ in $(seq 1 100); do
  if [[ -S "$socket" ]] && docker -H "unix://$socket" version >/dev/null 2>&1; then
    break
  fi
  sleep 0.05
done
if ! [[ -S "$socket" ]]; then
  echo "Docker-compatible socket did not start" >&2
  cat "$runtime_dir/daemon.stderr" >&2 || true
  exit 1
fi

host="unix://$socket"
docker -H "$host" version >/dev/null
docker -H "$host" info >/dev/null
docker -H "$host" ps --all >/dev/null
docker -H "$host" images >/dev/null

name="docker-cli-compat-$$"
events_file="$runtime_dir/events.jsonl"
timeout 5 docker -H "$host" events --since 0s --filter type=container \
  >"$events_file" 2>"$runtime_dir/events.stderr" &
events_pid=$!
sleep 0.2
container_id="$(docker -H "$host" create --name "$name" busybox true)"
[[ -n "$container_id" ]] || { echo "docker create returned no ID" >&2; exit 1; }
docker -H "$host" inspect "$name" >/dev/null
docker -H "$host" rm "$name" >/dev/null
wait "$events_pid" 2>/dev/null || true
grep -q 'container create' "$events_file" || {
  echo "Docker CLI did not receive a container create event" >&2
  cat "$events_file" >&2 || true
  cat "$runtime_dir/events.stderr" >&2 || true
  exit 1
}

echo "Docker CLI compatibility smoke passed: version/info/ps/images/create/rm/events"
