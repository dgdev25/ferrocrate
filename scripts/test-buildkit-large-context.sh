#!/usr/bin/env bash
# Regression for S200: BuildKit filesync must accept a real Compose context
# whose many small entries arrive as a long run of tiny HTTP/2 DATA frames.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ferro_bin="${FERROCRATE_BIN:-$repo_root/target/release/ferro-cli}"
[[ -x "$ferro_bin" ]] || { echo "missing ferro-cli: $ferro_bin" >&2; exit 2; }
command -v docker >/dev/null || { echo "docker CLI is required" >&2; exit 2; }

work_root="$(mktemp -d "${TMPDIR:-/tmp}/ferro-s200-context.XXXXXX")"
runtime_root="$(mktemp -d "${TMPDIR:-/tmp}/ferro-s200-runtime.XXXXXX")"
socket_path="$(mktemp -u "${TMPDIR:-/tmp}/ferro-s200.sock.XXXXXX")"
daemon_pid=""
cleanup() {
  [[ -z "$daemon_pid" ]] || kill "$daemon_pid" 2>/dev/null || true
  [[ -z "$daemon_pid" ]] || wait "$daemon_pid" 2>/dev/null || true
  rm -rf -- "$work_root" "$runtime_root"
}
trap cleanup EXIT

mkdir -p "$work_root/tree" "$runtime_root/run"
printf 'FROM scratch\nCOPY . /fixture\n' >"$work_root/Dockerfile"
printf 'services:\n  fixture:\n    build: .\n' >"$work_root/compose.yml"
for index in $(seq 1 512); do
  printf 'small fixture file %s\n' "$index" >"$work_root/tree/file-$index.txt"
done
# These are deliberately sparse binaries: the context has the same ~86MiB
# logical size as the reported project without making every test run write it.
truncate -s 64M "$work_root/tree/payload-a.bin"
truncate -s 22M "$work_root/tree/payload-b.bin"
[[ "$(du -sb "$work_root" | awk '{print $1}')" -ge $((86 * 1024 * 1024)) ]] || {
  echo "large BuildKit fixture is unexpectedly small" >&2
  exit 1
}

XDG_RUNTIME_DIR="$runtime_root/run" \
FERROCRATE_HOME="$runtime_root/home" \
  "$ferro_bin" daemon --docker-compat --socket "$socket_path" >"$work_root/daemon.out" 2>"$work_root/daemon.err" &
daemon_pid=$!
for _ in $(seq 1 100); do
  [[ -S "$socket_path" ]] && break
  sleep 0.1
done
[[ -S "$socket_path" ]] || { echo "compat daemon did not create its socket" >&2; exit 1; }

(
  cd "$work_root"
  DOCKER_HOST="unix://$socket_path" docker compose --ansi never build
) >"$work_root/build.out" 2>"$work_root/build.err"
echo "BuildKit large-context fixture passed"
