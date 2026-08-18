#!/usr/bin/env bash
set -euo pipefail

# Exercise the public Ferrocrate Docker-compatible socket with the real Docker
# CLI. The fixture is deliberately read-only and uses an isolated runtime.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${FERROCRATE_CLI_BIN:-${ROOT_DIR}/target/debug/ferro-cli}"

if [[ ! -x "${BIN}" ]]; then
  (cd "${ROOT_DIR}" && cargo build -p ferro-cli --offline)
fi

TMP_DIR="$(mktemp -d)"
export FERROCRATE_RUNTIME_DIR="${TMP_DIR}/runtime"
mkdir -p "${FERROCRATE_RUNTIME_DIR}"
SOCKET="${TMP_DIR}/ferro.sock"

"${BIN}" daemon --docker-compat --socket "${SOCKET}" >"${TMP_DIR}/daemon.log" 2>&1 &
DAEMON_PID=$!
cleanup() {
  kill "${DAEMON_PID}" >/dev/null 2>&1 || true
  wait "${DAEMON_PID}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

for _ in $(seq 1 50); do
  [[ -S "${SOCKET}" ]] && break
  sleep 0.1
done
if [[ ! -S "${SOCKET}" ]]; then
  echo "docker-cli-smoke: daemon socket did not appear" >&2
  sed -n '1,120p' "${TMP_DIR}/daemon.log" >&2 || true
  exit 1
fi

export DOCKER_HOST="unix://${SOCKET}"
docker version --format '{{.Server.Version}}'
docker info --format '{{.ServerVersion}} {{.OperatingSystem}}'
docker images --format '{{.Repository}}:{{.Tag}}'
docker network ls --format '{{.Name}}'
docker volume ls --format '{{.Name}}'
echo "docker-cli-smoke=pass"
