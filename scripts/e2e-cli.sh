#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT_DIR}/target/debug/ferro-cli"

if [[ ! -x "${BIN}" ]]; then
  echo "Building ferro-cli..."
  (cd "${ROOT_DIR}" && cargo build -p ferro-cli)
fi

run() {
  echo "+ $*"
  "$@"
}

cleanup() {
  if [[ -n "${DOCKER_COMPAT_PID:-}" ]]; then
    kill "${DOCKER_COMPAT_PID}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

TMP_DIR="$(mktemp -d)"
export FERROCRATE_RUNTIME_DIR="${TMP_DIR}/runtime"
mkdir -p "${FERROCRATE_RUNTIME_DIR}"
COMPOSE_FILE="${TMP_DIR}/compose.yml"
DOCKERFILE="${TMP_DIR}/Dockerfile"
HELLO_FILE="${TMP_DIR}/hello.txt"
SOCKET="${FERROCRATE_RUNTIME_DIR}/ferro.sock"

# 1) Pull + run + logs + exec + stop + rm
IMAGE_CANDIDATES=(
  "${FERROCRATE_E2E_IMAGE:-registry-1.docker.io/library/alpine:latest}"
  "registry-1.docker.io/library/busybox:latest"
  "registry.k8s.io/pause:3.9"
)

PULL_IMAGE=""
set +e
for candidate in "${IMAGE_CANDIDATES[@]}"; do
  "${BIN}" pull "${candidate}"
  if [[ $? -eq 0 ]]; then
    PULL_IMAGE="${candidate}"
    break
  fi
done
set -e

if [[ -z "${PULL_IMAGE}" ]]; then
  echo "Failed to pull any test image. Set FERROCRATE_E2E_IMAGE to a reachable registry image." >&2
  exit 1
fi

CID=$("${BIN}" run "${PULL_IMAGE}" sh -c "echo hello; sleep 1" | awk -F'container_id=' '{print $2}' | awk '{print $1}')
if [[ -z "${CID}" ]]; then
  echo "Failed to capture container id" >&2
  exit 1
fi
run "${BIN}" ps
LOGS=$("${BIN}" logs "${CID}")
if [[ "${LOGS}" != *"hello"* ]]; then
  echo "Expected logs to contain 'hello'" >&2
  exit 1
fi
run "${BIN}" exec "${CID}" echo hi
run "${BIN}" stop "${CID}"
run "${BIN}" rm "${CID}"

# 2) Build + run
cat > "${DOCKERFILE}" <<'DOCKER_EOF'
FROM scratch
COPY ./hello.txt /hello.txt
DOCKER_EOF

echo "hi" > "${HELLO_FILE}"
run "${BIN}" build "${DOCKERFILE}" --tag local/test:dev
OUT=$("${BIN}" run local/test:dev cat /hello.txt | awk -F'container_id=' '{print $2}' | awk '{print $1}')
if [[ -z "${OUT}" ]]; then
  echo "Failed to run built image" >&2
  exit 1
fi

# 3) Compose up/down
cat > "${COMPOSE_FILE}" <<COMPOSE_EOF
version: "3.8"
services:
  api:
    image: ${PULL_IMAGE}
    command: ["sh","-c","sleep 2"]
  web:
    image: ${PULL_IMAGE}
    depends_on:
      - api
    command: ["sh","-c","echo web && sleep 2"]
COMPOSE_EOF

run "${BIN}" compose -f "${COMPOSE_FILE}" up
run "${BIN}" compose -f "${COMPOSE_FILE}" down

# 4) Docker socket compatibility (basic)
"${BIN}" daemon --docker-compat --socket "${SOCKET}" &
DOCKER_COMPAT_PID=$!
# give it a moment
sleep 0.5
run curl --unix-socket "${SOCKET}" http://localhost/_ping
run curl --unix-socket "${SOCKET}" http://localhost/version
run curl --unix-socket "${SOCKET}" http://localhost/containers/json

# 5) Rootless bridge (optional)
if [[ "${FERROCRATE_ROOTLESS_NETNS:-}" == "1" ]]; then
  run "${BIN}" run alpine:latest sh -c "ip a; sleep 1"
fi

echo "E2E CLI checks passed."
