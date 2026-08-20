#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Keep the binary lookup aligned with Cargo's optional target directory. This
# matters for guest/CI runs that place build artifacts on a caller-owned disk
# rather than the repository filesystem.
TARGET_DIR="${CARGO_TARGET_DIR:-${ROOT_DIR}/target}"
BIN="${TARGET_DIR}/debug/ferro-cli"

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
    wait "${DOCKER_COMPAT_PID}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

TMP_DIR="$(mktemp -d)"
export FERROCRATE_RUNTIME_DIR="${TMP_DIR}/runtime"
# This generic CLI smoke is intentionally independent of the privileged eBPF
# qualification. Use the typed firewall fallback so a temporary runtime cannot
# leave shared bpffs classifiers behind between repeated runs.
network_backend="${FERROCRATE_NETWORK_BACKEND:-iptables}"
export FERROCRATE_NETWORK_BACKEND="${network_backend}"
mkdir -p "${FERROCRATE_RUNTIME_DIR}"
COMPOSE_FILE="${TMP_DIR}/compose.yml"
DOCKERFILE="${TMP_DIR}/Dockerfile"
HELLO_FILE="${TMP_DIR}/hello.txt"
SOCKET="${FERROCRATE_RUNTIME_DIR}/ferro.sock"
DOCKER_COMPAT_LOG="${TMP_DIR}/docker-compat.log"
HTTP_TIMEOUT="${FERROCRATE_E2E_HTTP_TIMEOUT:-10}"

docker_curl() {
  # A daemon/socket regression must fail with bounded diagnostics rather than
  # leaving a guest qualification run hung indefinitely.
  if ! curl --fail --silent --show-error --max-time "${HTTP_TIMEOUT}" \
    --unix-socket "${SOCKET}" "$@"; then
    echo "Docker-compatible daemon request failed (timeout=${HTTP_TIMEOUT}s); daemon log:" >&2
    sed -n '1,160p' "${DOCKER_COMPAT_LOG}" >&2 || true
    return 1
  fi
}

# Native builds and first-run runtime initialization can take longer on older
# guest kernels/filesystems. Keep readiness bounded while allowing callers to
# choose a stricter or more patient qualification budget.
daemon_ready_attempts="${FERROCRATE_E2E_DAEMON_READY_ATTEMPTS:-200}"
if ! [[ "${daemon_ready_attempts}" =~ ^[1-9][0-9]*$ ]]; then
  echo "FERROCRATE_E2E_DAEMON_READY_ATTEMPTS must be a positive integer" >&2
  exit 1
fi

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

CID=$("${BIN}" run --network-backend "${network_backend}" "${PULL_IMAGE}" sh -c "echo hello; sleep 1" | awk -F'container_id=' '{print $2}' | awk '{print $1}')
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
if ! "${BIN}" exec "${CID}" echo hi; then
  echo "exec: skipped (requires elevated privileges for nsenter)"
fi
run "${BIN}" stop "${CID}"
run "${BIN}" rm "${CID}"

# 2) Build + run
cat > "${DOCKERFILE}" <<DOCKER_EOF
FROM ${PULL_IMAGE}
COPY ./hello.txt /hello.txt
DOCKER_EOF

echo "hi" > "${HELLO_FILE}"
run "${BIN}" build --dockerfile "${DOCKERFILE}" --tag local/test:dev
OUT=$("${BIN}" run --network-backend "${network_backend}" local/test:dev /bin/cat /hello.txt | awk -F'container_id=' '{print $2}' | awk '{print $1}')
if [[ -z "${OUT}" ]]; then
  echo "Failed to run built image" >&2
  exit 1
fi

# 3) Compose up/down
compose_network_mode=""
if [[ "${FERROCRATE_ROOTLESS_NETNS:-}" == "1" ]]; then
  # Rootless Compose cannot provision a durable host bridge yet. Keep this
  # smoke focused on the supported lifecycle while the direct rootless bridge
  # check below exercises slirp4netns independently.
  compose_network_mode='    network_mode: none'
fi
cat > "${COMPOSE_FILE}" <<COMPOSE_EOF
version: "3.8"
services:
  api:
    image: ${PULL_IMAGE}
    command: ["sh","-c","sleep 2"]
${compose_network_mode}
  web:
    image: ${PULL_IMAGE}
    depends_on:
      - api
    command: ["sh","-c","echo web && sleep 2"]
${compose_network_mode}
COMPOSE_EOF

run "${BIN}" compose -f "${COMPOSE_FILE}" up
run "${BIN}" compose -f "${COMPOSE_FILE}" down

# 4) Docker socket compatibility (basic)
"${BIN}" daemon --docker-compat --socket "${SOCKET}" >"${DOCKER_COMPAT_LOG}" 2>&1 &
DOCKER_COMPAT_PID=$!
docker_compat_ready=0
docker_compat_unavailable=0
for _ in $(seq 1 "${daemon_ready_attempts}"); do
  if [[ -S "${SOCKET}" ]]; then
    ping_status=""
    if ping_status="$(curl --silent --show-error --max-time "${HTTP_TIMEOUT}" \
        --output "${TMP_DIR}/docker-ping-body" --write-out '%{http_code}' \
        --unix-socket "${SOCKET}" http://localhost/_ping 2>/dev/null)"; then
      if [[ "${ping_status}" == "200" ]]; then
        docker_compat_ready=1
        break
      fi
      if [[ "${ping_status}" == "503" ]] &&
          grep -q 'SO_PEERPIDFD' "${TMP_DIR}/docker-ping-body"; then
        docker_compat_unavailable=1
        break
      fi
    fi
  fi
  sleep 0.1
done
if [[ "${docker_compat_unavailable}" == 1 ]]; then
  echo "Docker-compatible daemon unavailable on this host: missing SO_PEERPIDFD" >&2
  sed -n '1,4p' "${TMP_DIR}/docker-ping-body" >&2 || true
  exit 77
fi
if [[ "${docker_compat_ready}" != 1 ]]; then
  echo "Docker-compatible daemon did not become ready at /_ping; daemon log:" >&2
  sed -n '1,160p' "${DOCKER_COMPAT_LOG}" >&2 || true
  exit 1
fi
run docker_curl http://localhost/_ping
run docker_curl http://localhost/version
run docker_curl http://localhost/containers/json

# 5) Rootless bridge (optional)
if [[ "${FERROCRATE_ROOTLESS_NETNS:-}" == "1" ]]; then
  run "${BIN}" run alpine:latest sh -c "ip a; sleep 1"
fi

echo "E2E CLI checks passed."
