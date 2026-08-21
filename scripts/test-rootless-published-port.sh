#!/usr/bin/env bash
set -euo pipefail

# Bounded, non-root qualification for slirp4netns host-port forwarding.
#
# This intentionally uses a dedicated runtime directory and an unprivileged
# host port. It never invokes sudo, starts a daemon, or leaves a workload
# behind when a readiness probe fails.

if [[ "$(id -u)" == "0" ]]; then
  echo "rootless published-port fixture must run as a non-root user" >&2
  exit 77
fi

repo_root="$(cd "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -n "${FERROCRATE_NETWORK_CLI:-}" ]]; then
  cli="${FERROCRATE_NETWORK_CLI}"
elif command -v ferro-cli >/dev/null 2>&1; then
  cli="$(command -v ferro-cli)"
else
  target_dir="${CARGO_TARGET_DIR:-${repo_root}/target}"
  cli="${target_dir}/debug/ferro-cli"
fi
if [[ ! -x "${cli}" ]]; then
  echo "rootless published-port fixture requires an executable ferro-cli: ${cli}" >&2
  exit 77
fi
command -v curl >/dev/null 2>&1 || {
  echo "rootless published-port fixture requires curl" >&2
  exit 77
}

host_port="${FERROCRATE_ROOTLESS_PUBLISH_PORT:-18090}"
wait_seconds="${FERROCRATE_ROOTLESS_PUBLISH_WAIT_SECONDS:-15}"
timeout_seconds="${FERROCRATE_ROOTLESS_PUBLISH_TIMEOUT:-30}"
for value in "${host_port}" "${wait_seconds}" "${timeout_seconds}"; do
  [[ "${value}" =~ ^[1-9][0-9]*$ ]] || {
    echo "port and timeout values must be positive integers" >&2
    exit 2
  }
done
(( host_port <= 65535 )) || { echo "invalid host port: ${host_port}" >&2; exit 2; }

runtime_dir="${FERROCRATE_RUNTIME_DIR:-$(mktemp -d)}"
runtime_owned=0
if [[ -z "${FERROCRATE_RUNTIME_DIR:-}" ]]; then
  runtime_owned=1
else
  mkdir -p "${runtime_dir}"
fi
container_id=""
cleanup() {
  if [[ -n "${container_id}" ]]; then
    timeout --foreground --signal=TERM --kill-after=5s 10s \
      env FERROCRATE_RUNTIME_DIR="${runtime_dir}" "${cli}" stop "${container_id}" >/dev/null 2>&1 || true
    timeout --foreground --signal=TERM --kill-after=5s 10s \
      env FERROCRATE_RUNTIME_DIR="${runtime_dir}" "${cli}" rm "${container_id}" >/dev/null 2>&1 || true
  fi
  if [[ "${runtime_owned}" == 1 ]]; then
    rm -rf -- "${runtime_dir}"
  fi
}
trap cleanup EXIT

# Avoid mistaking an unrelated service for Ferrocrate's forwarding socket.
if command -v ss >/dev/null 2>&1 && ss -H -ltn 2>/dev/null | awk -v p=":${host_port}" '$4 ~ p"$" {found=1} END {exit found ? 0 : 1}'; then
  echo "host port ${host_port} is already in use" >&2
  exit 77
fi

export FERROCRATE_RUNTIME_DIR="${runtime_dir}"
export FERROCRATE_ROOTLESS_NETNS=1
export FERROCRATE_NETWORK_BACKEND=iptables

echo "pull: busybox:1.36"
timeout --foreground --signal=TERM --kill-after=5s "${timeout_seconds}s" \
  "${cli}" pull busybox:1.36 >/dev/null

run_output="$(timeout --foreground --signal=TERM --kill-after=5s "${timeout_seconds}s" "${cli}" run \
  --name "ferro-rootless-publish-${host_port}" \
  --network bridge --network-backend iptables \
  --publish "${host_port}:8080/tcp" busybox:1.36 \
  sh -c 'mkdir -p /www; printf ferro-rootless-published-ok\\n >/www/index.html; httpd -f -p 8080 -h /www' 2>&1)" || {
  printf '%s\n' "${run_output}" >&2
  if grep -Eqi 'rootless bridge networking is unavailable|unshare: .*not permitted|user namespace.*unavailable' <<<"${run_output}"; then
    echo "rootless published-port prerequisites are unavailable on this host" >&2
    exit 77
  fi
  echo "rootless published-port workload failed to start" >&2
  exit 1
}
printf '%s\n' "${run_output}"
container_id="$(printf '%s\n' "${run_output}" | sed -n 's/.*container_id=\([^ ]*\).*/\1/p' | tail -1)"
if [[ -z "${container_id}" ]]; then
  echo "could not determine container id from ferro-cli output" >&2
  exit 1
fi

body_file="${runtime_dir}/rootless-published-body"
ready=0
for _ in $(seq 1 "${wait_seconds}"); do
  if curl --fail --silent --show-error --max-time 1 \
      "http://127.0.0.1:${host_port}/" -o "${body_file}"; then
    ready=1
    break
  fi
  sleep 1
done
if [[ "${ready}" != 1 ]]; then
  echo "rootless host-port listener did not become ready within ${wait_seconds}s" >&2
  "${cli}" logs "${container_id}" >&2 || true
  exit 1
fi
grep -Fxq 'ferro-rootless-published-ok' "${body_file}" || {
  echo "unexpected rootless published-port response:" >&2
  cat "${body_file}" >&2
  exit 1
}

echo "rootless published-port qualification passed: host=${host_port} container=8080 id=${container_id}"
