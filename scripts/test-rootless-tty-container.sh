#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" == 0 ]]; then
  echo "rootless TTY fixture must run as a non-root user" >&2
  exit 77
fi
repo_root="$(cd "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cli="${FERROCRATE_NETWORK_CLI:-${repo_root}/target/release/ferro-cli}"
[[ -x "$cli" ]] || { echo "missing executable ferro-cli: $cli" >&2; exit 77; }
command -v curl >/dev/null || { echo "rootless TTY fixture requires curl" >&2; exit 77; }
command -v python3 >/dev/null || { echo "rootless TTY fixture requires python3" >&2; exit 77; }
command -v timeout >/dev/null || { echo "rootless TTY fixture requires timeout" >&2; exit 77; }

runtime_dir="${FERROCRATE_RUNTIME_DIR:-$(mktemp -d)}"
runtime_owned=0
if [[ -z "${FERROCRATE_RUNTIME_DIR:-}" ]]; then
  runtime_owned=1
else
  mkdir -p "$runtime_dir"
fi
socket="$runtime_dir/docker.sock"
daemon_pid=""
container_id=""
daemon_log="$runtime_dir/rootless-tty-daemon.log"
wait_seconds="${FERROCRATE_ROOTLESS_TTY_WAIT_SECONDS:-12}"
timeout_seconds="${FERROCRATE_ROOTLESS_TTY_TIMEOUT:-35}"
for value in "$wait_seconds" "$timeout_seconds"; do
  [[ "$value" =~ ^[1-9][0-9]*$ ]] || { echo "timeouts must be positive integers" >&2; exit 2; }
done

cleanup() {
  if [[ -n "$container_id" && -S "$socket" ]]; then
    curl --silent --show-error --max-time 3 --unix-socket "$socket" \
      -X DELETE "http://localhost/v1.45/containers/${container_id}?force=true" >/dev/null 2>&1 || true
  fi
  if [[ -n "$daemon_pid" ]]; then
    kill "$daemon_pid" >/dev/null 2>&1 || true
    wait "$daemon_pid" >/dev/null 2>&1 || true
  fi
  if [[ "$runtime_owned" == 1 ]]; then rm -rf -- "$runtime_dir"; fi
}
trap cleanup EXIT

export FERROCRATE_RUNTIME_DIR="$runtime_dir"
export FERROCRATE_ROOTLESS_NETNS=1
export FERROCRATE_NETWORK_BACKEND=iptables
timeout --foreground --signal=TERM --kill-after=5s "${timeout_seconds}s" \
  "$cli" pull busybox:1.36 >/dev/null 2>&1 || {
  echo "rootless TTY image pull failed" >&2
  exit 77
}
timeout --foreground --signal=TERM --kill-after=5s "${timeout_seconds}s" \
  "$cli" daemon --docker-compat --socket "$socket" >"$daemon_log" 2>&1 &
daemon_pid=$!
daemon_ready=0
for _ in $(seq 1 "$wait_seconds"); do
  if [[ -S "$socket" ]] && curl --silent --show-error --max-time 1 \
      --unix-socket "$socket" http://localhost/_ping | grep -qx OK; then
    daemon_ready=1
    break
  fi
  sleep 1
done
if [[ "$daemon_ready" != 1 ]]; then
  echo "rootless Docker-compatible daemon did not become ready" >&2
  curl --silent --show-error --max-time 2 --unix-socket "$socket" \
    http://localhost/_ping >&2 || true
  sed -n '1,80p' "$daemon_log" >&2 || true
  exit 77
fi

create_body='{"Image":"busybox:1.36","Cmd":["/bin/sh","-c","read line; printf rootless-tty-attach:$line; sleep 1"],"Tty":true,"HostConfig":{"NetworkMode":"none"}}'
create_response="$(curl --silent --show-error --max-time 5 --unix-socket "$socket" \
  -H 'Content-Type: application/json' -d "$create_body" -X POST \
  'http://localhost/v1.45/containers/create?name=rootless-tty')"
container_id="$(printf '%s' "$create_response" | sed -n 's/.*"Id":"\([^"]*\)".*/\1/p')"
if [[ -z "$container_id" ]]; then
  printf '%s\n' "$create_response" >&2
  if grep -Eqi 'unsupported|unavailable|not permitted|SO_PEERPIDFD' <<<"$create_response"; then exit 77; fi
  exit 1
fi
container_ref="rootless-tty"
start_response="$(curl --silent --show-error --max-time 5 --unix-socket "$socket" \
  -X POST -w $'\n%{http_code}' "http://localhost/v1.45/containers/$container_ref/start")"
start_status="${start_response##*$'\n'}"
if [[ "$start_status" != 2* ]]; then
  printf '%s\n' "${start_response%$'\n'*}" >&2
  sed -n '1,80p' "$daemon_log" >&2 || true
  exit 1
fi
inspect="$(curl --silent --show-error --fail --max-time 5 --unix-socket "$socket" \
  "http://localhost/v1.45/containers/$container_ref/json")"
grep -q '"Tty":true' <<<"$inspect" || { echo "inspect did not preserve Tty=true" >&2; exit 1; }
client_result="$runtime_dir/rootless-tty-attach-result"
timeout --foreground --signal=TERM --kill-after=5s "${timeout_seconds}s" \
  python3 - "$socket" "$client_result" <<'PY' &
import pathlib
import socket
import sys
import time

socket_path = sys.argv[1]
result_path = pathlib.Path(sys.argv[2])
deadline = time.monotonic() + 10
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.settimeout(1)
try:
    sock.connect(socket_path)
    request = (
        "POST /v1.45/containers/rootless-tty/attach?logs=0&stream=1&stdin=1&stdout=1&stderr=1 "
        "HTTP/1.1\r\nHost: docker\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n"
        "Content-Length: 0\r\n\r\n"
    ).encode("ascii")
    sock.sendall(request)
    headers = bytearray()
    while b"\r\n\r\n" not in headers:
        if time.monotonic() >= deadline:
            raise RuntimeError("attach headers timed out")
        headers.extend(sock.recv(1))
        if len(headers) > 4096:
            raise RuntimeError("attach headers exceeded bound")
    if not headers.startswith(b"HTTP/1.1 101"):
        raise RuntimeError(f"unexpected attach response: {headers!r}")
    sock.sendall(b"rootless\n")
    payload = bytearray()
    while b"rootless-tty-attach:rootless" not in payload:
        if time.monotonic() >= deadline:
            raise RuntimeError(f"attach payload timed out: {payload!r}")
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            continue
        if not chunk:
            raise RuntimeError(f"attach closed before sentinel: {payload!r}")
        payload.extend(chunk)
        if len(payload) > 1024 * 1024:
            raise RuntimeError("attach payload exceeded bound")
    result_path.write_text("pass\n", encoding="ascii")
except Exception as error:
    result_path.write_text(f"failure: {error}\n", encoding="utf-8")
    raise
finally:
    sock.close()
PY
attach_pid=$!
sleep 1
resize_status="$(curl --silent --show-error --max-time 3 --unix-socket "$socket" \
  -X POST -w $'\n%{http_code}' "http://localhost/v1.45/containers/$container_ref/resize?w=100&h=40")"
[[ "${resize_status##*$'\n'}" == "200" ]] || {
  printf '%s\n' "$resize_status" >&2
  kill "$attach_pid" >/dev/null 2>&1 || true
  wait "$attach_pid" >/dev/null 2>&1 || true
  exit 1
}
if ! wait "$attach_pid"; then
  sed -n '1,20p' "$client_result" >&2 || true
  exit 1
fi
grep -qx 'pass' "$client_result" || { echo "rootless PTY attach did not pass" >&2; exit 1; }
body_file="$runtime_dir/rootless-tty-body"
output_ready=0
for _ in $(seq 1 "$wait_seconds"); do
  if curl --silent --show-error --fail --max-time 2 --unix-socket "$socket" \
      "http://localhost/v1.45/containers/$container_ref/logs?stdout=1&stderr=1" -o "$body_file" \
      && grep -q rootless-tty-attach:rootless "$body_file"; then
    output_ready=1
    break
  fi
  sleep 1
done
[[ "$output_ready" == 1 ]] || { echo "rootless PTY output did not drain" >&2; exit 1; }
echo "rootless TTY container qualification passed: id=$container_id (attach/resize/raw stream)"
