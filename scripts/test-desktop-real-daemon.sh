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
export HOME="$test_root/home"
export FERROCRATE_HOME="$HOME/.ferrocrate"
export FERROCRATE_IMAGE_STORE="$test_root/image-store"
mkdir -p "$HOME" "$FERROCRATE_IMAGE_STORE"
# Keep this real daemon/socket integration runnable without CAP_NET_ADMIN. This
# selects Ferrocrate's process-persistent test kernel adapter; HTTP routing,
# durable network lifecycle state, and every desktop proxy remain production
# code paths (there is no mocked server or mocked Tauri invocation).
export FERROCRATE_NETWORK_KERNEL_STATE="$test_root/network-kernel-state.json"
export FERROCRATE_BIN="${FERROCRATE_BIN:-$root/target/release/ferro-cli}"
desktop_bin="${FERRO_DESKTOP_BIN:-$root/target/debug/ferro-desktop}"
# Desktop proxy commands are entitlement-gated. Keep this integration test
# self-contained and scoped to its disposable root rather than borrowing a
# developer's paid entitlement.
if [[ -z "${FERROCRATE_ENTITLEMENT_FILE:-}" && -z "${FERROCRATE_ENTITLEMENT_PUBKEY:-}" ]]; then
  entitlement_dir="$test_root/entitlement"
  mkdir -p "$entitlement_dir"
  python3 - "$entitlement_dir" <<'PY'
import base64, json, os, sys, time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

directory = sys.argv[1]
key = Ed25519PrivateKey.generate()
payload = json.dumps({
    "plan": "pro",
    "subject": "desktop-real-daemon-test",
    "issued_at": int(time.time()),
    "expires_at": int(time.time()) + 3600,
    "features": ["desktop"],
}).encode()
envelope = json.dumps({
    "payload": base64.standard_b64encode(payload).decode(),
    "signature": base64.standard_b64encode(key.sign(payload)).decode(),
})
public_key = base64.standard_b64encode(key.public_key().public_bytes(
    serialization.Encoding.Raw,
    serialization.PublicFormat.Raw,
)).decode()
open(os.path.join(directory, "entitlement.lic"), "w").write(envelope)
open(os.path.join(directory, "entitlement.pub"), "w").write(public_key)
PY
  export FERROCRATE_ENTITLEMENT_FILE="$entitlement_dir/entitlement.lic"
  export FERROCRATE_ENTITLEMENT_PUBKEY="$(<"$entitlement_dir/entitlement.pub")"
fi
backend="${FERROCRATE_DESKTOP_BACKEND:-linux-native}"
case "$backend" in
  linux-native|wsl2|macos-vm) ;;
  *) echo "unsupported desktop backend row: $backend" >&2; exit 2 ;;
esac
host_os="$(uname -s)"
case "$host_os" in
  Linux) host_backend="linux-native" ;;
  Darwin) host_backend="macos-vm" ;;
  MINGW*|MSYS*|CYGWIN*) host_backend="wsl2" ;;
  *) host_backend="unavailable" ;;
esac
case "$backend" in
  linux-native) required_host="Linux" ;;
  wsl2) required_host="Windows" ;;
  macos-vm) required_host="macOS" ;;
esac
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

print_backend_rows() {
  local selected_result="$1" selected_endpoint="$2"
  printf 'backend\tresult\tendpoint\n'
  for row in linux-native wsl2 macos-vm; do
    if [[ "$row" == "$backend" ]]; then
      printf '%s\t%s\t%s\n' "$row" "$selected_result" "$selected_endpoint"
    else
      case "$row" in
        linux-native) printf '%s\tSKIP\trequires Linux host\n' "$row" ;;
        wsl2) printf '%s\tSKIP\trequires Windows host\n' "$row" ;;
        macos-vm) printf '%s\tSKIP\trequires macOS host\n' "$row" ;;
      esac
    fi
  done
}

if [[ "$backend" != "$host_backend" ]]; then
  print_backend_rows "SKIP" "requires $required_host host"
  printf 'selected backend %s does not match host backend %s; skipped without relabelling this host execution\n' "$backend" "$host_backend"
  exit 0
fi

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
curl -fsS --unix-socket "$socket" "http://localhost/containers/$container_id/stats?stream=false" | jq -e 'type == "object"' >/dev/null
print_backend_rows "PASS" "$socket"
printf 'desktop real-daemon paths passed via %s backend=%s\n' "$socket" "$backend"
