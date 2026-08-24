#!/usr/bin/env bash
# One-command Ferrocrate Desktop dev launcher: builds what is missing, provisions a
# self-signed dev license (off the default path), starts the daemon, opens the app.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
ui="$root/apps/ferro-desktop-ui"
lic_dir="$HOME/.ferrocrate/dev"
mode="${1:-native}"
if [[ "$mode" != "native" && "$mode" != "--web" ]]; then
  echo "usage: $0 [--web]" >&2
  exit 2
fi
export FERROCRATE_RUNTIME_DIR="${FERROCRATE_RUNTIME_DIR:-${XDG_RUNTIME_DIR:-$root/target/desktop-runtime}}"
mkdir -p "$FERROCRATE_RUNTIME_DIR"

say() { printf '\033[1;33m[dev-desktop]\033[0m %s\n' "$*"; }

# 1. dev license (never at the default ~/.ferrocrate/entitlement.lic — it breaks tests)
if [[ ! -f "$lic_dir/entitlement.lic" || ! -f "$lic_dir/entitlement.pub" ]]; then
  say "generating self-signed dev license in $lic_dir"
  mkdir -p "$lic_dir"
  python3 - "$lic_dir" <<'PY'
import json, base64, time, sys, os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
d = sys.argv[1]
sk = Ed25519PrivateKey.generate()
payload = json.dumps({"plan": "pro", "subject": "dev", "issued_at": int(time.time()),
                      "expires_at": int(time.time()) + 365*86400, "features": ["desktop"]}).encode()
sig = sk.sign(payload)
pub = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
open(os.path.join(d, "entitlement.lic"), "w").write(json.dumps({
    "payload": base64.standard_b64encode(payload).decode(),
    "signature": base64.standard_b64encode(sig).decode()}))
open(os.path.join(d, "entitlement.pub"), "w").write(base64.standard_b64encode(pub).decode())
PY
fi
export FERROCRATE_ENTITLEMENT_FILE="$lic_dir/entitlement.lic"
export FERROCRATE_ENTITLEMENT_PUBKEY="$(cat "$lic_dir/entitlement.pub")"

# 2. binaries (cargo is incremental; these are no-ops when up to date)
say "building daemon and runtime"
cargo build -q -p ferro-desktop
cargo build -q --release -p ferro-cli
ln -sf ferro-cli "$root/target/release/ferrocrate"

# 3. frontend + tauri shell
say "building UI"
( cd "$ui" && { [[ -d node_modules ]] || npm install --silent; } && npm run build --silent )
( cd "$ui/src-tauri" && cargo build -q )

# 4. run (the native Tauri shell owns its helper; web mode owns the same helper here)
export PATH="$root/target/release:$root/target/debug:$PATH"
if [[ "$mode" == "--web" ]]; then
  say "starting desktop supervisor (Ferrocrate socket: $FERROCRATE_RUNTIME_DIR/ferrocrate.sock)"
  "$root/target/debug/ferro-desktop" daemon &
  daemon_pid=$!
  trap 'kill "$daemon_pid" 2>/dev/null || true; wait "$daemon_pid" 2>/dev/null || true' EXIT
  daemon_ready=false
  for _ in $(seq 1 120); do
    if curl -fsS --unix-socket "$FERROCRATE_RUNTIME_DIR/ferrocrate.sock" http://d/_ping >/dev/null 2>&1; then
      daemon_ready=true
      break
    fi
    if ! kill -0 "$daemon_pid" 2>/dev/null; then
      wait "$daemon_pid" || true
      say "desktop supervisor exited before the Ferrocrate socket became ready"
      exit 1
    fi
    sleep 0.1
  done
  if [[ "$daemon_ready" != true ]]; then
    say "desktop supervisor did not make the Ferrocrate socket ready"
    exit 1
  fi
  say "launching Ferrocrate Desktop web UI"
  "$ui/src-tauri/target/debug/ferro-desktop-ui" --web --listen 127.0.0.1:4190
else
  say "launching Ferrocrate Desktop (Ferrocrate socket: $FERROCRATE_RUNTIME_DIR/ferrocrate.sock)"
  exec "$ui/src-tauri/target/debug/ferro-desktop-ui"
fi
