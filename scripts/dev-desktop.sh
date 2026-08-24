#!/usr/bin/env bash
# One-command Ferrocrate Desktop dev launcher: builds what is missing, provisions a
# self-signed dev license (off the default path), starts the daemon, opens the app.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
ui="$root/apps/ferro-desktop-ui"
lic_dir="$HOME/.ferrocrate/dev"
web=false

case "${1:-}" in
  "") ;;
  --web) web=true ;;
  *)
    echo "usage: $0 [--web]" >&2
    exit 2
    ;;
esac

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

# 4. run
export PATH="$root/target/release:$root/target/debug:$PATH"
say "starting daemon"
"$root/target/debug/ferro-desktop" daemon &
daemon_pid=$!
trap 'kill "$daemon_pid" 2>/dev/null || true' EXIT
sleep 1
if [[ "$web" == true ]]; then
  url="http://127.0.0.1:4190"
  say "web bridge ready at $url"
  "$ui/src-tauri/target/debug/ferro-desktop-ui" --web --listen 127.0.0.1:4190
else
  say "launching Ferrocrate Desktop"
  exec "$ui/src-tauri/target/debug/ferro-desktop-ui"
fi
