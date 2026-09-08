#!/usr/bin/env bash
# Test the actual platform credential store on a private bus and data directory.
set -euo pipefail
if [[ "${FERROCRATE_PRIVATE_KEYRING_TEST:-}" != 1 ]]; then
  fixture_dir=$(mktemp -d /tmp/ferrocrate-keyring-proof.XXXXXX)
  trap 'rm -rf "$fixture_dir"' EXIT
  mkdir -m 700 "$fixture_dir/data" "$fixture_dir/control"
  dbus-run-session -- env FERROCRATE_PRIVATE_KEYRING_TEST=1 \
    XDG_DATA_HOME="$fixture_dir/data" GNOME_KEYRING_CONTROL="$fixture_dir/control" \
    bash "$0" "$@"
  exit
fi

# This public fixture passphrase belongs only to the disposable collection.
printf '%s' 'ferrocrate-disposable-keyring-proof' | \
  gnome-keyring-daemon --unlock --foreground --components=secrets \
    --control-directory="$GNOME_KEYRING_CONTROL" &
keyring_pid=$!
trap 'kill "$keyring_pid" 2>/dev/null || true; wait "$keyring_pid" 2>/dev/null || true' EXIT
keyring_ready=0
for attempt in {1..50}; do
  kill -0 "$keyring_pid" 2>/dev/null || { echo 'Fixture keyring exited before becoming ready' >&2; exit 1; }
  if timeout 1s gdbus call --session --dest org.freedesktop.DBus --object-path /org/freedesktop/DBus \
    --method org.freedesktop.DBus.NameHasOwner org.freedesktop.secrets | rg -q true; then
    keyring_ready=1
    break
  fi
  sleep 0.1
done
[[ "$keyring_ready" == 1 ]] || { echo 'Fixture private keyring did not become ready' >&2; exit 1; }
cargo test --manifest-path apps/ferro-desktop-ui/src-tauri/Cargo.toml \
  --test credential_persistence --offline -- --include-ignored
