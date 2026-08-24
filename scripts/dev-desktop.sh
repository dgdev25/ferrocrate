#!/usr/bin/env bash
# Launch Ferrocrate Desktop for local development: dev license, PATH, daemon, UI.
set -eu
root="$(cd "$(dirname "$0")/.." && pwd)"
export FERROCRATE_ENTITLEMENT_PUBKEY="$(cat "$HOME/.ferrocrate/entitlement.pub")"
export PATH="$root/target/release:$root/target/debug:$PATH"
"$root/target/debug/ferro-desktop" daemon &
daemon_pid=$!
trap 'kill "$daemon_pid" 2>/dev/null || true' EXIT
sleep 1
"$root/apps/ferro-desktop-ui/src-tauri/target/debug/ferro-desktop-ui"
