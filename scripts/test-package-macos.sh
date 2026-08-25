#!/usr/bin/env bash
set -euo pipefail

artifact_dir="${1:-apps/ferro-desktop-ui/src-tauri/target/release/bundle/dmg}"
dmg="$(find "$artifact_dir" -maxdepth 1 -name '*.dmg' -print -quit)"
[[ -n "$dmg" ]] || { echo "macOS DMG is required" >&2; exit 1; }
mount="$(mktemp -d /tmp/ferrocrate-dmg.XXXXXX)"
trap 'hdiutil detach "$mount" -quiet 2>/dev/null || true; rm -rf "$mount"' EXIT
hdiutil attach "$dmg" -mountpoint "$mount" -nobrowse -quiet
app="$(find "$mount" -maxdepth 1 -name '*.app' -print -quit)"
[[ -n "$app" ]] || { echo "DMG contains no app" >&2; exit 1; }
codesign --verify --deep --strict "$app"
"$app/Contents/MacOS/ferro-desktop-ui" --help >/dev/null
FERROCRATE_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)" \
  bash scripts/local-smoke-gate.sh
