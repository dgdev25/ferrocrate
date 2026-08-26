#!/usr/bin/env bash
set -euo pipefail

artifact_dir="${1:-apps/ferro-desktop-ui/src-tauri/target/release/bundle}"
msi="$(find "$artifact_dir" -name '*.msi' -print -quit)"
nsis="$(find "$artifact_dir" -name '*setup.exe' -print -quit)"
[[ -n "$msi" && -n "$nsis" ]] || { echo "Windows MSI and NSIS artifacts are required" >&2; exit 1; }
powershell.exe -NoProfile -NonInteractive -Command \
  "Start-Process msiexec.exe -ArgumentList '/i', '$msi', '/qn', '/norestart' -Wait"
desktop_bin="$(find '/c/Program Files' -name 'ferro-desktop-sidecar.exe' -print -quit)"
cli_bin="$(find '/c/Program Files' -name 'ferrocrate.exe' -print -quit)"
FERROCRATE_SMOKE_PLATFORM=desktop FERROCRATE_DESKTOP_BIN="$desktop_bin" FERROCRATE_BIN="$cli_bin" \
  bash scripts/local-smoke-gate.sh
