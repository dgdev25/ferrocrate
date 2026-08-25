#!/usr/bin/env bash
set -euo pipefail

artifact_dir="${1:-apps/ferro-desktop-ui/src-tauri/target/release/bundle}"
msi="$(find "$artifact_dir" -name '*.msi' -print -quit)"
nsis="$(find "$artifact_dir" -name '*setup.exe' -print -quit)"
[[ -n "$msi" && -n "$nsis" ]] || { echo "Windows MSI and NSIS artifacts are required" >&2; exit 1; }
powershell.exe -NoProfile -NonInteractive -Command \
  "Start-Process msiexec.exe -ArgumentList '/i', '$msi', '/qn', '/norestart' -Wait"
ferrocrate.exe --help >/dev/null
bash scripts/local-smoke-gate.sh
