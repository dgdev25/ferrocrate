#!/usr/bin/env bash
set -euo pipefail

artifact_dir="${1:-dist/release}"
deb="$(find "$artifact_dir" -maxdepth 1 -name 'ferrocrate_*_*.deb' -print -quit)"
appimage="$(find "$artifact_dir" -maxdepth 1 -name '*.AppImage' -print -quit)"
[[ -n "$deb" && -n "$appimage" ]] || { echo "Linux deb and AppImage are required" >&2; exit 1; }
sudo -n dpkg -i "$deb"
/usr/local/bin/ferrocrate --help >/dev/null
chmod +x "$appimage"
"$appimage" --appimage-extract-and-run --help >/dev/null
FERROCRATE_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)" \
  bash scripts/local-smoke-gate.sh
