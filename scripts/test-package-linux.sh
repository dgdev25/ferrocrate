#!/usr/bin/env bash
set -euo pipefail

artifact_dir="${1:-dist/release}"
deb="$(find "$artifact_dir" -name '*.deb' -print -quit)"
appimage="$(find "$artifact_dir" -name '*.AppImage' -print -quit)"
[[ -n "$deb" && -n "$appimage" ]] || { echo "Linux deb and AppImage are required" >&2; exit 1; }
sudo -n dpkg -i "$deb"
/usr/local/bin/ferrocrate --help >/dev/null
chmod +x "$appimage"
extract="$(mktemp -d /tmp/ferrocrate-appimage-test.XXXXXX)"
trap 'rm -rf "$extract"' EXIT
(cd "$extract" && "$appimage" --appimage-extract >/dev/null)
test -x "$extract/squashfs-root/usr/bin/ferrocrate"
FERROCRATE_BIN=/usr/bin/ferrocrate \
  FERROCRATE_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)" \
  bash scripts/local-smoke-gate.sh
FERROCRATE_BIN="$extract/squashfs-root/usr/bin/ferrocrate" \
  FERROCRATE_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)" \
  bash scripts/local-smoke-gate.sh
