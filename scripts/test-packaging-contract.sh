#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

grep -Fq '"targets": ["appimage", "deb", "dmg", "nsis", "msi"]' "$repo_root/apps/ferro-desktop-ui/src-tauri/tauri.conf.json"
grep -Fq '"externalBin": ["binaries/ferrocrate", "binaries/ferro-desktop"]' "$repo_root/apps/ferro-desktop-ui/src-tauri/tauri.conf.json"
grep -Fq 'tauri-plugin-updater' "$repo_root/apps/ferro-desktop-ui/src-tauri/Cargo.toml"
grep -Fq 'build-deb-package.sh' "$repo_root/scripts/build-release-artifacts.sh"
grep -Fq 'archive="ferrocrate-${version}-linux-${arch}${archive_suffix}.tar.gz"' "$repo_root/scripts/install.sh"
! grep -Fq 'ferrocrate-${version}-${arch}.AppImage' "$repo_root/scripts/install.sh"
test -x "$repo_root/scripts/bundle-sidecars.sh"
grep -Fq 'FERROCRATE NON-BUNDLE SIDECAR PLACEHOLDER' \
  "$repo_root/apps/ferro-desktop-ui/src-tauri/build.rs"
grep -Fq 'validate-bundled-sidecars.mjs' \
  "$repo_root/apps/ferro-desktop-ui/src-tauri/tauri.conf.json"
windows_icon="$repo_root/apps/ferro-desktop-ui/src-tauri/icons/icon.ico"
grep -Fq '"icons/icon.ico"' \
  "$repo_root/apps/ferro-desktop-ui/src-tauri/tauri.conf.json"
test -s "$windows_icon"
test "$(od -An -tx1 -N4 "$windows_icon" | tr -d '[:space:]')" = "00000100"
grep -Fq 'scripts/bundle-sidecars.sh' "$repo_root/scripts/dev-desktop.sh"
test -f "$repo_root/scripts/validate-bundled-sidecars.mjs"
test -x "$repo_root/scripts/fix-appimage.sh"
test -x "$repo_root/scripts/build-updater-manifest.mjs"
for os in linux macos windows; do
  test -x "$repo_root/scripts/test-package-${os}.sh"
done

echo "packaging contract passed"
