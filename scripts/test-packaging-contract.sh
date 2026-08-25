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
test -x "$repo_root/scripts/fix-appimage.sh"
test -x "$repo_root/scripts/build-updater-manifest.mjs"
for os in linux macos windows; do
  test -x "$repo_root/scripts/test-package-${os}.sh"
done

echo "packaging contract passed"
