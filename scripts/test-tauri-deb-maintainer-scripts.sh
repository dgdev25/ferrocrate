#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d /tmp/ferrocrate-tauri-deb-test.XXXXXX)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/pkg/DEBIAN" "$tmp/pkg/usr/bin"
printf 'Package: ferrocrate-desktop\nVersion: 0.1.0\nArchitecture: amd64\nMaintainer: test\nDescription: test\n' >"$tmp/pkg/DEBIAN/control"
printf '#!/bin/sh\n' >"$tmp/pkg/usr/bin/ferrocrate"
chmod 0755 "$tmp/pkg/usr/bin/ferrocrate"
dpkg-deb --build --root-owner-group "$tmp/pkg" "$tmp/test.deb" >/dev/null
bash "$repo_root/scripts/inject-deb-maintainer-scripts.sh" "$tmp/test.deb"
mkdir "$tmp/control"
dpkg-deb -e "$tmp/test.deb" "$tmp/control"
cmp "$repo_root/packaging/debian/postinst" "$tmp/control/postinst"
echo "Tauri Debian maintainer-script regression passed"
