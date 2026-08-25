#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
deb="${1:-}"
[[ -f "$deb" ]] || { echo "usage: inject-deb-maintainer-scripts.sh PACKAGE.deb" >&2; exit 2; }
command -v dpkg-deb >/dev/null 2>&1 || { echo "dpkg-deb is required" >&2; exit 1; }
absolute="$(realpath "$deb")"
stage="$(mktemp -d /tmp/ferrocrate-tauri-deb.XXXXXX)"
trap 'rm -rf "$stage"' EXIT
dpkg-deb -R "$absolute" "$stage"
install -m 0755 "$repo_root/packaging/debian/postinst" "$stage/DEBIAN/postinst"
find "$stage" -exec touch -h -d "@${SOURCE_DATE_EPOCH:-0}" {} +
dpkg-deb --build --root-owner-group "$stage" "${absolute}.new" >/dev/null
mv "${absolute}.new" "$absolute"
echo "injected Debian maintainer scripts: $absolute"
