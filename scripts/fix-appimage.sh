#!/usr/bin/env bash
# Adapted from block/buzz (Apache-2.0), desktop/scripts/fix-appimage.sh.
# Workaround for Tauri issue #15665 on Mesa 25 / GLib 2.88 hosts.
set -euo pipefail

appimage="${1:-}"
[[ -f "$appimage" ]] || { echo "usage: fix-appimage.sh PATH.AppImage" >&2; exit 2; }
command -v appimagetool >/dev/null 2>&1 || {
  echo "fix-appimage: appimagetool is required" >&2
  exit 1
}
absolute="$(realpath "$appimage")"
work="$(mktemp -d /tmp/ferrocrate-appimage.XXXXXX)"
trap 'rm -rf "$work"' EXIT
(
  cd "$work"
  "$absolute" --appimage-extract >/dev/null
)
appdir="$work/squashfs-root"

# Force modern hosts to provide their mutually-compatible Wayland/GStreamer stack.
find "$appdir/usr/lib" -type f \( \
  -name 'libwayland-*.so*' -o -name 'libgst*.so*' -o -name 'libgstreamer*.so*' \
\) -delete 2>/dev/null || true

real_binary="$(find "$appdir/usr/bin" -maxdepth 1 -type f -perm -111 -name 'ferro-desktop-ui*' -print -quit)"
[[ -n "$real_binary" ]] || { echo "fix-appimage: desktop binary not found" >&2; exit 1; }
mv "$real_binary" "${real_binary}.real"
launcher="$(basename "$real_binary")"
apply_patch_placeholder=0
sed -e "s|@BINARY@|$launcher.real|g" >"$real_binary" <<'SH'
#!/bin/sh
unset GST_PLUGIN_PATH GST_PLUGIN_PATH_1_0 GST_PLUGIN_SYSTEM_PATH GST_PLUGIN_SYSTEM_PATH_1_0
exec "$(dirname "$0")/@BINARY@" "$@"
SH
chmod 0755 "$real_binary"

rm -f "$absolute"
ARCH="${ARCH:-$(uname -m)}" appimagetool "$appdir" "$absolute" >/dev/null

if [[ -n "${TAURI_SIGNING_PRIVATE_KEY:-}" ]]; then
  cargo tauri signer sign --private-key "$TAURI_SIGNING_PRIVATE_KEY" \
    ${TAURI_SIGNING_PRIVATE_KEY_PASSWORD:+--password "$TAURI_SIGNING_PRIVATE_KEY_PASSWORD"} \
    "$absolute"
fi
echo "repacked AppImage: $absolute"
