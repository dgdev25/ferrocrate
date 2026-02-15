#!/usr/bin/env bash
set -euo pipefail

APP_NAME="FerroCrate Desktop"
APP_DIR="${1:-./dist/macos/${APP_NAME}.app}"
BIN_PATH="${2:-./target/release/ferro-desktop}"
DMG_PATH="${3:-./dist/macos/ferro-desktop.dmg}"
CREATE_DMG="${CREATE_DMG:-1}"

if [[ ! -x "$BIN_PATH" ]]; then
  echo "missing executable binary: $BIN_PATH" >&2
  exit 1
fi

CONTENTS_DIR="$APP_DIR/Contents"
MACOS_DIR="$CONTENTS_DIR/MacOS"
RES_DIR="$CONTENTS_DIR/Resources"
PLIST_PATH="$CONTENTS_DIR/Info.plist"

mkdir -p "$MACOS_DIR" "$RES_DIR" "$(dirname "$DMG_PATH")"
cp "$BIN_PATH" "$MACOS_DIR/ferro-desktop"
chmod +x "$MACOS_DIR/ferro-desktop"

cat > "$PLIST_PATH" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key>
  <string>${APP_NAME}</string>
  <key>CFBundleIdentifier</key>
  <string>io.ferrocrate.desktop</string>
  <key>CFBundleExecutable</key>
  <string>ferro-desktop</string>
  <key>CFBundleVersion</key>
  <string>1</string>
  <key>CFBundleShortVersionString</key>
  <string>0.1.0</string>
  <key>LSMinimumSystemVersion</key>
  <string>12.0</string>
</dict>
</plist>
PLIST

if [[ "$CREATE_DMG" == "1" ]]; then
  if ! command -v hdiutil >/dev/null 2>&1; then
    echo "hdiutil is required to create dmg" >&2
    exit 1
  fi
  hdiutil create -volname "$APP_NAME" -srcfolder "$APP_DIR" -ov -format UDZO "$DMG_PATH" >/dev/null
  echo "created dmg: $DMG_PATH"
fi

echo "created app bundle: $APP_DIR"
