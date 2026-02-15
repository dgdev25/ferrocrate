#!/usr/bin/env bash
set -euo pipefail

APP_PATH="${1:-./dist/macos/FerroCrate Desktop.app}"
DMG_PATH="${2:-./dist/macos/ferro-desktop.dmg}"

: "${MACOS_SIGN_IDENTITY:?MACOS_SIGN_IDENTITY is required}"

if [[ ! -d "$APP_PATH" ]]; then
  echo "missing app bundle: $APP_PATH" >&2
  exit 1
fi

codesign --force --options runtime --timestamp --sign "$MACOS_SIGN_IDENTITY" "$APP_PATH"

if [[ -f "$DMG_PATH" ]]; then
  codesign --force --timestamp --sign "$MACOS_SIGN_IDENTITY" "$DMG_PATH"
fi

if [[ -n "${MACOS_NOTARY_PROFILE:-}" && -f "$DMG_PATH" ]]; then
  xcrun notarytool submit "$DMG_PATH" --keychain-profile "$MACOS_NOTARY_PROFILE" --wait
  xcrun stapler staple "$DMG_PATH"
fi

echo "signed macOS artifacts"
