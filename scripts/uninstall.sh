#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${FERROCRATE_INSTALL_DIR:-${HOME}/.local/bin}"
TARGET="$INSTALL_DIR/ferrocrate"

case "$INSTALL_DIR" in
  "$HOME"/*) ;;
  *)
    echo "refusing to remove outside the user install directory: $INSTALL_DIR" >&2
    exit 1
    ;;
esac

if [ -L "$TARGET" ] || [ -f "$TARGET" ]; then
  rm -f -- "$TARGET"
  echo "Removed $TARGET"
else
  echo "Ferrocrate is not installed at $TARGET"
fi
