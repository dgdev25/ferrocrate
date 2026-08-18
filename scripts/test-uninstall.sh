#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname -- "$0")/.." && pwd)"
tmp_home="$(mktemp -d)"
trap 'find "$tmp_home" -depth -delete' EXIT
mkdir -p "$tmp_home/bin" "$tmp_home/config/systemd/user" "$tmp_home/state"
printf 'binary\n' >"$tmp_home/bin/ferrocrate"
printf '[Service]\n' >"$tmp_home/config/systemd/user/ferrocrate.service"
printf 'keep\n' >"$tmp_home/state/containers.db"

HOME="$tmp_home" \
  FERROCRATE_INSTALL_DIR="$tmp_home/bin" \
  XDG_CONFIG_HOME="$tmp_home/config" \
  FERROCRATE_SKIP_SYSTEMCTL=1 \
  "$repo_root/scripts/uninstall.sh" >"$tmp_home/output.txt"

test ! -e "$tmp_home/bin/ferrocrate"
test ! -e "$tmp_home/config/systemd/user/ferrocrate.service"
test -f "$tmp_home/state/containers.db"
grep -q '^ferrocrate.uninstall.state=preserved$' "$tmp_home/output.txt"

if HOME="$tmp_home" FERROCRATE_INSTALL_DIR=/tmp/ferrocrate-unsafe XDG_CONFIG_HOME="$tmp_home/config" \
  FERROCRATE_SKIP_SYSTEMCTL=1 "$repo_root/scripts/uninstall.sh" >"$tmp_home/unsafe.txt" 2>&1; then
  echo "unsafe install directory unexpectedly accepted" >&2
  exit 1
fi
grep -q 'refusing to remove outside' "$tmp_home/unsafe.txt"

echo "uninstall regression checks passed"
