#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname -- "$0")/.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'find "$tmp_dir" -depth -delete' EXIT

# Source the installer without contacting the release service.  The production
# entrypoint remains unchanged; the guard in install.sh makes its transaction
# helper directly fixtureable.
# shellcheck source=scripts/install.sh
source "$repo_root/scripts/install.sh"

install_dir="$tmp_dir/bin"
mkdir -p "$install_dir"
printf 'previous\n' >"$install_dir/ferrocrate"

mkdir -p "$tmp_dir/v2/ferrocrate"
printf 'updated\n' >"$tmp_dir/v2/ferrocrate/ferrocrate"
tar -czf "$tmp_dir/v2.tar.gz" -C "$tmp_dir/v2" ferrocrate
install_linux_release "$tmp_dir/v2.tar.gz" "$install_dir"
test "$(cat "$install_dir/ferrocrate")" = updated
test ! -e "$install_dir/.ferrocrate.previous"

# A malformed archive must leave the already-installed version untouched.
mkdir -p "$tmp_dir/bad/other"
printf 'not an installer\n' >"$tmp_dir/bad/other/file"
tar -czf "$tmp_dir/bad.tar.gz" -C "$tmp_dir/bad" other
if install_linux_release "$tmp_dir/bad.tar.gz" "$install_dir"; then
  echo "malformed release unexpectedly installed" >&2
  exit 1
fi
test "$(cat "$install_dir/ferrocrate")" = updated
test ! -e "$install_dir/.ferrocrate.previous"

echo "installer upgrade/rollback regression checks passed"
