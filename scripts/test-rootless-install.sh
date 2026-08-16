#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname -- "$0")/.." && pwd)"
installer="$repo_root/scripts/rootless-install.sh"
tmp_home="$(mktemp -d)"
trap 'rm -rf -- "$tmp_home"' EXIT
runtime_dir="$tmp_home/run"
mkdir -p "$runtime_dir"

run_installer() {
  HOME="$tmp_home" \
    XDG_CONFIG_HOME="$tmp_home/config" \
    XDG_RUNTIME_DIR="$runtime_dir" \
    "$installer" --binary /bin/true --socket "$runtime_dir/ferrocrate.sock" "$@"
}

run_installer --dry-run >"$tmp_home/dry-run.txt"
grep -q '^rootless.install.dry_run=pass$' "$tmp_home/dry-run.txt"

run_installer >"$tmp_home/install.txt"
test -x "$tmp_home/.local/bin/ferrocrate"
test -f "$tmp_home/config/systemd/user/ferrocrate.service"

if run_installer >"$tmp_home/duplicate.txt" 2>&1; then
  echo "duplicate installation unexpectedly succeeded" >&2
  exit 1
fi
grep -q 'use --upgrade' "$tmp_home/duplicate.txt"

run_installer --upgrade >"$tmp_home/upgrade.txt"
grep -q '^rootless.install.mode=upgrade$' "$tmp_home/upgrade.txt"

if HOME="$tmp_home" XDG_CONFIG_HOME="$tmp_home/config" XDG_RUNTIME_DIR="$runtime_dir" \
  "$installer" --binary /bin/true --socket '/tmp/unsafe%socket' --dry-run \
  >"$tmp_home/unsafe.txt" 2>&1; then
  echo "unsafe socket path unexpectedly succeeded" >&2
  exit 1
fi
grep -q 'socket must be an absolute path' "$tmp_home/unsafe.txt"

echo "rootless installer regression checks passed"
