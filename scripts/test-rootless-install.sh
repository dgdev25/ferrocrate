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
grep -q '^rootless.install.subuid=' "$tmp_home/dry-run.txt"
grep -q '^rootless.install.subgid=' "$tmp_home/dry-run.txt"
grep -q '^rootless.install.cgroup_v2=' "$tmp_home/dry-run.txt"
grep -q '^rootless.install.user_namespaces=' "$tmp_home/dry-run.txt"
grep -q '^rootless.install.runtime_dir=pass$' "$tmp_home/dry-run.txt"

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

strict_home="$tmp_home/strict-home"
mkdir -p "$strict_home"
if HOME="$strict_home" XDG_CONFIG_HOME="$strict_home/config" XDG_RUNTIME_DIR="$strict_home/missing" \
  "$installer" --binary /bin/true --socket "$strict_home/missing/ferrocrate.sock" --strict --dry-run \
  >"$tmp_home/strict.txt" 2>&1; then
  echo "strict prerequisite check unexpectedly succeeded" >&2
  exit 1
fi
grep -q 'strict prerequisite check failed' "$tmp_home/strict.txt"
test ! -e "$strict_home/config/systemd/user/ferrocrate.service"

unsafe_bin="$tmp_home/unsafe-bin"
mkdir -p "$unsafe_bin"
for helper in newuidmap newgidmap slirp4netns; do
  ln -s /bin/true "$unsafe_bin/$helper"
done
if PATH="$unsafe_bin:/usr/bin:/bin" HOME="$tmp_home" \
  XDG_CONFIG_HOME="$tmp_home/config-unsafe" XDG_RUNTIME_DIR="$runtime_dir" \
  "$installer" --binary /bin/true --socket "$runtime_dir/unsafe.sock" --strict --dry-run \
  >"$tmp_home/unsafe-helper.txt" 2>&1; then
  echo "unsafe helper prerequisite unexpectedly succeeded" >&2
  exit 1
fi
grep -q 'unsafe-not-regular' "$tmp_home/unsafe-helper.txt"

echo "rootless installer regression checks passed"
