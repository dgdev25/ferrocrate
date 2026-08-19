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
grep -q '^rootless.install.userns_mount=' "$tmp_home/dry-run.txt"
grep -q '^rootless.install.bwrap=' "$tmp_home/dry-run.txt"
grep -q '^rootless.install.bwrap_nested=' "$tmp_home/dry-run.txt"
grep -q '^rootless.install.runtime_dir=pass$' "$tmp_home/dry-run.txt"

# Numeric UID/GID subordinate-ID entries are valid system configuration and
# must produce the same installer result as username entries.
printf '%s:200000:65536\n' "$(id -u)" >"$tmp_home/numeric-subuid"
printf '%s:200000:65536\n' "$(id -g)" >"$tmp_home/numeric-subgid"
FERROCRATE_ROOTLESS_SUBUID_FILE="$tmp_home/numeric-subuid" \
FERROCRATE_ROOTLESS_SUBGID_FILE="$tmp_home/numeric-subgid" \
  run_installer --dry-run >"$tmp_home/numeric-dry-run.txt"
grep -q '^rootless.install.subuid=pass$' "$tmp_home/numeric-dry-run.txt"
grep -q '^rootless.install.subgid=pass$' "$tmp_home/numeric-dry-run.txt"

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

# Uninstall removes only the user-owned binary and unit, leaving the runtime
# directory and unrelated files untouched.
run_installer --uninstall >"$tmp_home/uninstall.txt"
grep -q '^rootless.install.mode=uninstall$' "$tmp_home/uninstall.txt"
test ! -e "$tmp_home/.local/bin/ferrocrate"
test ! -e "$tmp_home/config/systemd/user/ferrocrate.service"
test -d "$runtime_dir"

# Reinstall so the upgrade rollback checks exercise an installed transaction.
run_installer >"$tmp_home/reinstall.txt"
test -x "$tmp_home/.local/bin/ferrocrate"
test -f "$tmp_home/config/systemd/user/ferrocrate.service"

# Fault-inject the second half of an upgrade and verify that the paired
# binary/unit transaction restores both previous artifacts.
sha_before_binary="$(sha256sum "$tmp_home/.local/bin/ferrocrate" | awk '{print $1}')"
sha_before_unit="$(sha256sum "$tmp_home/config/systemd/user/ferrocrate.service" | awk '{print $1}')"
if ! FERROCRATE_INSTALL_FAIL_AFTER_BINARY=1 run_installer --upgrade >"$tmp_home/rollback.txt" 2>&1; then
  :
else
  echo "injected upgrade failure unexpectedly succeeded" >&2
  exit 1
fi
grep -q 'injected failure after binary replacement' "$tmp_home/rollback.txt"
test "$(sha256sum "$tmp_home/.local/bin/ferrocrate" | awk '{print $1}')" = "$sha_before_binary"
test "$(sha256sum "$tmp_home/config/systemd/user/ferrocrate.service" | awk '{print $1}')" = "$sha_before_unit"

if HOME="$tmp_home" XDG_CONFIG_HOME="$tmp_home/config" XDG_RUNTIME_DIR="$runtime_dir" \
  "$installer" --binary /bin/true --socket '/tmp/unsafe%socket' --dry-run \
  >"$tmp_home/unsafe.txt" 2>&1; then
  echo "unsafe socket path unexpectedly succeeded" >&2
  exit 1
fi
grep -q 'socket must be an absolute path' "$tmp_home/unsafe.txt"

mkdir -p "$tmp_home/path with spaces"
cp /bin/true "$tmp_home/path with spaces/ferrocrate"
if HOME="$tmp_home" XDG_CONFIG_HOME="$tmp_home/config-space" XDG_RUNTIME_DIR="$runtime_dir" \
  "$installer" --binary "$tmp_home/path with spaces/ferrocrate" --socket "$runtime_dir/space.sock" --dry-run \
  >"$tmp_home/space.txt" 2>&1; then
  echo "space-containing binary path unexpectedly succeeded" >&2
  exit 1
fi
grep -q 'binary must be an absolute path' "$tmp_home/space.txt"

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

# --enable must fail before mutation when a user service manager is not
# available. This guards against leaving a binary/unit behind after a late
# systemd failure.
no_systemd="$tmp_home/no-systemd"
mkdir -p "$no_systemd"
cat >"$no_systemd/systemctl" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
chmod 0755 "$no_systemd/systemctl"
enable_home="$tmp_home/enable-home"
mkdir -p "$enable_home"
if PATH="$no_systemd:/usr/bin:/bin" HOME="$enable_home" \
  XDG_CONFIG_HOME="$enable_home/config" XDG_RUNTIME_DIR="$runtime_dir" \
  "$installer" --binary /bin/true --socket "$runtime_dir/enable.sock" --enable \
  >"$tmp_home/enable.txt" 2>&1; then
  echo "--enable unexpectedly succeeded without a user service manager" >&2
  exit 1
fi
grep -q 'no files were changed' "$tmp_home/enable.txt"
test ! -e "$enable_home/.local/bin/ferrocrate"
test ! -e "$enable_home/config/systemd/user/ferrocrate.service"

unsafe_bin="$tmp_home/unsafe-bin"
mkdir -p "$unsafe_bin"
for helper in newuidmap newgidmap slirp4netns bwrap; do
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
