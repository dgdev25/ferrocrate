#!/usr/bin/env bash
set -euo pipefail

# Install a per-user FerroCrate Docker-compatible daemon. This script never
# writes outside the invoking user's home directory and never requires sudo.
# It intentionally reports missing host prerequisites instead of silently
# installing privileged helpers.

usage() {
  cat <<'EOF'
Usage: rootless-install.sh [--binary PATH] [--socket PATH] [--enable] [--upgrade] [--dry-run] [--strict]

Installs ~/.local/bin/ferrocrate and a systemd user unit. --enable starts the
unit immediately when systemd --user is available. --upgrade atomically replaces
an existing per-user binary and unit. Use --dry-run to inspect the plan without
writing files. --strict fails before mutation when required rootless host
prerequisites are unavailable.
EOF
}

binary=""
socket="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/ferrocrate.sock"
enable=0
upgrade=0
dry_run=0
strict=0
while (($#)); do
  case "$1" in
    --binary) binary="${2:?missing path after --binary}"; shift 2 ;;
    --socket) socket="${2:?missing path after --socket}"; shift 2 ;;
    --enable) enable=1; shift ;;
    --upgrade) upgrade=1; shift ;;
    --dry-run) dry_run=1; shift ;;
    --strict) strict=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$binary" ]]; then
  binary="$(command -v ferrocrate || true)"
fi
if [[ -z "$binary" ]]; then
  candidate="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/target/release/ferrocrate"
  [[ -x "$candidate" ]] && binary="$candidate"
fi
if [[ -z "$binary" ]]; then
  # The workspace package is named ferro-cli and Cargo emits this binary;
  # release packaging may rename it to ferrocrate, so support both layouts.
  candidate="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/target/release/ferro-cli"
  [[ -x "$candidate" ]] && binary="$candidate"
fi
if [[ -z "$binary" || ! -x "$binary" ]]; then
  echo "rootless-install: ferrocrate/ferro-cli executable not found; pass --binary PATH" >&2
  exit 1
fi
if [[ "$binary" != /* || "$binary" == *[$'\t\n\r "%']* ]]; then
  echo "rootless-install: binary must be an absolute path without unit-file metacharacters" >&2
  exit 1
fi
if [[ "$socket" != /* || "$socket" == *[$'\t\n\r "%']* ]]; then
  echo "rootless-install: socket must be an absolute path" >&2
  exit 1
fi

uid="$(id -u)"
user="$(id -un)"
echo "rootless.install.user=$user"
echo "rootless.install.uid=$uid"
echo "rootless.install.binary=$binary"
echo "rootless.install.socket=$socket"
if ((upgrade)); then
  echo "rootless.install.mode=upgrade"
else
  echo "rootless.install.mode=install"
fi

prerequisite_failures=0
check_helper() {
  local helper="$1"
  local path owner
  path="$(command -v "$helper" || true)"
  if [[ -z "$path" ]]; then
    echo "rootless.install.$helper=missing"
    return 1
  fi
  if [[ -L "$path" || ! -f "$path" ]]; then
    echo "rootless.install.$helper=unsafe-not-regular"
    return 1
  fi
  owner="$(stat -c '%u' -- "$path" 2>/dev/null || true)"
  if [[ "$owner" != "0" ]] || find "$path" -prune -perm /022 -print -quit | grep -q .; then
    echo "rootless.install.$helper=unsafe-owner-or-mode"
    return 1
  fi
  echo "rootless.install.$helper=pass"
}
for helper in newuidmap newgidmap slirp4netns bwrap; do
  if ! check_helper "$helper"; then
    prerequisite_failures=1
  fi
done

if awk -F: -v user="$user" '$1 == user && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ && $3 > 0 { found=1 } END { exit !found }' /etc/subuid 2>/dev/null; then
  echo "rootless.install.subuid=pass"
else
  echo "rootless.install.subuid=missing"
  prerequisite_failures=1
fi
if awk -F: -v user="$user" '$1 == user && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ && $3 > 0 { found=1 } END { exit !found }' /etc/subgid 2>/dev/null; then
  echo "rootless.install.subgid=pass"
else
  echo "rootless.install.subgid=missing"
  prerequisite_failures=1
fi
if [[ -r /sys/fs/cgroup/cgroup.controllers ]]; then
  echo "rootless.install.cgroup_v2=pass"
else
  echo "rootless.install.cgroup_v2=missing"
  prerequisite_failures=1
fi
if [[ -r /proc/sys/user/max_user_namespaces ]] && (( $(< /proc/sys/user/max_user_namespaces) > 0 )); then
  echo "rootless.install.user_namespaces=pass"
else
  echo "rootless.install.user_namespaces=missing"
  prerequisite_failures=1
fi
if command -v unshare >/dev/null 2>&1 && \
  unshare --user --mount --fork --propagation unchanged true >/dev/null 2>&1; then
  echo "rootless.install.userns_mount=pass"
else
  echo "rootless.install.userns_mount=missing"
  prerequisite_failures=1
fi
if [[ -n "${XDG_RUNTIME_DIR:-}" && -d "$XDG_RUNTIME_DIR" && -w "$XDG_RUNTIME_DIR" ]]; then
  echo "rootless.install.runtime_dir=pass"
else
  echo "rootless.install.runtime_dir=missing"
  prerequisite_failures=1
fi
if ((strict && prerequisite_failures)); then
  echo "rootless-install: strict prerequisite check failed; no files were changed" >&2
  exit 1
fi

unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
unit_path="$unit_dir/ferrocrate.service"
installed_binary="$HOME/.local/bin/ferrocrate"
unit_content="[Unit]
Description=FerroCrate rootless Docker-compatible daemon
After=default.target

[Service]
ExecStart=$binary daemon --socket $socket --docker-compat
Restart=on-failure
RestartSec=2
Environment=FERROCRATE_RUNTIME_DIR=%h/.local/share/ferrocrate

[Install]
WantedBy=default.target
"

if ((upgrade)); then
  if (( !dry_run )) && [[ ! -e "$installed_binary" || ! -e "$unit_path" ]]; then
    echo "rootless-install: --upgrade requires an existing binary and user unit" >&2
    exit 1
  fi
elif (( !dry_run )) && [[ -e "$installed_binary" || -e "$unit_path" ]]; then
  echo "rootless-install: installation already exists; use --upgrade" >&2
  exit 1
fi

if ((dry_run)); then
  echo "rootless.install.dry_run=pass"
  printf '%s' "$unit_content"
  exit 0
fi

# Check service-manager availability before mutating either installation
# artifact. Without this preflight, --enable could install a binary and unit,
# then fail to start the user service, leaving a half-successful installation
# that the caller must discover and clean up manually.
if ((enable)); then
  if ! command -v systemctl >/dev/null 2>&1 || ! systemctl --user daemon-reload; then
    echo "rootless-install: --enable requested but systemd --user is unavailable; no files were changed" >&2
    exit 1
  fi
fi

install -d -m 0755 "$HOME/.local/bin" "$unit_dir"
binary_tmp="$(mktemp "$HOME/.local/bin/.ferrocrate.new.XXXXXX")"
unit_tmp="$(mktemp "$unit_dir/.ferrocrate.service.new.XXXXXX")"
rollback_dir="$(mktemp -d "$HOME/.local/bin/.ferrocrate-rollback.XXXXXX")"
transaction_committed=0
cleanup() {
  local status=$?
  rm -f -- "$binary_tmp" "$unit_tmp"
  if (( !transaction_committed )); then
    # Restore both artifacts if either replacement failed.  Never remove a
    # directory supplied as a deliberately invalid unit target.
    if [[ -f "$installed_binary" || -L "$installed_binary" ]]; then
      rm -f -- "$installed_binary"
    fi
    if [[ -f "$unit_path" || -L "$unit_path" ]]; then
      rm -f -- "$unit_path"
    fi
    if [[ -e "$rollback_dir/binary" ]]; then
      mv -f -- "$rollback_dir/binary" "$installed_binary" || true
    fi
    if [[ -e "$rollback_dir/unit" ]]; then
      install -d -m 0755 "$unit_dir"
      mv -f -- "$rollback_dir/unit" "$unit_path" || true
    fi
  fi
  if [[ -d "$rollback_dir" ]]; then
    rmdir -- "$rollback_dir" 2>/dev/null || true
  fi
  return "$status"
}
trap cleanup EXIT
install -m 0755 "$binary" "$binary_tmp"
printf '%s' "$unit_content" >"$unit_tmp"
chmod 0644 "$unit_tmp"
if [[ -e "$installed_binary" ]]; then
  mv -- "$installed_binary" "$rollback_dir/binary"
fi
if [[ -e "$unit_path" ]]; then
  mv -- "$unit_path" "$rollback_dir/unit"
fi
mv -f -- "$binary_tmp" "$installed_binary"
if [[ "${FERROCRATE_INSTALL_FAIL_AFTER_BINARY:-0}" == "1" ]]; then
  echo "rootless-install: injected failure after binary replacement" >&2
  exit 1
fi
mv -f -- "$unit_tmp" "$unit_path"
transaction_committed=1
trap - EXIT
cleanup
echo "rootless.install.binary_path=$installed_binary"
echo "rootless.install.unit_path=$unit_path"

if ((enable)); then
  if ! command -v systemctl >/dev/null 2>&1 || ! systemctl --user daemon-reload; then
    echo "rootless-install: --enable requested but systemd --user is unavailable" >&2
    exit 1
  fi
  systemctl --user enable --now ferrocrate.service
  echo "rootless.install.service=enabled"
else
  echo "rootless-install: run 'systemctl --user enable --now ferrocrate.service' to start"
fi
