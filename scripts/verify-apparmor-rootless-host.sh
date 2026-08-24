#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
package="${1:-$repo_root/dist/release/ferrocrate_0.1.0_amd64.deb}"
sysctl_name="kernel.apparmor_restrict_unprivileged_userns"
profile_name="usr.local.bin.ferrocrate"
profile_path="/etc/apparmor.d/usr.local.bin.ferrocrate"

if [[ "$(id -u)" != 0 ]]; then
  echo "usage: sudo $0 [ferrocrate.deb]" >&2
  exit 2
fi
if [[ ! -f "$package" ]]; then
  echo "AppArmor host proof requires a FerroCrate Debian package: $package" >&2
  exit 2
fi

proof_user="${SUDO_USER:-}"
if [[ -z "$proof_user" || "$proof_user" == root ]]; then
  echo "AppArmor host proof must be invoked by a non-root user through sudo" >&2
  exit 2
fi
proof_uid="$(id -u "$proof_user")"
proof_home="$(getent passwd "$proof_user" | cut -d: -f6)"
proof_runtime="/run/user/$proof_uid"
if [[ -z "$proof_home" || ! -d "$proof_runtime" ]]; then
  echo "cannot resolve HOME/XDG_RUNTIME_DIR for proof user $proof_user" >&2
  exit 2
fi

initial_sysctl="$(sysctl -n "$sysctl_name")"
restored=0
restore_sysctl() {
  if [[ "$restored" == 0 ]]; then
    sysctl -q -w "$sysctl_name=$initial_sysctl"
    restored=1
    echo "apparmor.proof.sysctl.restored=$(sysctl -n "$sysctl_name")"
  fi
}
trap restore_sysctl EXIT INT TERM

echo "apparmor.proof.user=$proof_user"
echo "apparmor.proof.host=$(hostname)"
echo "apparmor.proof.kernel=$(uname -r)"
echo "apparmor.proof.sysctl.initial=$initial_sysctl"

dpkg -i "$package"
test -x /usr/local/bin/ferrocrate
test -f "$profile_path"
apparmor_parser -r "$profile_path"
sysctl -q -w "$sysctl_name=1"
echo "apparmor.proof.sysctl.active=$(sysctl -n "$sysctl_name")"

if ! awk -v name="$profile_name" '$1 == name { found=1 } END { exit !found }' \
    /sys/kernel/security/apparmor/profiles; then
  echo "AppArmor profile is not loaded: $profile_name" >&2
  exit 1
fi
echo "apparmor.proof.profile=loaded name=$profile_name path=$profile_path"

runuser -u "$proof_user" -- env \
  HOME="$proof_home" \
  XDG_RUNTIME_DIR="$proof_runtime" \
  FERROCRATE_NETWORK_CLI=/usr/local/bin/ferrocrate \
  bash "$repo_root/scripts/verify-rootless.sh"
echo "apparmor.proof.verify_rootless=pass"

runuser -u "$proof_user" -- env \
  HOME="$proof_home" \
  XDG_RUNTIME_DIR="$proof_runtime" \
  FERROCRATE_NETWORK_CLI=/usr/local/bin/ferrocrate \
  bash "$repo_root/scripts/test-rootless-published-port.sh"
echo "apparmor.proof.published_port=pass"

restore_sysctl
trap - EXIT INT TERM
echo "apparmor.proof.result=pass"
