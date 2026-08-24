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
  if [[ "$restored" == 1 ]]; then
    return 0
  fi
  if [[ "$restored" == 2 ]]; then
    return 1
  fi

  if ! sysctl -q -w "$sysctl_name=$initial_sysctl"; then
    restored=2
    echo "AppArmor host proof could not restore $sysctl_name to $initial_sysctl" >&2
    return 1
  fi
  restored_value="$(sysctl -n "$sysctl_name")"
  if [[ "$restored_value" != "$initial_sysctl" ]]; then
    restored=2
    echo "AppArmor host proof could not restore $sysctl_name: initial=$initial_sysctl actual=$restored_value" >&2
    return 1
  fi
  restored=1
  echo "apparmor.proof.sysctl.restored=$restored_value"
}
trap restore_sysctl EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "apparmor.proof.user=$proof_user"
echo "apparmor.proof.host=$(hostname)"
echo "apparmor.proof.kernel=$(uname -r)"
if [[ -r /etc/os-release ]]; then
  host_os="$(sed -n 's/^PRETTY_NAME=//p' /etc/os-release | head -n 1)"
  host_os="${host_os#\"}"
  host_os="${host_os%\"}"
  echo "apparmor.proof.os=${host_os:-unknown}"
else
  echo "apparmor.proof.os=unknown"
fi
echo "apparmor.proof.sysctl.initial=$initial_sysctl"

dpkg -i "$package"
test -x /usr/local/bin/ferrocrate
test -f "$profile_path"
apparmor_parser -r "$profile_path"
echo "apparmor.proof.profile_parse=pass path=$profile_path"
sysctl -q -w "$sysctl_name=1"
active_sysctl="$(sysctl -n "$sysctl_name")"
if [[ "$active_sysctl" != 1 ]]; then
  echo "AppArmor host proof could not activate $sysctl_name=1: actual=$active_sysctl" >&2
  exit 1
fi
echo "apparmor.proof.sysctl.active=$active_sysctl"

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
echo "apparmor.proof.verify_rootless=recorded"

runuser -u "$proof_user" -- env \
  HOME="$proof_home" \
  XDG_RUNTIME_DIR="$proof_runtime" \
  FERROCRATE_NETWORK_CLI=/usr/local/bin/ferrocrate \
  bash "$repo_root/scripts/test-rootless-published-port.sh"
echo "apparmor.proof.published_port=pass"

restore_sysctl
trap - EXIT INT TERM
echo "apparmor.proof.result=pass"
