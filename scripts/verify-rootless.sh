#!/usr/bin/env bash
set -euo pipefail

userns_path="/proc/sys/kernel/unprivileged_userns_clone"
apparmor_profile_name="usr.local.bin.ferrocrate"
apparmor_profile_path="${FERROCRATE_APPARMOR_PROFILE_PATH:-/etc/apparmor.d/usr.local.bin.ferrocrate}"
apparmor_profiles_path="${FERROCRATE_APPARMOR_PROFILES_PATH:-/sys/kernel/security/apparmor/profiles}"
apparmor_userns_path="${FERROCRATE_APPARMOR_USERNS_PATH:-/proc/sys/kernel/apparmor_restrict_unprivileged_userns}"
apparmor_enabled_path="${FERROCRATE_APPARMOR_ENABLED_PATH:-/sys/module/apparmor/parameters/enabled}"
strict="${FERROCRATE_ROOTLESS_STRICT:-0}"
for argument in "$@"; do
  case "$argument" in
    --strict)
      strict=1
      ;;
    --help|-h)
      cat <<'USAGE'
Usage: verify-rootless.sh [--strict]

Probe rootless prerequisites. With --strict, return non-zero when any
prerequisite or namespace capability is unavailable.
USAGE
      exit 0
      ;;
    *)
      echo "verify-rootless: unknown argument: $argument" >&2
      exit 2
      ;;
  esac
done
missing=0
if [[ -f "$userns_path" ]]; then
  value=$(cat "$userns_path")
  echo "rootless.userns_clone=$value"
  if [[ "$value" != "1" ]]; then
    echo "unprivileged user namespaces are disabled: $userns_path=$value" >&2
    missing=1
  fi
fi

# Docker-compatible rootless authentication requires the kernel's
# SO_PEERPIDFD socket option.  Probe it directly on a local Unix socket pair
# before starting a daemon so an older kernel reports a capability boundary
# instead of a generic readiness timeout.  Keep the probe side-effect free:
# the returned pidfd is closed immediately and no process is created.
if command -v python3 >/dev/null 2>&1; then
  peer_pidfd_probe=""
  if peer_pidfd_probe=$(python3 - 2>&1 <<'PY'
import os
import socket

SO_PEERPIDFD = 77
left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    pidfd = left.getsockopt(socket.SOL_SOCKET, SO_PEERPIDFD)
    if pidfd < 0:
        raise OSError("kernel returned an invalid peer pidfd")
    os.close(pidfd)
finally:
    left.close()
    right.close()
PY
  ); then
    echo "rootless.peer_pidfd=pass"
  else
    peer_pidfd_reason="$(printf '%s' "$peer_pidfd_probe" | tr '\n' ' ' | tr -s ' ' | cut -c1-240)"
    echo "rootless.peer_pidfd=missing"
    echo "rootless.peer_pidfd_reason=${peer_pidfd_reason:-SO_PEERPIDFD is unavailable}"
    echo "warning: Docker-compatible rootless/CRI authentication requires a kernel with SO_PEERPIDFD" >&2
    missing=1
  fi
else
  echo "rootless.peer_pidfd=missing"
  echo "rootless.peer_pidfd_reason=python3 is unavailable for the socket capability probe"
  echo "warning: install python3 or provide an equivalent SO_PEERPIDFD probe before rootless qualification" >&2
  missing=1
fi

# The sysctl only expresses policy. Probe the namespace operation that the
# rootless workload launcher actually needs so a host cannot pass diagnostics
# while its user+mount namespace creation is denied by a container/LSM
# boundary. FerroCrate creates the user namespace first and applies the
# subordinate UID/GID maps through the authenticated newuidmap/newgidmap path;
# requiring util-linux's `--map-root-user` here would test a different mapping
# mechanism and reject hosts that the production path supports. Keep mount
# propagation unchanged: changing the caller's root propagation is optional.
# This probe is side-effect free: it launches `true` and exits.
if command -v unshare >/dev/null 2>&1; then
  if userns_mount_probe=$(unshare --user --mount --fork --propagation unchanged true 2>&1); then
    echo "rootless.userns_mount=pass"
  else
    probe_reason=$(printf '%s' "$userns_mount_probe" | tr '\n' ' ' | tr -s ' ' | cut -c1-240)
    echo "rootless.userns_mount=missing"
    echo "rootless.userns_mount_reason=${probe_reason:-probe exited unsuccessfully}"
    echo "warning: unprivileged user+mount namespace creation is unavailable" >&2
    missing=1
  fi
else
  echo "rootless.userns_mount=missing"
  echo "rootless.userns_mount_reason=unshare command is unavailable"
  echo "warning: unprivileged user+mount namespace creation is unavailable" >&2
  missing=1
fi

if command -v bwrap >/dev/null 2>&1 && command -v unshare >/dev/null 2>&1; then
  if bwrap_nested_probe=$(unshare --user --map-root-user --net --fork sh -c 'exec bwrap --ro-bind / / true' 2>&1); then
    echo "rootless.bwrap_nested=pass"
  else
    probe_reason=$(printf '%s' "$bwrap_nested_probe" | tr '\n' ' ' | tr -s ' ' | cut -c1-240)
    # Ubuntu's AppArmor userns policy can deny the mapping after the namespace
    # is created, producing only the generic uid_map EPERM from unshare. Read
    # the kernel policy knob when available so operators get a precise,
    # actionable diagnosis without weakening the policy automatically.
    if [[ -r "$apparmor_userns_path" ]] &&
       [[ "$(cat "$apparmor_userns_path")" == "1" ]]; then
      probe_reason="AppArmor restricts this unprofiled helper probe (kernel.apparmor_restrict_unprivileged_userns=1); FerroCrate profile status is reported below"
    fi
    echo "rootless.bwrap_nested=missing"
    echo "rootless.bwrap_nested_reason=${probe_reason:-probe exited unsuccessfully}"
    echo "warning: bridge-mode rootless workloads may be unavailable because nested bubblewrap user namespaces are denied" >&2
    missing=1
  fi
else
  echo "rootless.bwrap_nested=missing"
  echo "rootless.bwrap_nested_reason=unshare or bubblewrap command is unavailable"
  echo "warning: bridge-mode rootless workloads may be unavailable because nested bubblewrap user namespaces are denied" >&2
  missing=1
fi

# Bridge-mode workloads create the user+network namespace first and then use
# bubblewrap for the rootfs/mount boundary. This generic helper probe is not
# executed in FerroCrate's AppArmor domain, so its result is reported separately
# from the package profile state below.
user=$(id -un)
user_id=$(id -u)
group_id=$(id -g)
subuid_file="${FERROCRATE_ROOTLESS_SUBUID_FILE:-/etc/subuid}"
subgid_file="${FERROCRATE_ROOTLESS_SUBGID_FILE:-/etc/subgid}"
has_subid_entry() {
  local path="$1" name="$2" numeric_id="$3"
  [[ -r "$path" ]] || return 1
  awk -F: -v name="$name" -v numeric_id="$numeric_id" \
    '$1 == name || $1 == numeric_id { if ($2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ && $3 > 0) found=1 } END { exit !found }' "$path"
}
if has_subid_entry "$subuid_file" "$user" "$user_id"; then
  echo "rootless.subuid=pass"
else
  echo "rootless.subuid=missing"
  echo "warning: no $subuid_file entry for $(id -un) or UID $user_id; rootless will use 1:1 mapping" >&2
  missing=1
fi
if has_subid_entry "$subgid_file" "$user" "$group_id"; then
  echo "rootless.subgid=pass"
else
  echo "rootless.subgid=missing"
  echo "warning: no $subgid_file entry for $(id -un) or GID $group_id; rootless will use 1:1 mapping" >&2
  missing=1
fi

check_trusted_helper() {
  local helper="$1" path owner
  path="$(command -v "$helper" || true)"
  [[ -n "$path" && -f "$path" && ! -L "$path" ]] || return 1
  owner="$(stat -c '%u' -- "$path" 2>/dev/null || true)"
  [[ "$owner" == 0 ]] || return 1
  ! find "$path" -prune -perm /022 -print -quit 2>/dev/null | grep -q .
}

for helper in newuidmap newgidmap slirp4netns bwrap; do
  if check_trusted_helper "$helper"; then
    echo "rootless.$helper=pass"
  else
    echo "rootless.$helper=missing-or-untrusted"
    missing=1
  fi
done

if [[ -f /sys/fs/cgroup/cgroup.controllers ]]; then
  echo "rootless.cgroup_v2=pass"
else
  echo "rootless.cgroup_v2=missing"
  missing=1
fi

# Cgroup v2 being mounted is not sufficient for rootless resource controls:
# the caller must also own a delegated hierarchy. Probe only permissions and
# directory shape; never create a cgroup or write controller state here.
cgroup_relative="$(awk -F: '$1 == 0 { print $3; exit }' /proc/self/cgroup 2>/dev/null || true)"
cgroup_root="${FERROCRATE_CGROUP_ROOT:-/sys/fs/cgroup${cgroup_relative}}"
if [[ -d "$cgroup_root" && -w "$cgroup_root" && -w "$cgroup_root/cgroup.procs" ]]; then
  echo "rootless.cgroup_delegation=pass"
else
  echo "rootless.cgroup_delegation=missing"
  echo "rootless.cgroup_delegation_reason=caller hierarchy is not writable: $cgroup_root"
  echo "warning: rootless cgroup limits require a delegated user systemd scope (scripts/run-rootless-delegated.sh COMMAND ...) or a caller-owned FERROCRATE_CGROUP_ROOT" >&2
  missing=1
fi

if [[ -n "${XDG_RUNTIME_DIR:-}" && -d "$XDG_RUNTIME_DIR" && -w "$XDG_RUNTIME_DIR" ]]; then
  echo "rootless.xdg_runtime_dir=pass"
else
  echo "rootless.xdg_runtime_dir=missing"
  missing=1
fi

# Kernel version report: cgroup-v2 delegation, SO_PEERPIDFD (5.8+), and the
# userns sysctls used above assume a modern kernel. Below the floor the report
# is informational (individual probes above already fail closed), never an
# independent gate.
kernel_version="$(uname -r 2>/dev/null || echo unknown)"
kernel_major_minor="$(printf '%s' "$kernel_version" | awk -F. '{print $1"."$2}')"
kernel_floor_pass=1
if [[ "$kernel_major_minor" =~ ^([0-9]+)\.([0-9]+)$ ]]; then
  kmajor="${BASH_REMATCH[1]}"
  kminor="${BASH_REMATCH[2]}"
  if (( kmajor < 5 )) || { (( kmajor == 5 )) && (( kminor < 11 )); }; then
    kernel_floor_pass=0
  fi
  echo "rootless.kernel=pass version=${kernel_version}"
  (( kernel_floor_pass )) || echo "rootless.kernel_note=below 5.11; cgroup-v2 delegation and SO_PEERPIDFD probes above are authoritative"
else
  echo "rootless.kernel=unknown version=${kernel_version}"
fi

# AppArmor state: when the unprivileged-userns restriction is enabled, an
# unprofiled generic bubblewrap probe can be denied even if FerroCrate's
# package profile is loaded.
# Report the module, the sysctl, and (when restricted) the package profile's
# installation and kernel-loaded state.
apparmor_enabled="no"
if [[ -r "$apparmor_enabled_path" ]]; then
  apparmor_enabled="$(tr -d '[:space:]' <"$apparmor_enabled_path")"
  [[ "$apparmor_enabled" == "Y" ]] && apparmor_enabled="yes" || apparmor_enabled="no"
fi
if [[ "$apparmor_enabled" == "yes" ]]; then
  echo "rootless.apparmor=enabled"
else
  echo "rootless.apparmor=disabled-or-unavailable"
fi
if [[ -r "$apparmor_userns_path" ]]; then
  userns_restricted="$(cat "$apparmor_userns_path")"
  echo "rootless.apparmor_restrict_unprivileged_userns=${userns_restricted}"
  if [[ "$userns_restricted" == "1" ]]; then
    if [[ -f "$apparmor_profile_path" ]] && [[ -r "$apparmor_profiles_path" ]] &&
       awk -v name="$apparmor_profile_name" '$1 == name { found=1 } END { exit !found }' "$apparmor_profiles_path"; then
      echo "rootless.apparmor_profile=loaded name=${apparmor_profile_name} path=${apparmor_profile_path}"
      echo "rootless.apparmor_note=FerroCrate profile grants userns while the host-wide restriction remains active"
    elif [[ -f "$apparmor_profile_path" ]] && [[ -r "$apparmor_profiles_path" ]]; then
      echo "rootless.apparmor_profile=installed-not-loaded name=${apparmor_profile_name} path=${apparmor_profile_path}"
      echo "rootless.apparmor_remedy=sudo apparmor_parser -r ${apparmor_profile_path}"
      missing=1
    elif [[ -f "$apparmor_profile_path" ]]; then
      echo "rootless.apparmor_profile=installed-load-state-unreadable name=${apparmor_profile_name} path=${apparmor_profile_path}"
      echo "rootless.apparmor_note=run sudo aa-status to confirm the FerroCrate profile is loaded"
    else
      echo "rootless.apparmor_profile=absent name=${apparmor_profile_name} path=${apparmor_profile_path}"
      echo "rootless.apparmor_remedy=install or reinstall the FerroCrate Debian package, then run sudo apparmor_parser -r ${apparmor_profile_path}"
      missing=1
    fi
  fi
fi

# Rootless socket state: report every probed candidate with its disposition so
# a stale or missing socket is visible before a client command hangs.
socket_reported=0
for socket_candidate in \
  "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/ferrocrate/ferro.sock" \
  "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/ferrocrate/docker.sock" \
  "$HOME/.ferrocrate/run/ferro.sock"; do
  if [[ -S "$socket_candidate" ]]; then
    echo "rootless.socket=found path=${socket_candidate}"
    socket_reported=1
  fi
done
if (( ! socket_reported )); then
  echo "rootless.socket=none"
  echo "rootless.socket_note=no rootless daemon socket found; start one or export FERROCRATE_RUNTIME_DIR"
fi

if [[ "$strict" == 1 && "$missing" != 0 ]]; then
  echo "rootless prerequisites are incomplete (strict mode)" >&2
  echo "rootless remediation: enable unprivileged user+mount namespaces, configure /etc/subuid and /etc/subgid, install newuidmap/newgidmap, slirp4netns, and bubblewrap, and provide a writable XDG_RUNTIME_DIR" >&2
  exit 1
fi

echo "rootless verification checks passed"
