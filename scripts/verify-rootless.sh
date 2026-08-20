#!/usr/bin/env bash
set -euo pipefail

userns_path="/proc/sys/kernel/unprivileged_userns_clone"
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
# bubblewrap for the rootfs/mount boundary. A host can permit the standalone
# mount probe above while denying that nested combination, so report it
# separately instead of letting Compose fail after container state is created.
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
  echo "warning: rootless cgroup limits require a delegated user systemd scope (systemd-run --user --scope -p Delegate=yes) or a caller-owned FERROCRATE_CGROUP_ROOT" >&2
  missing=1
fi

if [[ -n "${XDG_RUNTIME_DIR:-}" && -d "$XDG_RUNTIME_DIR" && -w "$XDG_RUNTIME_DIR" ]]; then
  echo "rootless.xdg_runtime_dir=pass"
else
  echo "rootless.xdg_runtime_dir=missing"
  missing=1
fi

if [[ "$strict" == 1 && "$missing" != 0 ]]; then
  echo "rootless prerequisites are incomplete (strict mode)" >&2
  echo "rootless remediation: enable unprivileged user+mount namespaces, configure /etc/subuid and /etc/subgid, install newuidmap/newgidmap, slirp4netns, and bubblewrap, and provide a writable XDG_RUNTIME_DIR" >&2
  exit 1
fi

echo "rootless verification checks passed"
