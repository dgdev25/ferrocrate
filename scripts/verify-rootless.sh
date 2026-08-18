#!/usr/bin/env bash
set -euo pipefail

userns_path="/proc/sys/kernel/unprivileged_userns_clone"
strict="${FERROCRATE_ROOTLESS_STRICT:-0}"
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
if command -v unshare >/dev/null 2>&1 && \
  unshare --user --mount --fork --propagation unchanged true >/dev/null 2>&1; then
  echo "rootless.userns_mount=pass"
else
  echo "rootless.userns_mount=missing"
  echo "warning: unprivileged user+mount namespace creation is unavailable" >&2
  missing=1
fi

# Bridge-mode workloads create the user+network namespace first and then use
# bubblewrap for the rootfs/mount boundary. A host can permit the standalone
# mount probe above while denying that nested combination, so report it
# separately instead of letting Compose fail after container state is created.
if command -v bwrap >/dev/null 2>&1 && command -v unshare >/dev/null 2>&1 && \
  unshare --user --net --fork sh -c 'exec bwrap --ro-bind / / true' >/dev/null 2>&1; then
  echo "rootless.bwrap_nested=pass"
else
  echo "rootless.bwrap_nested=missing"
  echo "warning: bridge-mode rootless workloads may be unavailable because nested bubblewrap user namespaces are denied" >&2
  missing=1
fi

user=$(id -un)
user_id=$(id -u)
group_id=$(id -g)
subuid_file="${FERROCRATE_ROOTLESS_SUBUID_FILE:-/etc/subuid}"
subgid_file="${FERROCRATE_ROOTLESS_SUBGID_FILE:-/etc/subgid}"
has_subid_entry() {
  local path="$1" name="$2" numeric_id="$3"
  [[ -r "$path" ]] || return 1
  awk -F: -v name="$name" -v numeric_id="$numeric_id" \
    '$1 == name || $1 == numeric_id { found=1 } END { exit !found }' "$path"
}
if has_subid_entry "$subuid_file" "$user" "$user_id"; then
  echo "rootless.subuid=pass"
else
  echo "rootless.subuid=missing"
  echo "warning: no $subuid_file entry for $(id -un) or UID $user_id; rootless will use 1:1 mapping" >&2
fi
if has_subid_entry "$subgid_file" "$user" "$group_id"; then
  echo "rootless.subgid=pass"
else
  echo "rootless.subgid=missing"
  echo "warning: no $subgid_file entry for $(id -un) or GID $group_id; rootless will use 1:1 mapping" >&2
fi

for helper in newuidmap newgidmap; do
  if command -v "$helper" >/dev/null 2>&1; then
    echo "rootless.$helper=pass"
  else
    echo "rootless.$helper=missing"
    missing=1
  fi
done

if [[ -f /sys/fs/cgroup/cgroup.controllers ]]; then
  echo "rootless.cgroup_v2=pass"
else
  echo "rootless.cgroup_v2=missing"
  missing=1
fi

if [[ -n "${XDG_RUNTIME_DIR:-}" && -d "$XDG_RUNTIME_DIR" && -w "$XDG_RUNTIME_DIR" ]]; then
  echo "rootless.xdg_runtime_dir=pass"
else
  echo "rootless.xdg_runtime_dir=missing"
  missing=1
fi

if command -v slirp4netns >/dev/null 2>&1; then
  echo "rootless.slirp4netns=pass"
else
  echo "rootless.slirp4netns=missing"
  missing=1
fi

if [[ "$strict" == 1 && "$missing" != 0 ]]; then
  echo "rootless prerequisites are incomplete (strict mode)" >&2
  echo "rootless remediation: enable unprivileged user+mount namespaces, configure /etc/subuid and /etc/subgid, install newuidmap/newgidmap, slirp4netns, and bubblewrap, and provide a writable XDG_RUNTIME_DIR" >&2
  exit 1
fi

echo "rootless verification checks passed"
