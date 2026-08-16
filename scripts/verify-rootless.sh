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

user=$(id -un)
if grep -q "^${user}:" /etc/subuid 2>/dev/null; then
  echo "rootless.subuid=pass"
else
  echo "rootless.subuid=missing"
  echo "warning: no /etc/subuid entry for $(id -un); rootless will use 1:1 mapping" >&2
fi
if grep -q "^${user}:" /etc/subgid 2>/dev/null; then
  echo "rootless.subgid=pass"
else
  echo "rootless.subgid=missing"
  echo "warning: no /etc/subgid entry for $(id -un); rootless will use 1:1 mapping" >&2
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
  exit 1
fi

echo "rootless verification checks passed"
