#!/usr/bin/env bash
set -euo pipefail

userns_path="/proc/sys/kernel/unprivileged_userns_clone"
if [[ -f "$userns_path" ]]; then
  value=$(cat "$userns_path")
  if [[ "$value" != "1" ]]; then
    echo "unprivileged user namespaces are disabled: $userns_path=$value" >&2
    exit 1
  fi
fi

if ! grep -q "^$(id -un):" /etc/subuid 2>/dev/null; then
  echo "warning: no /etc/subuid entry for $(id -un); rootless will use 1:1 mapping" >&2
fi
if ! grep -q "^$(id -un):" /etc/subgid 2>/dev/null; then
  echo "warning: no /etc/subgid entry for $(id -un); rootless will use 1:1 mapping" >&2
fi

echo "rootless verification checks passed"
