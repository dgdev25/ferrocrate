#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
script="$repo_root/scripts/rootless-provision.sh"
tmp="$(mktemp -d /tmp/ferrocrate-rootless-provision.XXXXXX)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/empty-bin"

printf 'ID=ubuntu\nID_LIKE=debian\n' >"$tmp/os-release"
PATH="$tmp/empty-bin" \
  /bin/bash "$script" --os-release "$tmp/os-release" >"$tmp/output" 2>"$tmp/stderr"
/usr/bin/grep -q '^rootless.provision.package_manager=apt-get$' "$tmp/output"
/usr/bin/grep -q '^rootless.provision.packages=uidmap slirp4netns bubblewrap$' "$tmp/output"
/usr/bin/grep -q '^rootless.provision.result=dry-run$' "$tmp/output"
/usr/bin/grep -q 'rerun with --apply under sudo' "$tmp/stderr"

printf 'ID=fedora\n' >"$tmp/fedora-release"
PATH="$tmp/empty-bin" \
  /bin/bash "$script" --os-release "$tmp/fedora-release" --package-manager dnf >"$tmp/fedora-output"
/usr/bin/grep -q '^rootless.provision.package_manager=dnf$' "$tmp/fedora-output"
/usr/bin/grep -q '^rootless.provision.packages=shadow-utils slirp4netns bubblewrap$' "$tmp/fedora-output"

if PATH="$tmp/empty-bin" /bin/bash "$script" --os-release "$tmp/os-release" --package-manager unsupported >"$tmp/invalid" 2>&1; then
  echo "unsupported package manager unexpectedly succeeded" >&2
  exit 1
fi

echo "rootless provision regression passed"
