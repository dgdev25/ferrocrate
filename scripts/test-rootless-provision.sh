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

printf 'ID=rocky\nID_LIKE="rhel fedora"\n' >"$tmp/rocky-release"
PATH="$tmp/empty-bin" \
  /bin/bash "$script" --os-release "$tmp/rocky-release" >"$tmp/rocky-output"
/usr/bin/grep -q '^rootless.provision.package_manager=dnf$' "$tmp/rocky-output"
/usr/bin/grep -q '^rootless.provision.packages=shadow-utils slirp4netns bubblewrap$' "$tmp/rocky-output"

printf 'ID=arch\n' >"$tmp/arch-release"
PATH="$tmp/empty-bin" \
  /bin/bash "$script" --os-release "$tmp/arch-release" --no-update >"$tmp/arch-output"
/usr/bin/grep -q '^rootless.provision.package_manager=pacman$' "$tmp/arch-output"
/usr/bin/grep -q '^rootless.provision.packages=shadow slirp4netns bubblewrap$' "$tmp/arch-output"
/usr/bin/grep -q '^rootless.provision.command=pacman --needed --noconfirm -S shadow slirp4netns bubblewrap ' "$tmp/arch-output"

# `--apply` must reject an unprivileged caller before invoking a package
# manager. The fake manager writes a marker if reached; the marker must remain
# absent after the fail-closed check.
fake_bin="$tmp/fake-bin"
mkdir -p "$fake_bin"
cat >"$fake_bin/apt-get" <<'EOF'
#!/usr/bin/env bash
touch "${FERROCRATE_PROVISION_MARKER:?}"
EOF
chmod 0755 "$fake_bin/apt-get"
if (( EUID == 0 )); then
  echo "rootless provision: unprivileged --apply check skipped under root"
else
  if PATH="$fake_bin:$tmp/empty-bin" FERROCRATE_PROVISION_MARKER="$tmp/package-manager-ran" \
    /bin/bash "$script" --os-release "$tmp/os-release" --apply >"$tmp/apply-output" 2>"$tmp/apply-stderr"; then
    echo "unprivileged --apply unexpectedly succeeded" >&2
    exit 1
  fi
  /usr/bin/grep -q -- '--apply requires root' "$tmp/apply-stderr"
  test ! -e "$tmp/package-manager-ran"
fi

if PATH="$tmp/empty-bin" /bin/bash "$script" --os-release "$tmp/os-release" --package-manager unsupported >"$tmp/invalid" 2>&1; then
  echo "unsupported package manager unexpectedly succeeded" >&2
  exit 1
fi

echo "rootless provision regression passed"
