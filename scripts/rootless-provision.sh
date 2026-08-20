#!/usr/bin/env bash
set -euo pipefail

# Provision only host packages required by the rootless installer. This is a
# separate privileged operation; the installer never invokes a package manager
# or mutates /etc/subuid or /etc/subgid.
usage() {
  cat <<'EOF'
Usage: rootless-provision.sh [--apply] [--no-update]
       [--package-manager auto|apt|dnf|yum|pacman] [--os-release PATH]

Without --apply, print the exact package-manager command and make no changes.
--apply requires uid 0. Subordinate-ID policy is never edited automatically.
EOF
}

apply=0
update=1
manager=auto
os_release="${FERROCRATE_ROOTLESS_OS_RELEASE:-/etc/os-release}"
while (($#)); do
  case "$1" in
    --apply) apply=1; shift ;;
    --no-update) update=0; shift ;;
    --package-manager) manager="${2:?missing package manager}"; shift 2 ;;
    --os-release) os_release="${2:?missing os-release path}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "rootless-provision: unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ -r "$os_release" ]] || {
  echo "rootless-provision: cannot read os-release file: $os_release" >&2
  exit 1
}
# shellcheck disable=SC1090
. "$os_release"
os_id="${ID:-unknown}"
os_like="${ID_LIKE:-}"

missing=()
for helper in newuidmap newgidmap slirp4netns bwrap; do
  command -v "$helper" >/dev/null 2>&1 || missing+=("$helper")
done

echo "rootless.provision.os=$os_id"
echo "rootless.provision.missing=${missing[*]:-none}"
if ((${#missing[@]} == 0)); then
  echo "rootless.provision.result=already-satisfied"
  exit 0
fi

if [[ "$manager" == auto ]]; then
  case "$os_id $os_like" in
    *debian*|*ubuntu*) manager=apt ;;
    *fedora*|*rhel*|*centos*|*rocky*|*almalinux*) manager=dnf ;;
    *arch*) manager=pacman ;;
    *)
      echo "rootless-provision: unsupported distribution '$os_id' (ID_LIKE='$os_like'); pass --package-manager" >&2
      exit 77
      ;;
  esac
fi

case "$manager" in
  apt) package_manager=apt-get; packages=(uidmap slirp4netns bubblewrap) ;;
  dnf|yum) package_manager="$manager"; packages=(shadow-utils slirp4netns bubblewrap) ;;
  pacman) package_manager=pacman; packages=(shadow slirp4netns bubblewrap) ;;
  *)
    echo "rootless-provision: unsupported package manager '$manager'" >&2
    exit 2
    ;;
esac

command_line=("$package_manager")
if [[ "$manager" == pacman ]]; then
  command_line+=(--needed --noconfirm -S "${packages[@]}")
else
  if ((update)); then command_line+=(update); fi
  command_line+=(install -y "${packages[@]}")
fi
printf 'rootless.provision.package_manager=%s\n' "$package_manager"
printf 'rootless.provision.packages=%s\n' "${packages[*]}"
printf 'rootless.provision.command='
printf '%q ' "${command_line[@]}"
printf '\n'

if (( ! apply )); then
  echo "rootless.provision.result=dry-run"
  echo "rootless-provision: rerun with --apply under sudo to install these packages" >&2
  exit 0
fi
if [[ "$(id -u)" != 0 ]]; then
  echo "rootless-provision: --apply requires root; use sudo for this command" >&2
  exit 77
fi
command -v "$package_manager" >/dev/null 2>&1 || {
  echo "rootless-provision: package manager not found: $package_manager" >&2
  exit 1
}
"${command_line[@]}"

for helper in newuidmap newgidmap slirp4netns bwrap; do
  command -v "$helper" >/dev/null 2>&1 || {
    echo "rootless-provision: package install completed but helper is still missing: $helper" >&2
    exit 1
  }
done
echo "rootless.provision.result=pass"
