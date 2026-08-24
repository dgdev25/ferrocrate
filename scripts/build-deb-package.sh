#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
version=""
architecture=""
binary=""
output_dir="dist/release"

usage() {
  echo "Usage: build-deb-package.sh --version VERSION --architecture ARCH --binary PATH [--output-dir DIR]"
}

while (( $# )); do
  case "$1" in
    --version) version="${2:-}"; shift 2 ;;
    --architecture) architecture="${2:-}"; shift 2 ;;
    --binary) binary="${2:-}"; shift 2 ;;
    --output-dir) output_dir="${2:-}"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "build-deb-package: unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)([-+~][0-9A-Za-z.+~-]+)?$ ]] || {
  echo "build-deb-package: --version must be a Debian-compatible semantic version" >&2
  exit 2
}
[[ "$architecture" =~ ^[a-z0-9][a-z0-9-]*$ ]] || {
  echo "build-deb-package: --architecture is required" >&2
  exit 2
}
[[ -f "$binary" && -x "$binary" ]] || {
  echo "build-deb-package: --binary must name an executable regular file" >&2
  exit 2
}
command -v dpkg-deb >/dev/null 2>&1 || {
  echo "build-deb-package: dpkg-deb is required" >&2
  exit 1
}

stage="$(mktemp -d /tmp/ferrocrate-deb.XXXXXX)"
trap 'rm -rf "$stage"' EXIT

install -d -m 0755 \
  "$stage/DEBIAN" \
  "$stage/etc/apparmor.d" \
  "$stage/etc/systemd/system" \
  "$stage/usr/local/bin"
install -m 0755 "$binary" "$stage/usr/local/bin/ferrocrate"
install -m 0644 \
  "$repo_root/packaging/systemd/ferrocrate.service" \
  "$stage/etc/systemd/system/ferrocrate.service"
install -m 0644 \
  "$repo_root/packaging/apparmor/usr.local.bin.ferrocrate" \
  "$stage/etc/apparmor.d/usr.local.bin.ferrocrate"
install -m 0755 "$repo_root/packaging/debian/postinst" "$stage/DEBIAN/postinst"
sed \
  -e "s/@VERSION@/$version/g" \
  -e "s/@ARCHITECTURE@/$architecture/g" \
  "$repo_root/packaging/debian/control.in" >"$stage/DEBIAN/control"

find "$stage" -exec touch -h -d "@${SOURCE_DATE_EPOCH:-0}" {} +
mkdir -p "$output_dir"
package="$output_dir/ferrocrate_${version}_${architecture}.deb"
dpkg-deb --build --root-owner-group "$stage" "$package" >/dev/null
echo "created Debian package: $package"
