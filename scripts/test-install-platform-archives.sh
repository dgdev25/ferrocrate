#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/install.sh
source "$repo_root/scripts/install.sh"

tmp_dir="$(mktemp -d)"
trap 'find "$tmp_dir" -depth -delete' EXIT
release_root="$tmp_dir/releases"
mkdir -p "$release_root"

make_release() {
  local os="$1" version="$2" binary_name="$3" archive release_dir package_dir digest
  archive="$(platform_archive_name "$os" x86_64 "$version")"
  release_dir="$release_root/$version"
  package_dir="$tmp_dir/package-$os"
  mkdir -p "$package_dir/ferrocrate" "$release_dir"
  printf '%s-platform\n' "$os" >"$package_dir/ferrocrate/$binary_name"
  if [[ "$archive" == *.tar.gz ]]; then
    tar -czf "$release_dir/$archive" -C "$package_dir" ferrocrate
  else
    (cd "$package_dir" && zip -q -X -r "$release_dir/$archive" ferrocrate)
  fi
  digest="$(sha256sum "$release_dir/$archive" | awk '{print $1}')"
  printf '%s  %s\n' "$digest" "$archive" >"$release_dir/ferrocrate-${version}-checksums.txt"
  python3 - "$release_dir/$archive.provenance.json" "$version" "$archive" "$os" <<'PY'
import json
import sys
from pathlib import Path

Path(sys.argv[1]).write_text(json.dumps({
    "schema": "ferrocrate-release-provenance-v1",
    "version": sys.argv[2],
    "archive": sys.argv[3],
    "sha256": "PLACEHOLDER",
    "target_os": sys.argv[4],
    "target_arch": "x86_64",
    "target_libc": "gnu",
}, sort_keys=True) + "\n")
PY
  python3 - "$release_dir/$archive.provenance.json" "$release_dir/$archive" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

manifest = Path(sys.argv[1])
data = json.loads(manifest.read_text())
data["sha256"] = hashlib.sha256(Path(sys.argv[2]).read_bytes()).hexdigest()
manifest.write_text(json.dumps(data, sort_keys=True) + "\n")
PY
}

make_release macos v2.0.0 ferrocrate
make_release windows v2.0.1 ferrocrate.exe

for spec in "macos v2.0.0 ferrocrate" "windows v2.0.1 ferrocrate.exe"; do
  read -r os version binary_name <<<"$spec"
  GITHUB_RELEASE_BASE="file://$release_root"
  export GITHUB_RELEASE_BASE
  archive_path="$(download_platform_release "$os" x86_64 "$version" "$tmp_dir/download-$os")"
  install_dir="$tmp_dir/install-$os"
  install_platform_archive "$os" "$archive_path" "$install_dir"
  grep -Fxq "$os-platform" "$install_dir/$binary_name"
done

echo "platform archive installer regression passed"
