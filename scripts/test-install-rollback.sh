#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname -- "$0")/.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'find "$tmp_dir" -depth -delete' EXIT

# Source the installer without contacting the release service.  The production
# entrypoint remains unchanged; the guard in install.sh makes its transaction
# helper directly fixtureable.
# shellcheck source=scripts/install.sh
source "$repo_root/scripts/install.sh"

install_dir="$tmp_dir/bin"
mkdir -p "$install_dir"
printf 'previous\n' >"$install_dir/ferrocrate"

mkdir -p "$tmp_dir/v2/ferrocrate"
printf 'updated\n' >"$tmp_dir/v2/ferrocrate/ferrocrate"
printf 'security-object-v2\n' >"$tmp_dir/v2/ferrocrate/ferro-security.o"
tar -czf "$tmp_dir/v2.tar.gz" -C "$tmp_dir/v2" ferrocrate
install_linux_release "$tmp_dir/v2.tar.gz" "$install_dir"
test "$(cat "$install_dir/ferrocrate")" = updated
test "$(cat "$install_dir/ferro-security.o")" = security-object-v2
test ! -e "$install_dir/.ferrocrate.previous"

# A malformed archive must leave the already-installed version untouched.
mkdir -p "$tmp_dir/bad/other"
printf 'not an installer\n' >"$tmp_dir/bad/other/file"
tar -czf "$tmp_dir/bad.tar.gz" -C "$tmp_dir/bad" other
if install_linux_release "$tmp_dir/bad.tar.gz" "$install_dir"; then
  echo "malformed release unexpectedly installed" >&2
  exit 1
fi
test "$(cat "$install_dir/ferrocrate")" = updated
test "$(cat "$install_dir/ferro-security.o")" = security-object-v2
test ! -e "$install_dir/.ferrocrate.previous"

# Exercise the same checksum and provenance verification used by the network
# installer, but against a deterministic local release fixture.
release_root="$tmp_dir/releases"
download_dir="$tmp_dir/download"
version="v1.2.3"
release_dir="$release_root/$version"
release_archive="$release_dir/ferrocrate-${version}-linux-x86_64.tar.gz"
mkdir -p "$release_dir"
cp "$tmp_dir/v2.tar.gz" "$release_archive"
archive_digest="$(sha256sum "$release_archive" | awk '{print $1}')"
printf '%s  %s\n' "$archive_digest" "$(basename "$release_archive")" \
  >"$release_dir/ferrocrate-${version}-checksums.txt"
python3 - "$release_dir/ferrocrate-${version}-linux-x86_64.tar.gz.provenance.json" "$version" "$archive_digest" <<'PY'
import json
import sys
from pathlib import Path

Path(sys.argv[1]).write_text(
    json.dumps(
        {
            "schema": "ferrocrate-release-provenance-v1",
            "version": sys.argv[2],
            "archive": f"ferrocrate-{sys.argv[2]}-linux-x86_64.tar.gz",
            "sha256": sys.argv[3],
        },
        sort_keys=True,
    ),
    encoding="utf-8",
)
PY
GITHUB_RELEASE_BASE="file://$release_root" \
  FERROCRATE_VERSION="$version" \
  download_linux_release x86_64 "$version" "$download_dir" \
  >"$tmp_dir/downloaded-path.txt"
test -f "$(tail -n 1 "$tmp_dir/downloaded-path.txt")"

# The installer must reject a checksum manifest that is ambiguous or points
# outside the downloaded artifact name.
printf '%s  %s\n%s  ../outside.tar.gz\n' "$archive_digest" "$(basename "$release_archive")" \
  "$archive_digest" >"$release_dir/ferrocrate-${version}-checksums.txt"
if bash -c '
  source "$1"
  GITHUB_RELEASE_BASE="$2" download_linux_release x86_64 "$3" "$4"
' _ "$repo_root/scripts/install.sh" "file://$release_root" "$version" \
  "$tmp_dir/ambiguous-download" >/dev/null 2>&1; then
  echo "ambiguous checksum manifest unexpectedly verified" >&2
  exit 1
fi
printf '%s  %s\n' "$archive_digest" "$(basename "$release_archive")" \
  >"$release_dir/ferrocrate-${version}-checksums.txt"

# Missing checksums are not an acceptable release fallback.
mv "$release_dir/ferrocrate-${version}-checksums.txt" "$release_dir/checksums.saved"
if bash -c '
  source "$1"
  GITHUB_RELEASE_BASE="$2" download_linux_release x86_64 "$3" "$4"
' _ "$repo_root/scripts/install.sh" "file://$release_root" "$version" \
  "$tmp_dir/missing-checksum-download" >/dev/null 2>&1; then
  echo "missing checksum manifest unexpectedly verified" >&2
  exit 1
fi
mv "$release_dir/checksums.saved" "$release_dir/ferrocrate-${version}-checksums.txt"

# A changed archive must fail closed even when the release has a provenance
# document, preventing an attacker from swapping bytes after publication.
printf 'tampered\n' >>"$release_archive"
if bash -c '
  source "$1"
  GITHUB_RELEASE_BASE="$2" download_linux_release x86_64 "$3" "$4"
' _ "$repo_root/scripts/install.sh" "file://$release_root" "$version" \
  "$tmp_dir/tampered-download" >"$tmp_dir/tampered-output.txt" 2>&1; then
  echo "tampered release unexpectedly verified" >&2
  exit 1
fi
grep -q 'Release checksum verification failed\|checksum' "$tmp_dir/tampered-output.txt"

echo "installer upgrade/rollback regression checks passed"
