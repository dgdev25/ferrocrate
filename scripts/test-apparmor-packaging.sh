#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
profile="$repo_root/packaging/apparmor/usr.local.bin.ferrocrate"
postinst="$repo_root/packaging/debian/postinst"
builder="$repo_root/scripts/build-deb-package.sh"
tmp="$(mktemp -d /tmp/ferrocrate-apparmor-package.XXXXXX)"
trap 'rm -rf "$tmp"' EXIT

test -f "$profile"
grep -Fqx 'profile usr.local.bin.ferrocrate /usr/local/bin/ferrocrate flags=(unconfined) {' "$profile"
grep -Eq '^[[:space:]]+userns,$' "$profile"
grep -Fq '# Existing Linux capability access remains unchanged by the unconfined attachment.' "$profile"

if command -v apparmor_parser >/dev/null 2>&1; then
  apparmor_parser -QK "$profile"
fi

test -x "$postinst"
grep -Fq '/usr/sbin/apparmor_parser -r /etc/apparmor.d/usr.local.bin.ferrocrate' "$postinst"

printf '#!/bin/sh\nexit 0\n' >"$tmp/ferrocrate"
chmod 0755 "$tmp/ferrocrate"
bash "$builder" \
  --version 0.1.0 \
  --architecture amd64 \
  --binary "$tmp/ferrocrate" \
  --output-dir "$tmp/out"

deb="$tmp/out/ferrocrate_0.1.0_amd64.deb"
test -f "$deb"
dpkg-deb --contents "$deb" >"$tmp/contents"
grep -Eq '\./usr/local/bin/ferrocrate$' "$tmp/contents"
grep -Eq '\./etc/systemd/system/ferrocrate.service$' "$tmp/contents"
grep -Eq '\./etc/apparmor.d/usr.local.bin.ferrocrate$' "$tmp/contents"

mkdir "$tmp/control"
dpkg-deb --control "$deb" "$tmp/control"
grep -Fq 'Package: ferrocrate' "$tmp/control/control"
grep -Fq '/usr/sbin/apparmor_parser -r /etc/apparmor.d/usr.local.bin.ferrocrate' "$tmp/control/postinst"

echo "AppArmor Debian packaging regression passed"
