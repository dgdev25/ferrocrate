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

postinst_fixture="$tmp/postinst"
fixture_parser="$tmp/bin/apparmor_parser"
fixture_profile="$tmp/etc/apparmor.d/usr.local.bin.ferrocrate"
fixture_enabled="$tmp/sys/module/apparmor/parameters/enabled"
parser_log="$tmp/parser.log"
mkdir -p "$(dirname "$fixture_parser")" "$(dirname "$fixture_profile")" "$(dirname "$fixture_enabled")"
cp "$profile" "$fixture_profile"
printf 'Y\n' >"$fixture_enabled"
sed \
  -e "s|/usr/sbin/apparmor_parser|$fixture_parser|g" \
  -e "s|/etc/apparmor.d/usr.local.bin.ferrocrate|$fixture_profile|g" \
  -e "s|/sys/module/apparmor/parameters/enabled|$fixture_enabled|g" \
  "$postinst" >"$postinst_fixture"
chmod 0755 "$postinst_fixture"

cat >"$fixture_parser" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "--version" ]]; then
  printf 'AppArmor parser version %s\n' "$PARSER_VERSION"
  exit 0
fi
printf '%s\n' "$*" >>"$PARSER_LOG"
major="${PARSER_VERSION%%.*}"
if (( major < 4 )); then
  echo 'unsupported userns rule' >&2
  exit 91
fi
EOF
chmod 0755 "$fixture_parser"
printf '#!/bin/sh\nexit 0\n' >"$tmp/bin/systemctl"
chmod 0755 "$tmp/bin/systemctl"

: >"$parser_log"
PATH="$tmp/bin:$PATH" PARSER_VERSION=3.0.8 PARSER_LOG="$parser_log" "$postinst_fixture" configure
test ! -s "$parser_log"

: >"$parser_log"
PATH="$tmp/bin:$PATH" PARSER_VERSION=4.0.0 PARSER_LOG="$parser_log" "$postinst_fixture" configure
grep -Fqx -- "-r $fixture_profile" "$parser_log"

echo "AppArmor Debian packaging regression passed"
