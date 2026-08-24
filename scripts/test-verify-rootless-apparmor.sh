#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d /tmp/ferrocrate-rootless-apparmor-diagnostic.XXXXXX)"
trap 'rm -rf -- "$tmp"' EXIT

profile="$tmp/usr.local.bin.ferrocrate"
profiles="$tmp/profiles"
restriction="$tmp/apparmor_restrict_unprivileged_userns"
enabled="$tmp/enabled"
helpers="$tmp/helpers"

printf 'profile fixture\n' >"$profile"
printf 'usr.local.bin.ferrocrate (unconfined)\n' >"$profiles"
printf '1\n' >"$restriction"
printf 'Y\n' >"$enabled"
mkdir "$helpers"
printf '#!/bin/sh\necho forced helper denial >&2\nexit 1\n' >"$helpers/unshare"
printf '#!/bin/sh\nexit 0\n' >"$helpers/bwrap"
chmod 0755 "$helpers/unshare" "$helpers/bwrap"

output="$tmp/output"
FERROCRATE_APPARMOR_PROFILE_PATH="$profile" \
FERROCRATE_APPARMOR_PROFILES_PATH="$profiles" \
FERROCRATE_APPARMOR_USERNS_PATH="$restriction" \
FERROCRATE_APPARMOR_ENABLED_PATH="$enabled" \
PATH="$helpers:$PATH" \
  bash "$repo_root/scripts/verify-rootless.sh" >"$output" 2>&1

grep -Fqx 'rootless.apparmor=enabled' "$output"
grep -Fqx 'rootless.apparmor_restrict_unprivileged_userns=1' "$output"
grep -Fqx "rootless.apparmor_profile=loaded name=usr.local.bin.ferrocrate path=$profile" "$output"
grep -Fqx 'rootless.apparmor_note=FerroCrate profile grants userns while the host-wide restriction remains active' "$output"
grep -Fqx 'rootless.bwrap_nested_reason=AppArmor restricts this unprofiled helper probe (kernel.apparmor_restrict_unprivileged_userns=1); FerroCrate profile status is reported below' "$output"

: >"$profiles"
FERROCRATE_APPARMOR_PROFILE_PATH="$profile" \
FERROCRATE_APPARMOR_PROFILES_PATH="$profiles" \
FERROCRATE_APPARMOR_USERNS_PATH="$restriction" \
FERROCRATE_APPARMOR_ENABLED_PATH="$enabled" \
PATH="$helpers:$PATH" \
  bash "$repo_root/scripts/verify-rootless.sh" >"$output" 2>&1

grep -Fqx "rootless.apparmor_profile=installed-not-loaded name=usr.local.bin.ferrocrate path=$profile" "$output"
grep -Fqx "rootless.apparmor_remedy=sudo apparmor_parser -r $profile" "$output"

echo "rootless AppArmor diagnostic regression passed"
