#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d /tmp/ferrocrate-apparmor-host-proof.XXXXXX)"
trap 'rm -rf -- "$tmp"' EXIT

fixture_root="$tmp/repo"
fixture_bin="$tmp/bin"
fixture_home="$tmp/home"
fixture_runtime="$tmp/runtime"
fixture_profile="$tmp/etc/apparmor.d/usr.local.bin.ferrocrate"
fixture_profiles="$tmp/sys/kernel/security/apparmor/profiles"
fixture_os_release="$tmp/etc/os-release"
fixture_cli="$tmp/usr/local/bin/ferrocrate"
fixture_package="$tmp/ferrocrate.deb"
mkdir -p \
  "$fixture_root/scripts" \
  "$fixture_bin" \
  "$fixture_home" \
  "$fixture_runtime" \
  "$(dirname -- "$fixture_profile")" \
  "$(dirname -- "$fixture_profiles")" \
  "$(dirname -- "$fixture_cli")"
printf 'fixture package\n' >"$fixture_package"
printf '# fixture profile\n' >"$fixture_profile"
printf 'usr.local.bin.ferrocrate (enforce)\n' >"$fixture_profiles"
printf 'PRETTY_NAME="Fixture Linux 1"\n' >"$fixture_os_release"
printf '#!/bin/sh\nexit 0\n' >"$fixture_cli"
chmod 0755 "$fixture_cli"

# Relocate only absolute host paths. The resulting script retains the real
# control flow while all privileged effects are served by fixture commands.
sed \
  -e "s|profile_path=\"/etc/apparmor.d/usr.local.bin.ferrocrate\"|profile_path=\"$fixture_profile\"|" \
  -e "s|proof_runtime=\"/run/user/\$proof_uid\"|proof_runtime=\"$fixture_runtime\"|" \
  -e "s|/sys/kernel/security/apparmor/profiles|$fixture_profiles|" \
  -e "s|/etc/os-release|$fixture_os_release|" \
  -e "s|/usr/local/bin/ferrocrate|$fixture_cli|g" \
  "$repo_root/scripts/verify-apparmor-rootless-host.sh" \
  >"$fixture_root/scripts/verify-apparmor-rootless-host.sh"
chmod 0755 "$fixture_root/scripts/verify-apparmor-rootless-host.sh"

cat >"$fixture_bin/id" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == -u && -n "${2:-}" ]]; then
  printf '1000\n'
elif [[ "${1:-}" == -u ]]; then
  printf '0\n'
else
  printf 'proof\n'
fi
EOF

cat >"$fixture_bin/getent" <<EOF
#!/usr/bin/env bash
printf 'proof:x:1000:1000::%s:/bin/bash\\n' '$fixture_home'
EOF

cat >"$fixture_bin/sysctl" <<'EOF'
#!/usr/bin/env bash
case "$*" in
  '-n kernel.apparmor_restrict_unprivileged_userns')
    cat "$PROOF_SYSCTL_STATE"
    ;;
  '-q -w kernel.apparmor_restrict_unprivileged_userns='*)
    value="${3#*=}"
    if [[ "${PROOF_CORRUPT_ACTIVE:-0}" == 1 && "$value" == 1 ]]; then
      value=0
    fi
    if [[ "${PROOF_CORRUPT_RESTORE:-0}" == 1 && "$value" == 0 ]]; then
      value=1
    fi
    printf '%s\n' "$value" >"$PROOF_SYSCTL_STATE"
    printf 'write=%s\n' "$value" >>"$PROOF_SYSCTL_LOG"
    ;;
  *)
    printf 'unexpected sysctl invocation: %s\n' "$*" >&2
    exit 98
    ;;
esac
EOF

cat >"$fixture_bin/dpkg" <<'EOF'
#!/usr/bin/env bash
printf 'dpkg %s\n' "$*" >>"$PROOF_COMMAND_LOG"
EOF

cat >"$fixture_bin/apparmor_parser" <<'EOF'
#!/usr/bin/env bash
printf 'apparmor_parser %s\n' "$*" >>"$PROOF_COMMAND_LOG"
EOF

cat >"$fixture_bin/runuser" <<'EOF'
#!/usr/bin/env bash
printf 'runuser %s\n' "$*" >>"$PROOF_COMMAND_LOG"
case "$*" in
  *'/scripts/verify-rootless.sh --strict')
    printf 'verify-rootless host proof must record unprofiled probes without strict mode\n' >&2
    exit 9
    ;;
  *'/scripts/verify-rootless.sh')
    printf 'rootless.userns_mount=missing\n'
    printf 'rootless.apparmor_profile=loaded name=usr.local.bin.ferrocrate\n'
    ;;
  *'/scripts/test-rootless-published-port.sh')
    if [[ "${PROOF_SIGNAL_PUBLISHED:-0}" == 1 ]]; then
      kill -TERM "$PPID"
      sleep 0.1
      exit 0
    fi
    [[ "${PROOF_FAIL_PUBLISHED:-0}" == 0 ]] || exit 23
    ;;
  *)
    printf 'unexpected runuser invocation: %s\n' "$*" >&2
    exit 97
    ;;
esac
EOF
chmod 0755 "$fixture_bin"/*

run_proof() {
  local output=$1
  shift
  env \
    PATH="$fixture_bin:$PATH" \
    SUDO_USER=proof \
    PROOF_SYSCTL_STATE="$tmp/sysctl-state" \
    PROOF_SYSCTL_LOG="$tmp/sysctl-log" \
    PROOF_COMMAND_LOG="$tmp/command-log" \
    "$@" \
    "$fixture_root/scripts/verify-apparmor-rootless-host.sh" "$fixture_package" \
    >"$output" 2>&1
}

printf '0\n' >"$tmp/sysctl-state"
: >"$tmp/sysctl-log"
: >"$tmp/command-log"
run_proof "$tmp/success.out"
grep -Fqx 'apparmor.proof.sysctl.initial=0' "$tmp/success.out"
grep -Fqx 'apparmor.proof.os=Fixture Linux 1' "$tmp/success.out"
grep -Fqx 'apparmor.proof.sysctl.active=1' "$tmp/success.out"
grep -Fqx "apparmor.proof.profile_parse=pass path=$fixture_profile" "$tmp/success.out"
grep -Fqx "apparmor.proof.profile=loaded name=usr.local.bin.ferrocrate path=$fixture_profile" "$tmp/success.out"
grep -Fqx 'apparmor.proof.sysctl.restored=0' "$tmp/success.out"
grep -Fqx 'apparmor.proof.result=pass' "$tmp/success.out"
grep -Fqx 'rootless.userns_mount=missing' "$tmp/success.out"
grep -Fqx 'apparmor.proof.verify_rootless=recorded' "$tmp/success.out"
if grep -Fqx 'apparmor.proof.verify_rootless=pass' "$tmp/success.out"; then
  echo 'host proof mislabeled the unprofiled diagnostic probe as a pass' >&2
  exit 1
fi
test "$(cat "$tmp/sysctl-state")" = 0
test "$(cat "$tmp/sysctl-log")" = $'write=1\nwrite=0'
grep -Fqx "dpkg -i $fixture_package" "$tmp/command-log"
grep -Fqx "apparmor_parser -r $fixture_profile" "$tmp/command-log"
verify_rootless_command="runuser -u proof -- env HOME=$fixture_home XDG_RUNTIME_DIR=$fixture_runtime FERROCRATE_NETWORK_CLI=$fixture_cli bash $fixture_root/scripts/verify-rootless.sh"
published_port_command="runuser -u proof -- env HOME=$fixture_home XDG_RUNTIME_DIR=$fixture_runtime FERROCRATE_NETWORK_CLI=$fixture_cli bash $fixture_root/scripts/test-rootless-published-port.sh"
grep -Fqx "$verify_rootless_command" "$tmp/command-log"
if grep -Fq 'verify-rootless.sh --strict' "$tmp/command-log"; then
  echo 'host proof incorrectly made unprofiled helper probes a strict gate' >&2
  exit 1
fi
grep -Fqx "$published_port_command" "$tmp/command-log"

printf '0\n' >"$tmp/sysctl-state"
: >"$tmp/sysctl-log"
: >"$tmp/command-log"
if run_proof "$tmp/active-mismatch.out" PROOF_CORRUPT_ACTIVE=1; then
  echo 'host proof unexpectedly passed without activating the restricted sysctl' >&2
  exit 1
fi
grep -Fqx 'AppArmor host proof could not activate kernel.apparmor_restrict_unprivileged_userns=1: actual=0' "$tmp/active-mismatch.out"
grep -Fqx 'apparmor.proof.sysctl.restored=0' "$tmp/active-mismatch.out"
if grep -q '^runuser ' "$tmp/command-log"; then
  echo 'host proof ran rootless fixtures without the restricted sysctl active' >&2
  exit 1
fi

printf '0\n' >"$tmp/sysctl-state"
: >"$tmp/sysctl-log"
: >"$tmp/command-log"
if run_proof "$tmp/failure.out" PROOF_FAIL_PUBLISHED=1; then
  echo 'host proof unexpectedly passed a failed published-port fixture' >&2
  exit 1
fi
grep -Fqx 'apparmor.proof.sysctl.restored=0' "$tmp/failure.out"
if grep -Fqx 'apparmor.proof.result=pass' "$tmp/failure.out"; then
  echo 'host proof recorded a pass after a failed published-port fixture' >&2
  exit 1
fi
test "$(cat "$tmp/sysctl-state")" = 0
test "$(cat "$tmp/sysctl-log")" = $'write=1\nwrite=0'

printf '0\n' >"$tmp/sysctl-state"
: >"$tmp/sysctl-log"
: >"$tmp/command-log"
set +e
run_proof "$tmp/signal.out" PROOF_SIGNAL_PUBLISHED=1
signal_status=$?
set -e
test "$signal_status" = 143
grep -Fqx 'apparmor.proof.sysctl.restored=0' "$tmp/signal.out"
if grep -Fqx 'apparmor.proof.result=pass' "$tmp/signal.out"; then
  echo 'host proof recorded a pass after termination' >&2
  exit 1
fi
test "$(cat "$tmp/sysctl-state")" = 0

printf '0\n' >"$tmp/sysctl-state"
: >"$tmp/sysctl-log"
: >"$tmp/command-log"
if run_proof "$tmp/restore-mismatch.out" PROOF_CORRUPT_RESTORE=1; then
  echo 'host proof unexpectedly passed a mismatched sysctl restoration' >&2
  exit 1
fi
grep -Fqx 'AppArmor host proof could not restore kernel.apparmor_restrict_unprivileged_userns: initial=0 actual=1' "$tmp/restore-mismatch.out"
if grep -Fqx 'apparmor.proof.result=pass' "$tmp/restore-mismatch.out"; then
  echo 'host proof recorded a pass after mismatched sysctl restoration' >&2
  exit 1
fi

echo 'AppArmor restricted-userns host-proof harness regression passed'
