#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'SELinux enforcement fixture failed: %s\n' "$*" >&2
  exit 1
}

[[ "$(uname -s)" == "Linux" ]] || fail "Linux is required"
[[ "${EUID}" -eq 0 ]] || fail "run as root"
command -v getenforce >/dev/null 2>&1 || fail "getenforce is required"
command -v runcon >/dev/null 2>&1 || fail "runcon is required"

state="$(getenforce 2>/dev/null || true)"
[[ "$state" == "Enforcing" ]] || fail "SELinux must be Enforcing (reported: ${state:-unknown})"

selinux_type="${FERROCRATE_SELINUX_TYPE:-container_t}"
runcon -t "$selinux_type" -- true \
  || fail "allowed command failed under SELinux type ${selinux_type}"

if runcon -t "$selinux_type" -- sh -c 'cat /etc/shadow >/dev/null' 2>/dev/null; then
  fail "SELinux type ${selinux_type} unexpectedly read /etc/shadow"
fi

printf 'SELinux enforcement fixture passed: type=%s, allowed=true, shadow-denied=true\n' \
  "$selinux_type"
