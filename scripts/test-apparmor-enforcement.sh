#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
profile="$repo_root/scripts/fixtures/ferrocrate-apparmor-test.profile"

for command_name in apparmor_parser aa-exec; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "AppArmor enforcement fixture requires $command_name" >&2
    exit 77
  }
done
if [[ "$(id -u)" != 0 ]]; then
  echo "AppArmor enforcement fixture requires root" >&2
  exit 77
fi
if ! aa-status --enabled >/dev/null 2>&1; then
  echo "AppArmor is not enabled" >&2
  exit 77
fi

loaded=0
cleanup() {
  if (( loaded )); then
    apparmor_parser -R "$profile" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

apparmor_parser -r "$profile"
loaded=1

aa-exec -p ferrocrate-security-test -- /usr/bin/true
if aa-exec -p ferrocrate-security-test -- /bin/sh -c 'cat /etc/shadow >/dev/null 2>&1'; then
  echo "AppArmor denial did not fire for /etc/shadow" >&2
  exit 1
fi

echo "AppArmor enforcement fixture passed: allow and denial paths verified"
