#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" == 0 ]]; then
  echo "run-rootless-delegated: run as the target non-root user, not root" >&2
  exit 77
fi
command -v systemd-run >/dev/null 2>&1 || {
  echo "run-rootless-delegated: systemd-run is unavailable; provide a caller-owned FERROCRATE_CGROUP_ROOT" >&2
  exit 77
}
if (($# == 0)); then
  echo "Usage: run-rootless-delegated.sh COMMAND [ARGUMENT ...]" >&2
  exit 2
fi

# `--scope` already waits for the caller's process. Do not add --wait or
# --pipe: systemd rejects those options in scope mode, and the resulting error
# otherwise looks like a cgroup-delegation failure.
exec systemd-run --user --scope -p Delegate=yes -- "$@"
