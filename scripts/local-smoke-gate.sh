#!/usr/bin/env bash
set -euo pipefail

# One-command bounded local smoke gate (local Docker-equivalence item 2).
# Validates: binary, rootless doctor, lifecycle, volumes, Compose, Docker API,
# and cleanup — in a single bounded invocation.
#
# This is the short per-change smoke path. The full milestone gate remains
# scripts/local-release-gate.sh.

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "${0}")/.." && pwd)}"
timeout_seconds="${FERROCRATE_SMOKE_GATE_TIMEOUT_SECONDS:-600}"

usage() {
  cat <<'USAGE'
Usage: local-smoke-gate.sh [options]

Runs the bounded local smoke gate: ferro-cli binary sanity, rootless
prerequisite doctor, then the e2e CLI corpus (lifecycle, volumes, Compose,
Docker API socket, cleanup) under a hard timeout.

Options:
  --timeout <seconds>   Hard wall-clock bound (default: FERROCRATE_SMOKE_GATE_TIMEOUT_SECONDS or 600)
  --strict-doctor       Fail when any rootless prerequisite is unavailable
                        (default: doctor runs informationally and only its own
                        errors fail the gate)
  -h, --help            Show this help
USAGE
}

strict_doctor=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --timeout) timeout_seconds="${2:?missing seconds}"; shift 2 ;;
    --strict-doctor) strict_doctor=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done
if ! [[ "${timeout_seconds}" =~ ^[1-9][0-9]*$ ]]; then
  echo "--timeout must be a positive integer" >&2
  exit 2
fi

cd "$repo_root"

echo "[smoke] 1/3 rootless prerequisite doctor"
doctor_args=()
if (( strict_doctor )); then
  doctor_args+=(--strict)
fi
# The doctor probes kernel/userspace prerequisites before any mutation; without
# --strict its findings are informational and a probe crash is the only failure.
doctor_status=0
doctor_output="$(timeout --foreground --kill-after=10s 60s \
  bash scripts/verify-rootless.sh "${doctor_args[@]}")" || doctor_status=$?
printf '%s\n' "$doctor_output"
if (( doctor_status != 0 )); then
  echo "[smoke] doctor failed with exit ${doctor_status}" >&2
  exit 1
fi

# An unprivileged caller on a host that denies nested user/network namespaces
# (for example Ubuntu's apparmor_restrict_unprivileged_userns policy) cannot
# run bridge workloads. Keep the smoke corpus on the documented fail-closed
# path (--network none / network_mode: none) instead of failing at the first
# run; rootful callers keep the bridge path.
if [[ "${EUID:-$(id -u)}" != 0 ]] &&
    grep -q '^rootless.bwrap_nested=missing$' <<<"$doctor_output"; then
  echo "[smoke] host denies nested user namespaces: using network_mode=none fallback"
  export FERROCRATE_E2E_NETWORK_MODE=none
  export FERROCRATE_ROOTLESS_NETNS=1
fi

echo "[smoke] 2/3 e2e CLI corpus (lifecycle, volumes, Compose, API, cleanup)"
timeout --foreground --kill-after=15s "${timeout_seconds}s" \
  bash scripts/e2e-cli.sh

echo "[smoke] 3/3 no-leftover process check"
if pgrep -x ferro-cli >/dev/null 2>&1; then
  echo "ferro-cli processes still running after smoke gate:" >&2
  pgrep -ax ferro-cli >&2
  exit 1
fi

echo "local smoke gate passed (timeout=${timeout_seconds}s, strict-doctor=${strict_doctor})"
