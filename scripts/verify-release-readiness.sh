#!/usr/bin/env bash
set -euo pipefail

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/.." && pwd)}"
cd "$repo_root"

# The candidate contract selects required host rows. Missing capabilities are
# failures by default; an intentionally narrower check must name its scope.
required="${FERROCRATE_READINESS_REQUIRED:-rootful,apparmor,rootless}"
IFS=',' read -ra required_rows <<< "$required"
[[ -n "$required" ]] || { echo "empty readiness scope" >&2; exit 2; }
for row in "${required_rows[@]}"; do
  case "$row" in rootful|apparmor|rootless|none) ;; *) echo "unknown readiness row: $row" >&2; exit 2 ;; esac
done
[[ "$required" != *none* || "$required" == none ]] || { echo "none cannot be combined with required rows" >&2; exit 2; }
is_required() { [[ ",$required," == *",$1,"* ]]; }
missing_required=0
record_unavailable() {
  if is_required "$1"; then
    echo "[release] $1=blocked: $2" >&2
    missing_required=1
  else
    echo "[release] $1=not-required: $2"
  fi
}

if [[ -f docs/evidence/host-matrix/rows.tsv ]]; then
  echo "[release] validating private historical host-matrix inventory (not candidate qualification)"
  bash scripts/verify-host-matrix-evidence.sh
else
  echo "[release] historical host-matrix inventory not present in public checkout"
fi

echo "[release] validating Docker API contract"
cargo test -p ferro-cli --test api_compat_matrix --offline -- --nocapture

echo "[release] validating CRI socket and lifecycle contract"
cargo test -p ferro-cri --test socket_integration --offline -- --test-threads=1
if [[ "$(id -u)" == 0 ]]; then
  echo "[release] validating rootful CRI crash recovery"
  bash scripts/test-cri-rootful-recovery.sh
else
  record_unavailable rootful "requires root"
fi

echo "[release] validating security enforcement tests"
cargo test -p ferro-core --test security_tests --offline -- --nocapture
bash scripts/verify-mac-policy.sh target/release-readiness/mac-policy.txt
cargo test -p ferro-net --offline --lib security_monitor -- --test-threads=1
if [[ "$(id -u)" == 0 ]] && command -v aa-status >/dev/null 2>&1 \
  && aa-status --enabled >/dev/null 2>&1; then
  echo "[release] validating AppArmor allow/deny enforcement"
  bash scripts/test-apparmor-enforcement.sh
else
  record_unavailable apparmor "requires root and enabled AppArmor"
fi

echo "[release] recording rootless prerequisite diagnostics"
mkdir -p target/release-readiness
run_rootless_diagnostics() {
  if [[ "$(id -u)" != 0 ]]; then
    FERROCRATE_ROOTLESS_STRICT=1 bash scripts/verify-rootless.sh --strict
    return
  fi
  local test_user="${FERROCRATE_ROOTLESS_TEST_USER:-}" test_uid test_home
  if [[ -z "$test_user" ]]; then
    echo "rootful runner requires FERROCRATE_ROOTLESS_TEST_USER for unprivileged diagnostics" >&2
    return 77
  fi
  test_uid="$(id -u "$test_user" 2>/dev/null)" || return 77
  if [[ "$test_uid" == 0 || "$test_user" == root ]]; then
    echo "FERROCRATE_ROOTLESS_TEST_USER must identify an unprivileged account" >&2
    return 77
  fi
  command -v runuser >/dev/null 2>&1 || {
    echo "rootless diagnostics require runuser on the privileged qualification host" >&2
    return 77
  }
  test_home="$(getent passwd "$test_user" | cut -d: -f6)"
  [[ -n "$test_home" ]] || return 77
  runuser -u "$test_user" -- env HOME="$test_home" USER="$test_user" LOGNAME="$test_user" \
    FERROCRATE_ROOTLESS_STRICT=1 bash "$repo_root/scripts/verify-rootless.sh" --strict
}
if run_rootless_diagnostics \
  >target/release-readiness/rootless-prerequisites.txt 2>&1; then
  echo "[release] rootless prerequisites=pass (workload qualification is separate)"
else
  record_unavailable rootless "strict unprivileged prerequisites failed; root runners require FERROCRATE_ROOTLESS_TEST_USER; see target/release-readiness/rootless-prerequisites.txt"
fi

echo "[release] collecting compatibility evidence"
bash scripts/compat-evidence.sh
bash scripts/test-check-linux-binary-compat.sh

(( missing_required == 0 )) || { echo "[release] required host readiness is incomplete" >&2; exit 1; }
echo "[release] checks passed for declared host scope: $required; this is not full release qualification"
