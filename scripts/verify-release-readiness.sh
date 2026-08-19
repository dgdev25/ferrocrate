#!/usr/bin/env bash
set -euo pipefail

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/.." && pwd)}"
cd "$repo_root"

echo "[release] validating host-matrix manifest and qualified evidence"
bash scripts/verify-host-matrix-evidence.sh

echo "[release] validating Docker API contract"
cargo test -p ferro-cli --test api_compat_matrix --offline -- --nocapture

echo "[release] validating CRI socket and lifecycle contract"
cargo test -p ferro-cri --test socket_integration --offline -- --test-threads=1

echo "[release] validating security enforcement tests"
cargo test -p ferro-core --test security_tests --offline -- --nocapture
bash scripts/verify-mac-policy.sh target/release-readiness/mac-policy.txt
cargo test -p ferro-net --offline --lib security_monitor -- --test-threads=1
if [[ "$(id -u)" == 0 ]] && command -v aa-status >/dev/null 2>&1 \
  && aa-status --enabled >/dev/null 2>&1; then
  echo "[release] validating AppArmor allow/deny enforcement"
  bash scripts/test-apparmor-enforcement.sh
else
  echo "[release] AppArmor enforcement fixture skipped (requires root and enabled AppArmor)"
fi

echo "[release] recording rootless prerequisite diagnostics"
mkdir -p target/release-readiness
FERROCRATE_ROOTLESS_STRICT=0 bash scripts/verify-rootless.sh \
  >target/release-readiness/rootless-prerequisites.txt 2>&1 || true

echo "[release] collecting compatibility evidence"
bash scripts/compat-evidence.sh
bash scripts/test-check-linux-binary-compat.sh

echo "[release] readiness checks passed"
