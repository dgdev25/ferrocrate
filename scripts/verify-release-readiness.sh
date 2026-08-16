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

echo "[release] collecting compatibility evidence"
bash scripts/compat-evidence.sh

echo "[release] readiness checks passed"
