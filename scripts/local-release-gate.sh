#!/usr/bin/env bash
set -euo pipefail

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/.." && pwd)}"
version="${FERROCRATE_RELEASE_VERSION:-v0.1.0}"
artifact_dir="${FERROCRATE_RELEASE_ARTIFACT_DIR:-$repo_root/target/release-artifacts}"
skip_workspace=0
skip_format=0

usage() {
  cat <<'USAGE'
Usage: local-release-gate.sh [options]

Runs the reproducible, non-network release gate used when hosted CI is absent.

Options:
  --version <tag>       Semver release tag (default: FERROCRATE_RELEASE_VERSION or v0.1.0)
  --artifact-dir <dir>  Output directory for the verified archive
  --skip-workspace      Skip the serialized workspace test (for fast packaging checks)
  --skip-format         Skip formatting check (for an explicitly documented legacy baseline)
  -h, --help            Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) version="${2:?missing version}"; shift 2 ;;
    --artifact-dir) artifact_dir="${2:?missing artifact directory}"; shift 2 ;;
    --skip-workspace) skip_workspace=1; shift ;;
    --skip-format) skip_format=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

cd "$repo_root"
if (( ! skip_format )); then
  echo "[gate] cargo fmt --check"
  cargo fmt --all -- --check
else
  echo "[gate] cargo fmt --check (SKIPPED by request)"
fi

if (( ! skip_workspace )); then
  echo "[gate] serialized all-features workspace tests"
  cargo test --workspace --all-features --offline -- --test-threads=1
fi

echo "[gate] release-readiness and compatibility checks"
bash scripts/verify-release-readiness.sh

echo "[gate] public release build and channel verification"
bash scripts/build-release-artifacts.sh \
  --version "$version" --channel public --output-dir "$artifact_dir"
bash scripts/verify-release-channel-artifacts.sh \
  --channel public --version "$version" --artifact-dir "$artifact_dir"

echo "local release gate passed (version=$version)"
