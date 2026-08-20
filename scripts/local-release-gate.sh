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

echo "[gate] rootless installer/uninstall lifecycle checks"
bash -n scripts/rootless-install.sh scripts/test-rootless-install.sh \
  scripts/uninstall.sh scripts/test-uninstall.sh \
  scripts/install.sh scripts/test-install-rollback.sh \
  scripts/test-rootless-subid-diagnostics.sh \
  scripts/test-reliability-matrix-preflight.sh \
  scripts/perf/check-docker-comparison.sh scripts/perf/test-check-docker-comparison.sh \
  scripts/perf/docker-image-lifecycle-comparison.sh \
  scripts/perf/docker-volume-io-comparison.sh \
  scripts/test-state-migrations.sh \
  scripts/test-default-dependency-graph.sh \
  scripts/test-selinux-enforcement.sh \
  scripts/next-release-version.sh scripts/test-next-release-version.sh \
  scripts/generate-release-index.sh scripts/test-generate-release-index.sh \
  scripts/perf/check-benchmark-register.sh scripts/perf/test-check-benchmark-register.sh \
  scripts/perf/test-update-benchmark-register.sh \
  scripts/verify-indie-release-plan.sh \
  scripts/test-docker-cli-compat.sh \
  scripts/e2e-cli.sh scripts/test-e2e-cli-backend.sh
bash scripts/verify-indie-release-plan.sh
if command -v docker >/dev/null 2>&1; then
  # A release gate must never turn a present Docker installation into a stale
  # binary skip. The smoke helper rebuilds the default release CLI when its
  # source is newer, then runs in strict mode so failures remain visible.
  FERROCRATE_DOCKER_CLI_REQUIRED=1 \
    FERROCRATE_DOCKER_CLI_REBUILD_STALE=1 \
    bash scripts/test-docker-cli-compat.sh
else
  bash scripts/test-docker-cli-compat.sh
fi
bash scripts/test-rootless-install.sh
bash scripts/test-rootless-subid-diagnostics.sh
bash scripts/test-reliability-matrix-preflight.sh
bash scripts/test-uninstall.sh
bash scripts/test-install-rollback.sh
bash scripts/test-state-migrations.sh
bash scripts/test-default-dependency-graph.sh
bash scripts/test-rootless-cri-oci.sh
bash scripts/test-e2e-cli-backend.sh
bash scripts/perf/test-check-docker-comparison.sh
bash scripts/perf/test-check-benchmark-register.sh
bash scripts/perf/test-update-benchmark-register.sh
bash scripts/test-generate-changelog.sh
bash scripts/test-next-release-version.sh
bash scripts/test-generate-release-index.sh
bash scripts/test-shell-out-audit.sh

if (( ! skip_workspace )); then
  echo "[gate] serialized all-features workspace tests"
  cargo test --workspace --all-features --offline -- --test-threads=1
fi

echo "[gate] release-readiness and compatibility checks"
cargo test -p ferro-core --offline registry::tests -- --test-threads=1
bash scripts/verify-release-readiness.sh

echo "[gate] public release build and channel verification"
bash scripts/test-release-provenance.sh
bash scripts/test-sign-binaries.sh
bash scripts/build-release-artifacts.sh \
  --version "$version" --channel public --output-dir "$artifact_dir"
bash scripts/verify-release-channel-artifacts.sh \
  --channel public --version "$version" --artifact-dir "$artifact_dir"

echo "local release gate passed (version=$version)"
