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

Runs the release contract on a qualified self-hosted runner. Dependency scans
may use the network. Full qualification requires FERROCRATE_CANDIDATE_EVIDENCE.

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
candidate_head="$(git rev-parse HEAD)"
if [[ -n "${GITHUB_SHA:-}" && "$candidate_head" != "$GITHUB_SHA" ]]; then
  echo "local release gate: checkout differs from GITHUB_SHA" >&2
  exit 1
fi

echo "[gate] release, evidence, and harness regression contracts"
python3 scripts/check-release-workflows.py
python3 scripts/test_release_workflow_contracts.py
python3 scripts/test_local_release_gate.py
python3 scripts/test_candidate_evidence.py
python3 scripts/test_readiness_scope.py
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s bench -p 'test_suite_*.py'
node --test scripts/release-artifacts.test.mjs
bash scripts/test-qualification-fault-matrix.sh
python3 scripts/check-advisory-exceptions.py

if (( ! skip_workspace && ! skip_format )); then
  : "${FERROCRATE_CANDIDATE_EVIDENCE:?full release gate requires a candidate evidence manifest; see docs/operations/candidate-evidence.md}"
  python3 scripts/check-candidate-evidence.py --manifest "$FERROCRATE_CANDIDATE_EVIDENCE" \
    --candidate "$candidate_head" --repo "$repo_root"
fi
# sudo commonly replaces PATH with a system-only value. Resolve the invoking
# operator's pinned Rust toolchain before the first Cargo step so privileged
# qualification fails with a useful prerequisite message instead of a shell
# lookup error.
if [[ -n "${FERROCRATE_CARGO:-}" && -x "${FERROCRATE_CARGO}" ]]; then
  cargo_bin="${FERROCRATE_CARGO}"
elif command -v cargo >/dev/null 2>&1; then
  cargo_bin="$(command -v cargo)"
else
  operator_home=""
  if [[ -n "${SUDO_USER:-}" ]] && command -v getent >/dev/null 2>&1; then
    operator_home="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
  fi
  if [[ -n "$operator_home" && -x "$operator_home/.cargo/bin/cargo" ]]; then
    export CARGO_HOME="${CARGO_HOME:-$operator_home/.cargo}"
    export RUSTUP_HOME="${RUSTUP_HOME:-$operator_home/.rustup}"
    export PATH="$operator_home/.cargo/bin:$PATH"
    cargo_bin="$operator_home/.cargo/bin/cargo"
  elif [[ -x $HOME/.cargo/bin/cargo ]]; then
    export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
    export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
    export PATH="$HOME/.cargo/bin:$PATH"
    cargo_bin=$HOME/.cargo/bin/cargo
  else
    echo "local release gate requires Cargo (set FERROCRATE_CARGO or expose the operator's Rustup toolchain)" >&2
    exit 2
  fi
fi
export FERROCRATE_CARGO="$cargo_bin"
export PATH="$(dirname "$cargo_bin"):$PATH"
echo "[gate] current Rust and frontend dependency policy"
"$cargo_bin" audit --deny warnings
npm audit --prefix apps/ferro-desktop-ui --audit-level=low
echo "[gate] frontend tests, types, lint and production build"
npm run --prefix apps/ferro-desktop-ui test
npm run --prefix apps/ferro-desktop-ui typecheck
npm run --prefix apps/ferro-desktop-ui lint
npm run --prefix apps/ferro-desktop-ui build
release_target="${CARGO_TARGET_DIR:-$repo_root/target}"
release_target_owned=0
if [[ -z "${CARGO_TARGET_DIR:-}" && "${EUID:-$(id -u)}" -eq 0 ]]; then
  # Never let a privileged release qualification write root-owned incremental
  # state into the checkout.  An explicit CARGO_TARGET_DIR remains an operator
  # choice for reproducible CI/build farms; otherwise keep the whole gate in a
  # bounded, disposable target tree.
  release_target="$(mktemp -d /tmp/ferrocrate-release-target.XXXXXX)"
  release_target_owned=1
  export CARGO_TARGET_DIR="$release_target"
  cleanup_release_target() {
    if (( release_target_owned )); then
      rm -rf -- "$release_target"
    fi
  }
  trap cleanup_release_target EXIT INT TERM
fi
if [[ "$release_target" != /* ]]; then
  release_target="$repo_root/$release_target"
fi
if (( ! skip_format )); then
  echo "[gate] cargo fmt --check"
  "$cargo_bin" fmt --all -- --check
else
  echo "[gate] cargo fmt --check (SKIPPED by request)"
fi

echo "[gate] rootless installer/uninstall lifecycle checks"
bash -n scripts/rootless-install.sh scripts/test-rootless-install.sh \
  scripts/rootless-provision.sh scripts/test-rootless-provision.sh \
  scripts/uninstall.sh scripts/test-uninstall.sh \
  scripts/install.sh scripts/test-install-rollback.sh \
  scripts/test-rootless-subid-diagnostics.sh \
  scripts/test-reliability-matrix-preflight.sh \
  scripts/perf/check-docker-comparison.sh scripts/perf/test-check-docker-comparison.sh \
  scripts/perf/docker-image-lifecycle-comparison.sh \
  scripts/perf/docker-volume-io-comparison.sh scripts/perf/docker-build-cache-comparison.sh \
  scripts/perf/docker-network-run-comparison.sh scripts/perf/docker-ipv6-comparison.sh \
  scripts/perf/docker-outbound-http-comparison.sh \
  scripts/perf/run-baseline.sh \
  scripts/perf/docker-volume-io-comparison.sh \
  scripts/test-state-migrations.sh \
  scripts/test-default-dependency-graph.sh \
  scripts/test-selinux-enforcement.sh \
  scripts/next-release-version.sh scripts/test-next-release-version.sh \
  scripts/generate-release-index.sh scripts/test-generate-release-index.sh \
  scripts/perf/check-benchmark-register.sh scripts/perf/test-check-benchmark-register.sh \
  scripts/perf/test-update-benchmark-register.sh \
  scripts/check-roadmap-progress.sh \
  scripts/verify-indie-release-plan.sh \
  scripts/test-docker-cli-compat.sh \
  scripts/e2e-cli.sh scripts/test-e2e-cli-backend.sh \
  scripts/test-real-app-compose.sh \
  scripts/local-smoke-gate.sh scripts/test-local-smoke-gate.sh \
  scripts/test-rootless-published-port.sh scripts/test-rootless-tty-container.sh \
  scripts/test-ebpf-networking.sh scripts/test-ebpf-networking-backend.sh \
  scripts/test-build-release-target-dir.sh scripts/test-cross-platform-release-targets.sh scripts/test-reproducible-release-artifacts.sh scripts/test-fixtures/cargo
bash scripts/verify-indie-release-plan.sh
if command -v docker >/dev/null 2>&1; then
  # A release gate must never turn a present Docker installation into a stale
  # binary skip. Build into the selected (possibly isolated) target directory
  # before invoking the smoke helper; the helper only auto-rebuilds the legacy
  # repository target path.
  if [[ ! -x "$release_target/release/ferro-cli" ||
        "$release_target/release/ferro-cli" -ot "$repo_root/ferro-cli/src/main.rs" ]]; then
    echo "[gate] building Docker-compatible release CLI"
    "$cargo_bin" build -p ferro-cli --release --locked
  fi
  FERROCRATE_DOCKER_CLI_REQUIRED=1 \
    FERROCRATE_DOCKER_CLI_REBUILD_STALE=1 \
    FERROCRATE_BIN="$release_target/release/ferro-cli" \
    timeout --foreground --kill-after=10s \
      "${FERROCRATE_DOCKER_CLI_GATE_TIMEOUT_SECONDS:-240}s" \
      bash scripts/test-docker-cli-compat.sh
else
  timeout --foreground --kill-after=10s \
    "${FERROCRATE_DOCKER_CLI_GATE_TIMEOUT_SECONDS:-240}s" \
    bash scripts/test-docker-cli-compat.sh
fi
bash scripts/test-rootless-install.sh
bash scripts/test-rootless-provision.sh
bash scripts/test-rootless-subid-diagnostics.sh
bash scripts/test-reliability-matrix-preflight.sh
bash scripts/test-uninstall.sh
bash scripts/test-install-rollback.sh
bash scripts/test-state-migrations.sh
bash scripts/test-default-dependency-graph.sh
bash scripts/test-rootless-cri-oci.sh
bash scripts/test-e2e-cli-backend.sh
bash scripts/test-local-smoke-gate.sh
bash scripts/test-ebpf-networking-backend.sh
bash scripts/perf/test-check-docker-comparison.sh
bash scripts/perf/test-check-benchmark-register.sh
bash scripts/perf/test-update-benchmark-register.sh
bash scripts/check-roadmap-progress.sh
bash scripts/test-generate-changelog.sh
bash scripts/test-next-release-version.sh
bash scripts/test-generate-release-index.sh
bash scripts/test-shell-out-audit.sh

if (( ! skip_workspace )); then
  echo "[gate] serialized all-features workspace tests"
  "$cargo_bin" test --workspace --all-features --locked --offline -- --test-threads=1
fi

echo "[gate] release-readiness and compatibility checks"
"$cargo_bin" test -p ferro-core --locked --offline registry::tests -- --test-threads=1
bash scripts/verify-release-readiness.sh

echo "[gate] public release build and channel verification"
bash scripts/test-release-provenance.sh
bash scripts/test-cross-platform-release-targets.sh
bash scripts/test-reproducible-release-artifacts.sh
bash scripts/test-sign-binaries.sh
bash scripts/build-release-artifacts.sh \
  --version "$version" --channel public --output-dir "$artifact_dir"
bash scripts/test-build-release-target-dir.sh
bash scripts/verify-release-channel-artifacts.sh \
  --channel public --version "$version" --artifact-dir "$artifact_dir"

if (( skip_workspace || skip_format )); then
  echo "local release checks partial (version=$version); requested skips prohibit release qualification"
else
  python3 scripts/check-candidate-evidence.py --manifest "$FERROCRATE_CANDIDATE_EVIDENCE" \
    --candidate "$candidate_head" --repo "$repo_root"
  echo "local release gate passed (version=$version, candidate=$candidate_head)"
fi
