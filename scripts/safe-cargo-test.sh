#!/usr/bin/env bash
set -euo pipefail

# Run one narrowly scoped Cargo test without allowing a stalled build or test
# process to remain attached to the developer workstation.
package=""
filter=""
timeout_seconds="60"
target_dir=""

usage() {
  cat <<'USAGE'
Usage: safe-cargo-test.sh --package <crate> --filter <name> [options]

Options:
  --package <crate>       Cargo package to test (required)
  --filter <name>         Test filter passed to Cargo (required)
  --timeout <seconds>     Hard wall-clock limit (default: 60)
  --target-dir <path>     Isolated Cargo target directory
  -h, --help              Show this help

The wrapper always uses one Cargo build job, disables incremental metadata, and
runs tests serially. It is intentionally unsuitable for workspace-wide gates.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --package) package="${2:?missing package}"; shift 2 ;;
    --filter) filter="${2:?missing filter}"; shift 2 ;;
    --timeout) timeout_seconds="${2:?missing timeout}"; shift 2 ;;
    --target-dir) target_dir="${2:?missing target directory}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$package" || -z "$filter" ]]; then
  echo "--package and --filter are required" >&2
  usage >&2
  exit 2
fi
if ! [[ "$timeout_seconds" =~ ^[1-9][0-9]*$ ]]; then
  echo "--timeout must be a positive integer" >&2
  exit 2
fi

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/.." && pwd)}"
cd "$repo_root"
if [[ -z "$target_dir" ]]; then
  target_dir="/tmp/ferrocrate-safe-test-${BASHPID}"
fi
case "$target_dir" in
  /*) ;;
  *) echo "--target-dir must be an absolute path" >&2; exit 2 ;;
esac

echo "[safe-test] package=$package filter=$filter timeout=${timeout_seconds}s target=$target_dir"
exec timeout --signal=TERM --kill-after=5s "${timeout_seconds}s" \
  env CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="$target_dir" \
  cargo test -p "$package" --offline "$filter" -- --test-threads=1
