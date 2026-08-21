#!/usr/bin/env bash
set -euo pipefail

# Bounded native cross-target probe. The networking crate, shared core library,
# and CLI binary are checked independently so a foreign target cannot silently
# regress back to Linux-only compile assumptions. Runtime execution remains a
# separate native-host qualification.
target="${1:-x86_64-pc-windows-gnu}"
toolchain="${FERROCRATE_CROSS_TOOLCHAIN:-nightly-2026-02-11}"
repo_root="$(cd "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

if ! rustup target list --toolchain "$toolchain" --installed | grep -Fxq "$target"; then
  echo "SKIP: Rust target is not installed: $target" >&2
  exit 77
fi

# Apple targets need an Apple SDK-aware compiler.  A Linux host may have the
# Rust standard library installed while still lacking the SDK and linker; do
# not spend several minutes compiling native dependencies only to fail on
# cc-rs' first `-arch` flag.  A macOS runner (xcrun) or an explicitly provisioned
# cross compiler is required for a real probe.
if [[ "$target" == *-apple-darwin ]]; then
  if ! command -v xcrun >/dev/null 2>&1 && ! command -v o64-clang >/dev/null 2>&1; then
    echo "SKIP: $target requires an Apple SDK-aware compiler (xcrun or o64-clang); host toolchain is unavailable" >&2
    exit 77
  fi
fi

min_free_kb="${FERROCRATE_CROSS_MIN_FREE_KB:-4194304}"
[[ "$min_free_kb" =~ ^[1-9][0-9]*$ ]] || {
  echo "FERROCRATE_CROSS_MIN_FREE_KB must be a positive integer" >&2
  exit 2
}
available_kb="$(df -Pk /tmp | awk 'NR == 2 { print $4 }')"
if [[ ! "$available_kb" =~ ^[0-9]+$ ]] || (( available_kb < min_free_kb )); then
  echo "SKIP: cross-target build requires ${min_free_kb} KiB free; available=${available_kb:-unknown} KiB" >&2
  exit 77
fi
target_dir="$(mktemp -d /tmp/ferrocrate-cross-target.XXXXXX)"
active_pid=""
cleanup() {
  # The caller may wrap this script in an outer timeout.  In that case the
  # shell can receive TERM before run_bounded reaches its own deadline; reap
  # the exact setsid process group here so Cargo/rustc cannot outlive the
  # qualification runner and continue consuming CPU or disk.
  if [[ -n "$active_pid" ]] && kill -0 "$active_pid" 2>/dev/null; then
    kill -TERM -- "-$active_pid" 2>/dev/null || true
    sleep 1
    kill -KILL -- "-$active_pid" 2>/dev/null || true
    wait "$active_pid" 2>/dev/null || true
  fi
  if [[ -d "$target_dir" ]]; then
    find "$target_dir" -depth -delete 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

run_bounded() {
  local seconds="$1"
  shift
  setsid "$@" &
  local command_pid=$!
  active_pid="$command_pid"
  local deadline=$((SECONDS + seconds))
  while kill -0 "$command_pid" 2>/dev/null; do
    if (( SECONDS >= deadline )); then
      echo "SKIP: cross-target command timed out after ${seconds}s" >&2
      kill -TERM -- "-$command_pid" 2>/dev/null || true
      sleep 1
      kill -KILL -- "-$command_pid" 2>/dev/null || true
      wait "$command_pid" 2>/dev/null || true
      active_pid=""
      return 124
    fi
    sleep 0.1
  done
  wait "$command_pid"
  active_pid=""
}

command -v setsid >/dev/null 2>&1 || {
  echo "SKIP: setsid is required for cross-target process-group cleanup" >&2
  exit 77
}

run_bounded "${FERROCRATE_CROSS_TIMEOUT_SECONDS:-240}" \
  env CARGO_BUILD_JOBS="${FERROCRATE_CROSS_BUILD_JOBS:-1}" CARGO_TARGET_DIR="$target_dir" \
cargo "+$toolchain" check -p ferro-net --lib --target "$target"

run_bounded "${FERROCRATE_CROSS_TIMEOUT_SECONDS:-240}" \
  env CARGO_BUILD_JOBS="${FERROCRATE_CROSS_BUILD_JOBS:-1}" CARGO_TARGET_DIR="$target_dir" \
  cargo "+$toolchain" check -p ferro-core --lib --target "$target"

run_bounded "${FERROCRATE_CROSS_TIMEOUT_SECONDS:-240}" \
  env CARGO_BUILD_JOBS="${FERROCRATE_CROSS_BUILD_JOBS:-1}" CARGO_TARGET_DIR="$target_dir" \
  cargo "+$toolchain" check -p ferro-cli --target "$target"

echo "native cross-target ferro-net, ferro-core, and ferro-cli checks passed: $target"
