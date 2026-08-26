#!/usr/bin/env bash
set -euo pipefail

# Privileged-only CRI recovery gate. The individual tests stay #[ignore] in
# the normal socket suite because they need rootful OCI execution; this wrapper
# makes the qualification explicit and bounded for release hosts.
repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$repo_root"

if [[ "$(id -u)" != 0 ]]; then
  echo "rootful CRI recovery requires root (exit 77)" >&2
  exit 77
fi
command -v setsid >/dev/null 2>&1 || {
  echo "rootful CRI recovery requires setsid for process-group cleanup" >&2
  exit 77
}

cargo_bin="${FERROCRATE_CARGO:-}"
if [[ -z "$cargo_bin" ]]; then
  for candidate in $HOME/.cargo/bin/cargo "$HOME/.cargo/bin/cargo"; do
    if [[ -x "$candidate" ]]; then
      cargo_bin="$candidate"
      break
    fi
  done
fi
[[ -x "$cargo_bin" ]] || {
  echo "rootful CRI recovery requires Cargo" >&2
  exit 77
}

export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
target_dir="${FERROCRATE_CRI_ROOTFUL_TARGET:-$(mktemp -d /tmp/ferrocrate-cri-rootful.XXXXXX)}"
target_dir_owned=0
if [[ -z "${FERROCRATE_CRI_ROOTFUL_TARGET:-}" ]]; then
  target_dir_owned=1
fi
mkdir -p "$target_dir"
cleanup() {
  if ((target_dir_owned)); then
    find "$target_dir" -depth -delete 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

run_case() {
  local name="$1"
  # The first privileged run may compile the CRI/OCI dependency graph. Keep a
  # hard bound, but leave enough room for a cold cache; subsequent runs are
  # normally much faster.
  local timeout_seconds="${FERROCRATE_CRI_ROOTFUL_TIMEOUT_SECONDS:-180}"
  [[ "$timeout_seconds" =~ ^[1-9][0-9]*$ ]] || {
    echo "FERROCRATE_CRI_ROOTFUL_TIMEOUT_SECONDS must be a positive integer" >&2
    exit 2
  }
  echo "[cri-rootful] $name (timeout=${timeout_seconds}s)"
  setsid env PATH="$(dirname "$cargo_bin"):$PATH" \
    CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="$target_dir" \
    "$cargo_bin" test -p ferro-cri --test socket_integration "$name" --offline \
    -- --ignored --nocapture --test-threads=1 >"$target_dir/$name.log" 2>&1 &
  local command_pid=$!
  local deadline=$((SECONDS + timeout_seconds))
  while kill -0 "$command_pid" 2>/dev/null; do
    if ((SECONDS >= deadline)); then
      echo "[cri-rootful] $name timed out; terminating process group" >&2
      kill -TERM -- "-$command_pid" 2>/dev/null || true
      sleep 1
      kill -KILL -- "-$command_pid" 2>/dev/null || true
      wait "$command_pid" 2>/dev/null || true
      cat "$target_dir/$name.log" >&2 || true
      return 124
    fi
    sleep 0.1
  done
  local status=0
  wait "$command_pid" || status=$?
  cat "$target_dir/$name.log"
  return "$status"
}

run_case cri_start_recovery_rebinds_published_runtime_after_response_crash
run_case cri_start_recovery_rebinds_runtime_after_mid_operation_crash
run_case cri_stop_recovery_reconciles_runtime_after_effect_crash
run_case cri_network_effect_crash_is_cleaned_from_pending_state
run_case cri_remove_sandbox_network_effect_crash_is_reconciled_on_restart
run_case cri_pending_publication_crash_without_kernel_effects_is_reclaimed
run_case cri_netns_effect_crash_is_reconciled_on_restart
run_case cri_remove_sandbox_store_crash_is_reconciled_on_restart
run_case cri_remove_sandbox_netns_crash_clears_pending_idempotently
run_case cri_remove_container_runtime_crash_rebinds_cleared_binding
echo "rootful CRI recovery gate passed (10/10)"
