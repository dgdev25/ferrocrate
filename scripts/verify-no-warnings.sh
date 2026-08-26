#!/usr/bin/env bash
set -euo pipefail

unset FERROCRATE_ENTITLEMENT_FILE FERROCRATE_ENTITLEMENT_PUBKEY

run_without_warnings() {
  local warning_log
  warning_log="$(mktemp)"
  if ! "$@" 2>&1 | tee "$warning_log"; then
    rm -f "$warning_log"
    return 1
  fi
  if grep -Eq '(^|:) warning(\[|:)|^npm warn|^\(!\)' "$warning_log"; then
    echo "warning output detected: $*" >&2
    rm -f "$warning_log"
    return 1
  fi
  rm -f "$warning_log"
}

run_without_warnings cargo build --workspace --all-targets
run_without_warnings cargo clippy --workspace --all-targets -- -D warnings
run_without_warnings cargo doc --workspace --no-deps

(
  cd apps/ferro-desktop-ui/src-tauri
  run_without_warnings cargo build --all-targets
  run_without_warnings cargo clippy --all-targets -- -D warnings
)

(
  cd apps/ferro-desktop-ui
  run_without_warnings npm run build
  # vite builds with esbuild, which strips types without checking them, so type
  # errors were invisible to this gate until the declaration files had drifted.
  run_without_warnings npm run typecheck
  run_without_warnings npm run lint
)
