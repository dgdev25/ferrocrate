#!/usr/bin/env bash
set -euo pipefail

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/.." && pwd)}"
cd "$repo_root"

if [[ "$(id -u)" != "0" ]]; then
  echo "authenticated two-host qualification requires root" >&2
  exit 1
fi

# The matrix runner must classify a root invocation without a usable Rust
# toolchain as blocked, not as a failed network qualification. Root commonly
# has a separate HOME/rustup configuration from the operator running the
# matrix; callers can provide RUSTUP_HOME/CARGO_HOME explicitly.
auth_cargo="${FERROCRATE_CARGO_BIN:-$(command -v cargo || true)}"
if [[ -z "$auth_cargo" ]] || ! "$auth_cargo" --version >/dev/null 2>&1; then
  echo "authenticated two-host qualification requires a usable cargo toolchain" >&2
  exit 77
fi

"$auth_cargo" test -p ferro-mgr --test real_two_host_qualification \
  --offline -- --ignored --nocapture
