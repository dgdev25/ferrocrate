#!/usr/bin/env bash
set -euo pipefail

if ! command -v cargo-tarpaulin >/dev/null 2>&1; then
  echo "coverage: cargo-tarpaulin required" >&2
  exit 1
fi

cargo tarpaulin --workspace --fail-under 80
