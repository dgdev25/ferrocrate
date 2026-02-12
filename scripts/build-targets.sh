#!/usr/bin/env bash
set -euo pipefail

TARGETS=(
  x86_64-unknown-linux-gnu
  aarch64-unknown-linux-gnu
  riscv64gc-unknown-linux-gnu
)

for target in "${TARGETS[@]}"; do
  if ! rustup target list --installed | grep -q "^${target}$"; then
    rustup target add "${target}"
  fi
  cargo build --release --target "${target}"
done
