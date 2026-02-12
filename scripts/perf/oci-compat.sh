#!/usr/bin/env bash
set -euo pipefail

RUNTIME_DIR=${FERROCRATE_RUNTIME_DIR:-$HOME/.ferrocrate}

if [ ! -x ./target/release/ferro-cli ]; then
  cargo build -p ferro-cli --release
fi

./target/release/ferro-cli pull alpine:latest >/dev/null 2>&1 || true

manifest=$(ls -1 "$RUNTIME_DIR/images/configs" 2>/dev/null | head -n1 || true)
if [ -z "$manifest" ]; then
  echo "perf.oci_compat=0"
  exit 1
fi

echo "perf.oci_compat=1"
