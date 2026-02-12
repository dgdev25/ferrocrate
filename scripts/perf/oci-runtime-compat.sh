#!/usr/bin/env bash
set -euo pipefail

IMAGE=${FERROCRATE_PERF_IMAGE:-alpine:latest}

if [ ! -x ./target/release/ferro-cli ]; then
  cargo build -p ferro-cli --release
fi

./target/release/ferro-cli pull "$IMAGE" >/dev/null 2>&1 || true
./target/release/ferro-cli run --rm "$IMAGE" true >/dev/null 2>&1

if [ "$?" -eq 0 ]; then
  echo "perf.oci_runtime_compat=1"
else
  echo "perf.oci_runtime_compat=0"
  exit 1
fi
