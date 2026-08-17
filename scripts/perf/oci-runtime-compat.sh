#!/usr/bin/env bash
set -euo pipefail

IMAGE=${FERROCRATE_PERF_IMAGE:-alpine:latest}

if [ ! -x ./target/release/ferro-cli ]; then
  cargo build -p ferro-cli --release
fi

pull_ok=1
if ! ./target/release/ferro-cli pull "$IMAGE" >/dev/null 2>&1; then
  pull_ok=0
fi

if ./target/release/ferro-cli run --rm --network none --network-backend iptables "$IMAGE" true >/dev/null 2>&1; then
  echo "perf.oci_runtime_compat=1"
else
  if [[ "$pull_ok" -eq 0 ]]; then
    echo "perf.oci_runtime_compat_skipped=1"
    echo "perf.oci_runtime_compat_skip_reason=image_unavailable"
    exit 77
  else
    echo "perf.oci_runtime_compat=0"
    exit 1
  fi
fi
