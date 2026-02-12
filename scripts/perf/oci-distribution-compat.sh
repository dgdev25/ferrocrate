#!/usr/bin/env bash
set -euo pipefail

IMAGE=${FERROCRATE_PERF_IMAGE:-alpine:latest}

if [ ! -x ./target/release/ferro-cli ]; then
  cargo build -p ferro-cli --release
fi

./target/release/ferro-cli pull "$IMAGE" >/dev/null

if [ "$?" -eq 0 ]; then
  echo "perf.oci_distribution_compat=1"
else
  echo "perf.oci_distribution_compat=0"
  exit 1
fi
