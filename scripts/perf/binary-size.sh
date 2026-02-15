#!/usr/bin/env bash
set -euo pipefail

MAX_BINARY_BYTES=${FERROCRATE_PERF_BINARY_MAX_BYTES:-31457280}
ENFORCE=${FERROCRATE_PERF_ENFORCE:-1}

if [ ! -x ./target/release/ferro-cli ]; then
  cargo build -p ferro-cli --release
fi

size_bytes=$(stat -c %s ./target/release/ferro-cli)
size_mb=$((size_bytes / 1024 / 1024))

echo "perf.binary_size_bytes=${size_bytes}"
echo "perf.binary_size_mb=${size_mb}"
echo "perf.binary_size_max_bytes_slo=${MAX_BINARY_BYTES}"

if [ "${ENFORCE}" = "1" ] && [ "${size_bytes}" -gt "${MAX_BINARY_BYTES}" ]; then
  echo "error: binary size SLO violation (${size_bytes}B > ${MAX_BINARY_BYTES}B)" >&2
  exit 1
fi
