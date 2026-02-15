#!/usr/bin/env bash
set -euo pipefail

IMAGE=${FERROCRATE_PERF_IMAGE:-alpine:latest}
RUNTIME_DIR=${FERROCRATE_RUNTIME_DIR:-$HOME/.ferrocrate}
BLOB_DIR="$RUNTIME_DIR/images/blobs"
MIN_PULL_MIB_PER_S=${FERROCRATE_PERF_PULL_MIN_MIB_PER_S:-50}
ENFORCE=${FERROCRATE_PERF_ENFORCE:-1}
ALLOW_SKIP=${FERROCRATE_PERF_ALLOW_SKIP:-0}

if [ ! -x ./target/release/ferro-cli ]; then
  cargo build -p ferro-cli --release
fi

mkdir -p "$BLOB_DIR"
before=$(du -sb "$BLOB_DIR" | awk '{print $1}')
start_ns=$(date +%s%N)
if ! ./target/release/ferro-cli pull "$IMAGE" >/dev/null 2>&1; then
  if [ "${ALLOW_SKIP}" = "1" ]; then
    echo "perf.pull_skipped=1"
    echo "perf.pull_skip_reason=pull_failed"
    exit 0
  fi
  echo "error: pull benchmark failed (set FERROCRATE_PERF_ALLOW_SKIP=1 to skip unsupported environments)" >&2
  exit 1
fi
end_ns=$(date +%s%N)
after=$(du -sb "$BLOB_DIR" | awk '{print $1}')

bytes=$((after - before))
elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))
if [ "$elapsed_ms" -gt 0 ]; then
  mbps=$(( bytes * 1000 / 1024 / 1024 / elapsed_ms ))
else
  mbps=0
fi

echo "perf.pull_bytes=${bytes}"
echo "perf.pull_ms=${elapsed_ms}"
echo "perf.pull_mib_per_s=${mbps}"
echo "perf.pull_min_mib_per_s_slo=${MIN_PULL_MIB_PER_S}"

if [ "${bytes}" -le 0 ]; then
  if [ "${ALLOW_SKIP}" = "1" ]; then
    echo "perf.pull_skipped=1"
    echo "perf.pull_skip_reason=no_new_bytes"
    exit 0
  fi
  echo "error: pull benchmark did not download new bytes (bytes=${bytes})" >&2
  exit 1
fi

if [ "${ENFORCE}" = "1" ] && [ "${mbps}" -lt "${MIN_PULL_MIB_PER_S}" ]; then
  echo "error: pull throughput SLO violation (${mbps}MiB/s < ${MIN_PULL_MIB_PER_S}MiB/s)" >&2
  exit 1
fi
