#!/usr/bin/env bash
set -euo pipefail

IMAGE=${FERROCRATE_PERF_IMAGE:-alpine:latest}
RUNTIME_DIR=${FERROCRATE_RUNTIME_DIR:-$HOME/.ferrocrate}
ISOLATED=${FERROCRATE_PERF_PULL_ISOLATED:-0}
MIN_PULL_MIB_PER_S=${FERROCRATE_PERF_PULL_MIN_MIB_PER_S:-50}
ENFORCE=${FERROCRATE_PERF_ENFORCE:-1}
ALLOW_SKIP=${FERROCRATE_PERF_ALLOW_SKIP:-0}

if [ ! -x ./target/release/ferro-cli ]; then
  cargo build -p ferro-cli --release
fi

cleanup() {
  if [ "${ISOLATED}" = "1" ] && [ -n "${isolated_runtime_dir:-}" ]; then
    rm -rf "$isolated_runtime_dir"
  fi
}
trap cleanup EXIT

if [ "${ISOLATED}" = "1" ]; then
  isolated_runtime_dir=$(mktemp -d "${TMPDIR:-/tmp}/ferrocrate-pull.XXXXXX")
  RUNTIME_DIR="$isolated_runtime_dir"
fi

BLOB_DIR="$RUNTIME_DIR/images/blobs"
mkdir -p "$BLOB_DIR"
before=$(du -sb "$BLOB_DIR" | awk '{print $1}')
start_ns=$(date +%s%N)
if ! FERROCRATE_RUNTIME_DIR="$RUNTIME_DIR" ./target/release/ferro-cli pull "$IMAGE" >/dev/null 2>&1; then
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
  # Preserve sub-MiB/s precision. Integer truncation made small but real
  # throughput differences invisible and caused evidence to report `1` for
  # measurements such as 1.06 MiB/s.
  mbps=$(awk -v bytes="$bytes" -v elapsed_ms="$elapsed_ms" \
    'BEGIN { printf "%.2f", (bytes * 1000) / (1024 * 1024 * elapsed_ms) }')
else
  mbps="0.00"
fi

echo "perf.pull_bytes=${bytes}"
echo "perf.pull_ms=${elapsed_ms}"
echo "perf.pull_mib_per_s=${mbps}"
echo "perf.pull_min_mib_per_s_slo=${MIN_PULL_MIB_PER_S}"
if [ "${ISOLATED}" = "1" ]; then
  echo "perf.pull_store=isolated"
else
  echo "perf.pull_store=configured"
fi

if [ "${bytes}" -le 0 ]; then
  if [ "${ALLOW_SKIP}" = "1" ]; then
    echo "perf.pull_skipped=1"
    echo "perf.pull_skip_reason=no_new_bytes"
    exit 0
  fi
  echo "error: pull benchmark did not download new bytes (bytes=${bytes})" >&2
  exit 1
fi

if [ "${ENFORCE}" = "1" ] && awk -v measured="$mbps" -v minimum="$MIN_PULL_MIB_PER_S" \
  'BEGIN { exit !(measured < minimum) }'; then
  echo "error: pull throughput SLO violation (${mbps}MiB/s < ${MIN_PULL_MIB_PER_S}MiB/s)" >&2
  exit 1
fi
