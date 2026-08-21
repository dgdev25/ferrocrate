#!/usr/bin/env bash
set -euo pipefail

IMAGE=${FERROCRATE_PERF_IMAGE:-alpine:latest}
# Keep the default runnable on hosts that deny unprivileged user namespaces;
# privileged bridge qualification sets FERROCRATE_PERF_NETWORK_MODE=bridge.
NETWORK_MODE=${FERROCRATE_PERF_NETWORK_MODE:-none}
NETWORK_BACKEND=${FERROCRATE_PERF_NETWORK_BACKEND:-iptables}
WARM_RUNS=${FERROCRATE_PERF_WARM_RUNS:-5}
COLD_SLO_MS=${FERROCRATE_PERF_STARTUP_COLD_SLO_MS:-100}
WARM_P95_SLO_MS=${FERROCRATE_PERF_STARTUP_WARM_P95_SLO_MS:-50}
ENFORCE=${FERROCRATE_PERF_ENFORCE:-1}
ALLOW_SKIP=${FERROCRATE_PERF_ALLOW_SKIP:-0}

if [ ! -x ./target/release/ferro-cli ]; then
  cargo build -p ferro-cli --release
fi

./target/release/ferro-cli pull "$IMAGE" >/dev/null 2>&1 || true

# Cold run: first execution after pull.
start_ns=$(date +%s%N)
if ! ./target/release/ferro-cli run --rm --network "$NETWORK_MODE" --network-backend "$NETWORK_BACKEND" "$IMAGE" true >/dev/null 2>&1; then
  if [ "${ALLOW_SKIP}" = "1" ]; then
    echo "perf.startup_skipped=1"
    echo "perf.startup_skip_reason=run_failed"
    exit 0
  fi
  echo "error: startup benchmark failed on cold run (set FERROCRATE_PERF_ALLOW_SKIP=1 to skip unsupported environments)" >&2
  exit 1
fi
end_ns=$(date +%s%N)
cold_ms=$(( (end_ns - start_ns) / 1000000 ))

# Warm runs: repeated execution with image/runtime artifacts hot.
warm_samples=()
for _ in $(seq 1 "$WARM_RUNS"); do
  start_ns=$(date +%s%N)
  if ! ./target/release/ferro-cli run --rm --network "$NETWORK_MODE" --network-backend "$NETWORK_BACKEND" "$IMAGE" true >/dev/null 2>&1; then
    if [ "${ALLOW_SKIP}" = "1" ]; then
      echo "perf.startup_skipped=1"
      echo "perf.startup_skip_reason=warm_run_failed"
      exit 0
    fi
    echo "error: startup benchmark failed on warm run (set FERROCRATE_PERF_ALLOW_SKIP=1 to skip unsupported environments)" >&2
    exit 1
  fi
  end_ns=$(date +%s%N)
  warm_samples+=( $(( (end_ns - start_ns) / 1000000 )) )
done

warm_p95_ms=$(printf '%s\n' "${warm_samples[@]}" | sort -n | awk '
  {
    samples[NR] = $1
  }
  END {
    if (NR == 0) {
      print 0
      exit
    }
    idx = int((NR * 95 + 99) / 100)
    if (idx < 1) idx = 1
    if (idx > NR) idx = NR
    print samples[idx]
  }')

echo "perf.startup_cold_ms=${cold_ms}"
echo "perf.startup_warm_p95_ms=${warm_p95_ms}"
echo "perf.startup_cold_slo_ms=${COLD_SLO_MS}"
echo "perf.startup_warm_p95_slo_ms=${WARM_P95_SLO_MS}"

if [ "${ENFORCE}" = "1" ]; then
  if [ "${cold_ms}" -gt "${COLD_SLO_MS}" ]; then
    echo "error: cold startup SLO violation (${cold_ms}ms > ${COLD_SLO_MS}ms)" >&2
    exit 1
  fi
  if [ "${warm_p95_ms}" -gt "${WARM_P95_SLO_MS}" ]; then
    echo "error: warm startup p95 SLO violation (${warm_p95_ms}ms > ${WARM_P95_SLO_MS}ms)" >&2
    exit 1
  fi
fi
