#!/usr/bin/env bash
set -euo pipefail

MAX_AI_NS=${FERROCRATE_PERF_AI_MAX_NS:-5000000}
ENFORCE=${FERROCRATE_PERF_ENFORCE:-1}
ALLOW_SKIP=${FERROCRATE_PERF_ALLOW_SKIP:-0}

out=$(cargo run --release -p ferro-mind --example ai_latency --quiet 2>/dev/null || true)
if [ -z "${out}" ]; then
  if [ "${ALLOW_SKIP}" = "1" ]; then
    echo "perf.ai_skipped=1"
    echo "perf.ai_skip_reason=run_failed"
    exit 0
  fi
  echo "error: failed to run ai latency benchmark example" >&2
  exit 1
fi
echo "${out}"
echo "perf.ai_max_ns_slo=${MAX_AI_NS}"

value=$(echo "${out}" | awk -F= '/perf.ai_inference_ns=/{print $2}' | tail -n1)
if [ -z "${value}" ]; then
  if [ "${ALLOW_SKIP}" = "1" ]; then
    echo "perf.ai_skipped=1"
    echo "perf.ai_skip_reason=missing_metric"
    exit 0
  fi
  echo "error: ai latency benchmark did not produce perf.ai_inference_ns metric" >&2
  exit 1
fi

if [ "${ENFORCE}" = "1" ] && [ "${value}" -gt "${MAX_AI_NS}" ]; then
  echo "error: AI inference latency SLO violation (${value}ns > ${MAX_AI_NS}ns)" >&2
  exit 1
fi
