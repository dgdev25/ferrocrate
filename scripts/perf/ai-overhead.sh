#!/usr/bin/env bash
set -euo pipefail

MAX_NS="${FERROCRATE_PERF_AI_OVERHEAD_MAX_NS:-1000000}"
ENFORCE="${FERROCRATE_PERF_ENFORCE:-1}"
ALLOW_SKIP="${FERROCRATE_PERF_ALLOW_SKIP:-0}"

out="$(cargo run --release -p ferro-mind --example ai_overhead --quiet 2>/dev/null || true)"
if [[ -z "$out" ]]; then
  if [[ "$ALLOW_SKIP" == "1" ]]; then
    printf 'perf.ai_overhead_skipped=1\nperf.ai_overhead_skip_reason=run_failed\n'
    exit 0
  fi
  printf 'error: failed to run AI overhead benchmark\n' >&2
  exit 1
fi
printf '%s\nperf.ai_monitor_sample_max_ns=%s\n' "$out" "$MAX_NS"
value="$(awk -F= '/perf.ai_monitor_sample_ns=/{print $2}' <<<"$out" | tail -n1)"
if [[ -z "$value" || ! "$value" =~ ^[0-9]+$ ]]; then
  printf 'error: AI overhead benchmark did not produce a numeric metric\n' >&2
  exit 1
fi
if [[ "$ENFORCE" == "1" && "$value" -gt "$MAX_NS" ]]; then
  printf 'error: AI monitor overhead SLO violation (%sns > %sns)\n' "$value" "$MAX_NS" >&2
  exit 1
fi
