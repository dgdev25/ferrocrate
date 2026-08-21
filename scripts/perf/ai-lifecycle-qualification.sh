#!/usr/bin/env bash
set -euo pipefail

# AI multi-container lifecycle qualification (roadmap item 23). Unprivileged:
# every scenario runs the CLI as the invoking user (rootless execution when
# non-root). Measures enabled/disabled AI overhead across N containers,
# steady-state RSS, and end-to-end coherence-gate rejection. In-process
# exhaustion/ledger/failover scenarios live in
# tests/ai_multi_container_qualification.rs.
#
# All container operations are bounded by timeout --foreground; each measured
# cell uses a fresh runtime directory that is removed on exit unless
# FERROCRATE_AI_QUAL_KEEP_TMP=1.
repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/../.." && pwd)}"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/ferrocrate-perf-target}"
export CARGO_TARGET_DIR
binary="${FERROCRATE_BIN:-$CARGO_TARGET_DIR/release/ferro-cli}"
image="${FERROCRATE_AI_QUAL_IMAGE:-alpine:3.19}"
base_count="${FERROCRATE_AI_QUAL_COUNT:-10}"
scale_count="${FERROCRATE_AI_QUAL_SCALE_COUNT:-50}"
runs="${FERROCRATE_AI_QUAL_RUNS:-3}"
memory_limit="${FERROCRATE_AI_QUAL_MEMORY_LIMIT_BYTES:-67108864}"
keep_tmp="${FERROCRATE_AI_QUAL_KEEP_TMP:-0}"
operation_timeout="${FERROCRATE_AI_QUAL_OPERATION_TIMEOUT_SECONDS:-45}"

for value in "$base_count" "$scale_count" "$runs" "$operation_timeout"; do
  [[ "$value" =~ ^[1-9][0-9]*$ ]] || { echo "invalid count/runs/timeout: $value" >&2; exit 2; }
done
(( runs >= 3 )) || { echo "runs must be >= 3 for a median" >&2; exit 2; }
(( operation_timeout <= 900 )) || { echo "operation timeout must be <= 900s" >&2; exit 2; }

if [[ ! -x "$binary" ]]; then
  timeout --foreground --kill-after=120s 900s cargo build --release -p ferro-cli \
    >/dev/null
fi
if ! command -v /usr/bin/time >/dev/null 2>&1; then
  echo "perf.ai_qual_skipped=1"
  echo "perf.ai_qual_skip_reason=usr_bin_time_missing"
  exit 77
fi

tmp_root="$(mktemp -d /tmp/ferrocrate-ai-qual.XXXXXX)"
cleanup() {
  if [[ "$keep_tmp" == "1" ]]; then
    echo "perf.ai_qual_tmp_root=$tmp_root" >&2
  else
    rm -rf "$tmp_root"
  fi
}
trap cleanup EXIT

echo "perf.ai_qual_euid=${EUID:-$(id -u)}"
echo "perf.ai_qual_image=$image"
echo "perf.ai_qual_runs=$runs"
echo "perf.ai_qual_operation_timeout_seconds=$operation_timeout"

median() {
  # Median of a newline-separated numeric list.
  printf '%s\n' "$@" | sort -n | awk -v n="$#" 'NR == int((n + 1) / 2) { print; exit }'
}

# Runs one container batch of `count` serial bounded runs in a fresh runtime
# dir under `$1` (mode dir). Prints the batch wall time in ms on stdout. The
# ferrofile.toml for the enabled cells is read from the working directory, so
# every invocation runs with cwd = workdir.
run_batch() {
  local workdir="$1" ai_flag="$2" count="$3" extra_args="${4:-}"
  local runtime_dir="$workdir/runtime"
  mkdir -p "$runtime_dir"
  local run_args=(--rm --network none)
  if [[ -n "$extra_args" ]]; then
    run_args+=($extra_args)
  fi
  timeout --foreground --signal=TERM --kill-after=5s "${operation_timeout}s" \
    env FERROCRATE_RUNTIME_DIR="$runtime_dir" HOME="$workdir" FERROCRATE_AI="$ai_flag" \
    "$binary" pull "$image" >/dev/null 2>&1 || {
      echo "perf.ai_qual_skipped=1" >&2
      echo "perf.ai_qual_skip_reason=image_unavailable" >&2
      exit 77
    }
  local start_ns end_ns index
  start_ns="$(date +%s%N)"
  for (( index = 0; index < count; index++ )); do
    (cd "$workdir" &&
      timeout --foreground --signal=TERM --kill-after=5s "${operation_timeout}s" \
        env FERROCRATE_RUNTIME_DIR="$runtime_dir" HOME="$workdir" FERROCRATE_AI="$ai_flag" \
        "$binary" run "${run_args[@]}" "$image" true) \
      >"$workdir/run-$index.log" 2>&1 || {
        echo "perf.ai_qual_run_failed=1" >&2
        sed -n '1,5p' "$workdir/run-$index.log" >&2
        return 1
      }
  done
  end_ns="$(date +%s%N)"
  echo $(( (end_ns - start_ns) / 1000000 ))
}

write_ferrofile() {
  # The AI lifecycle path activates only when the container has an
  # [ai_runtime] config (ferrofile.toml in the working directory).
  cat >"$1/ferrofile.toml" <<'TOML'
[ai_runtime]
authority = "user"
token_budget = 1000
memory_budget_mb = 64
TOML
}

# Scenario S1: per-container startup overhead, AI disabled vs enabled, with
# and without a memory limit (the AI monitor samples only under a limit).
startup_cell() {
  local label="$1" ai_flag="$2" count="$3" extra_args="${4:-}"
  local cell_root="$tmp_root/startup-$label-$count"
  mkdir -p "$cell_root/work"
  [[ "$ai_flag" == "1" ]] && write_ferrofile "$cell_root/work"
  local elapsed median_ms per_container
  local samples=()
  for (( run_index = 1; run_index <= runs; run_index++ )); do
    # A fresh runtime dir per run keeps per-run artifacts (AI restart
    # snapshots) countable and prevents state leaking between samples.
    rm -rf "$cell_root/work/runtime"
    elapsed="$(run_batch "$cell_root/work" "$ai_flag" "$count" "$extra_args")" || return 1
    samples+=("$elapsed")
  done
  median_ms="$(median "${samples[@]}")"
  per_container=$(( median_ms / count ))
  echo "perf.ai_qual_startup_${label}_count${count}_median_ms=$median_ms"
  echo "perf.ai_qual_startup_${label}_count${count}_per_container_ms=$per_container"
}

startup_cell disabled 0 "$base_count"
startup_cell enabled 1 "$base_count"
startup_cell enabled-limit 1 "$base_count" "--memory-max $memory_limit"
startup_cell disabled 0 "$scale_count"
startup_cell enabled 1 "$scale_count"
startup_cell enabled-limit 1 "$scale_count" "--memory-max $memory_limit"

# Evidence the enabled AI path is active: one restart-policy snapshot per
# container is written under <runtime>/ai/restart/.
startup_cell_ai_artifacts="$tmp_root/startup-enabled-$scale_count/work/runtime/ai/restart"
if [[ -d "$startup_cell_ai_artifacts" ]]; then
  artifacts="$(find "$startup_cell_ai_artifacts" -maxdepth 1 -name '*.json' -type f | wc -l)"
  echo "perf.ai_qual_enabled_ai_artifacts=$artifacts"
fi

# Scenario S2: steady-state RSS of one container run, AI disabled vs enabled
# (median max resident set size of the CLI process across runs).
rss_cell() {
  local label="$1" ai_flag="$2" extra_args="${3:-}"
  local cell_root="$tmp_root/rss-$label"
  mkdir -p "$cell_root/work"
  [[ "$ai_flag" == "1" ]] && write_ferrofile "$cell_root/work"
  local runtime_dir="$cell_root/work/runtime"
  mkdir -p "$runtime_dir"
  timeout --foreground --signal=TERM --kill-after=5s "${operation_timeout}s" \
    env FERROCRATE_RUNTIME_DIR="$runtime_dir" HOME="$cell_root/work" FERROCRATE_AI="$ai_flag" \
    "$binary" pull "$image" >/dev/null 2>&1 || exit 77
  local run_args=(--rm --network none)
  [[ -n "$extra_args" ]] && run_args+=($extra_args)
  local samples=() rss_kb
  for (( run_index = 1; run_index <= runs; run_index++ )); do
    (
      cd "$cell_root/work"
      timeout --foreground --signal=TERM --kill-after=5s "${operation_timeout}s" \
        /usr/bin/time -v \
        env FERROCRATE_RUNTIME_DIR="$runtime_dir" HOME="$cell_root/work" \
        FERROCRATE_AI="$ai_flag" \
        "$binary" run "${run_args[@]}" "$image" true
    ) >"$cell_root/out-$run_index.log" 2>"$cell_root/time-$run_index.txt" || {
      echo "perf.ai_qual_rss_${label}_run_failed=1" >&2
      sed -n '1,5p' "$cell_root/time-$run_index.txt" >&2
      return 1
    }
    rss_kb="$(awk -F': ' '/Maximum resident set size/ { print $2 }' \
      "$cell_root/time-$run_index.txt")"
    samples+=("${rss_kb:-0}")
  done
  echo "perf.ai_qual_rss_${label}_median_kb=$(median "${samples[@]}")"
}

rss_cell disabled 0
rss_cell enabled 1
rss_cell enabled-limit 1 "--memory-max $memory_limit"

# Scenario S3: end-to-end coherence-gate rejection. A ferrofile requiring
# `model_loaded` without FERRO_MODEL_PATH must refuse every container run
# before execution.
gate_root="$tmp_root/gate"
mkdir -p "$gate_root/work/runtime"
cat >"$gate_root/work/ferrofile.toml" <<'TOML'
[ai_runtime]
authority = "user"
coherence_gates = ["model_loaded"]
TOML
timeout --foreground --signal=TERM --kill-after=5s "${operation_timeout}s" \
  env FERROCRATE_RUNTIME_DIR="$gate_root/work/runtime" HOME="$gate_root/work" \
  "$binary" pull "$image" >/dev/null 2>&1 || exit 77
gate_rejected=0
gate_other=0
for (( index = 0; index < base_count; index++ )); do
  if (cd "$gate_root/work" &&
    timeout --foreground --signal=TERM --kill-after=5s "${operation_timeout}s" \
      env FERROCRATE_RUNTIME_DIR="$gate_root/work/runtime" HOME="$gate_root/work" \
      FERROCRATE_AI=1 \
      "$binary" run --rm --network none "$image" true) \
    >"$gate_root/gate-$index.log" 2>&1; then
    gate_other=$((gate_other + 1))
  elif grep -q "coherence gate failed" "$gate_root/gate-$index.log"; then
    gate_rejected=$((gate_rejected + 1))
  else
    gate_other=$((gate_other + 1))
    sed -n '1,3p' "$gate_root/gate-$index.log" >&2
  fi
done
echo "perf.ai_qual_gate_attempts=$base_count"
echo "perf.ai_qual_gate_rejected=$gate_rejected"
echo "perf.ai_qual_gate_unexpected=$gate_other"
if (( gate_rejected != base_count || gate_other != 0 )); then
  echo "perf.ai_qual_gate_result=fail" >&2
  exit 1
fi
echo "perf.ai_qual_gate_result=pass"
