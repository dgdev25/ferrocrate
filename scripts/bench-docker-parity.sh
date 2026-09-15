#!/usr/bin/env bash
# Measure the eleven Docker-versus-FerroCrate rows documented in
# docs/evidence/performance/2026-08-23-docker-vs-ferrocrate.md.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ferro_bin="${FERROCRATE_BIN:-$repo_root/target/release/ferro-cli}"
image="${FERROCRATE_DOCKER_PARITY_IMAGE:-alpine:latest}"
pull_image="${FERROCRATE_DOCKER_PARITY_PULL_IMAGE:-alpine:3.19}"
rounds=10
slow_rounds=5
timeout_seconds=60
output_dir="${FERROCRATE_DOCKER_PARITY_OUTPUT_DIR:-$repo_root/benchmarks/docker-parity-$(date -u +%Y%m%dT%H%M%SZ)}"
isolated_docker="${FERROCRATE_DOCKER_PARITY_ISOLATED_DOCKER:-0}"
list_only=0

operation_ids=(
  run-to-exit
  start-detached
  stop-t-1
  exec-bin-true
  logs-1000-lines
  ps-a
  images-list
  volume-create
  pull-alpine-3-19-cold
  build-copy-only-no-cache
  build-copy-only-cached
)

usage() {
  cat <<'USAGE'
Usage: scripts/bench-docker-parity.sh [options]

Run paired Docker/FerroCrate samples for the eleven documented parity rows.

Options:
  --rounds <1..100>        Rounds for lifecycle/list operations (default: 10)
  --slow-rounds <1..100>   Rounds for pull/build operations (default: 5)
  --timeout <1..300>       Per-command timeout in seconds (default: 60)
  --output-dir <path>      Directory for samples.tsv, metadata.txt, and summary.md
  --list                   Print operation identifiers and exit without mutation
  -h, --help               Show this help

The runner never builds ferro-cli implicitly. It creates only resources named
with its unique prefix and removes those resources during cleanup.

Set FERROCRATE_DOCKER_PARITY_ISOLATED_DOCKER=1 only when DOCKER_HOST targets a
dedicated daemon with no other clients. That opt-in permits reset/removal of
alpine:3.19 between cold-pull rounds; shared engines record that row unavailable.
USAGE
}

require_bounded_integer() {
  local option="$1" value="$2" maximum="$3"
  if ! [[ "$value" =~ ^[1-9][0-9]*$ ]] || (( value > maximum )); then
    echo "$option must be an integer in 1..$maximum" >&2
    exit 2
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rounds)
      rounds="${2:-}"
      shift 2
      ;;
    --slow-rounds)
      slow_rounds="${2:-}"
      shift 2
      ;;
    --timeout)
      timeout_seconds="${2:-}"
      shift 2
      ;;
    --output-dir)
      output_dir="${2:-}"
      shift 2
      ;;
    --list)
      list_only=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

require_bounded_integer "--rounds" "$rounds" 100
require_bounded_integer "--slow-rounds" "$slow_rounds" 100
require_bounded_integer "--timeout" "$timeout_seconds" 300
if [[ "$isolated_docker" != 0 && "$isolated_docker" != 1 ]]; then
  echo "FERROCRATE_DOCKER_PARITY_ISOLATED_DOCKER must be 0 or 1" >&2
  exit 2
fi
if [[ -z "$output_dir" || "$output_dir" == *$'\n'* ]]; then
  echo "--output-dir must be a non-empty path without newlines" >&2
  exit 2
fi

if (( list_only )); then
  printf '%s\n' "${operation_ids[@]}"
  exit 0
fi

[[ "$image" =~ ^[A-Za-z0-9._/@:-]+$ ]] || { echo "invalid benchmark image: $image" >&2; exit 2; }
[[ "$pull_image" == "alpine:3.19" ]] || {
  echo "FERROCRATE_DOCKER_PARITY_PULL_IMAGE must remain alpine:3.19 for this benchmark" >&2
  exit 2
}
[[ "$image" != "$pull_image" ]] || {
  echo "FERROCRATE_DOCKER_PARITY_IMAGE must differ from FERROCRATE_DOCKER_PARITY_PULL_IMAGE" >&2
  exit 2
}
[[ -x "$ferro_bin" ]] || { echo "missing executable ferro-cli: $ferro_bin" >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "docker CLI is unavailable" >&2; exit 1; }
command -v timeout >/dev/null 2>&1 || { echo "timeout is required" >&2; exit 1; }

mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"
work_root="$(mktemp -d "${TMPDIR:-/tmp}/ferrocrate-docker-parity.XXXXXX")"
bench_elapsed_file="$work_root/last-elapsed"
docker_config="$work_root/docker-config"
mkdir -p "$docker_config"
samples_file="$output_dir/samples.tsv"
metadata_file="$output_dir/metadata.txt"
summary_file="$output_dir/summary.md"
samples_tmp="$work_root/samples.tsv"
summary_tmp="$work_root/summary.md"
run_id="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
run_prefix="ferrocrate-parity-${run_id}"
owner_label="io.ferrocrate.parity-run=${run_id}"
current_ferro_runtime=""
declare -a docker_containers=()
declare -a docker_volumes=()
declare -a docker_images=()
failures=0

# GNU timeout on this host quantizes its wait to ~100 ms, which flattens
# every fast operation into wrapper latency. A minimal Python runner
# enforces the bound and records the child's precise wall time to
# $bench_elapsed_file; record_sample prefers that over its own clock.
bench_timer_run() {
  python3 - "$timeout_seconds" "$bench_elapsed_file" "$@" <<'PYEOF'
import subprocess, sys, time
bound = float(sys.argv[1])
out = sys.argv[2]
cmd = sys.argv[3:]
start = time.perf_counter()
try:
    code = subprocess.run(cmd, timeout=bound).returncode
except subprocess.TimeoutExpired:
    code = 124
elapsed = time.perf_counter() - start
with open(out, "w") as handle:
    handle.write(f"{elapsed:.6f}")
sys.exit(code)
PYEOF
}

docker_cmd() {
  bench_timer_run env DOCKER_CONFIG="$docker_config" docker "$@"
}

ferro_cmd() {
  bench_timer_run env FERROCRATE_RUNTIME_DIR="$current_ferro_runtime" "$ferro_bin" "$@"
}

engine_cmd() {
  local engine="$1"
  shift
  if [[ "$engine" == docker ]]; then
    docker_cmd "$@"
  else
    ferro_cmd "$@"
  fi
}

docker_container_owned_id() {
  local inspection inspected_run container_id extra
  if ! inspection="$(docker_cmd container inspect --format \
    '{{ printf "%s\t%s" (index .Config.Labels "io.ferrocrate.parity-run") .Id }}' \
    "$1" 2>/dev/null)"; then
    return 1
  fi
  IFS=$'\t' read -r inspected_run container_id extra <<<"$inspection"
  if [[ "$inspected_run" == "$run_id" && "$container_id" =~ ^[0-9a-f]{64}$ && -z "$extra" ]]; then
    printf '%s\n' "$container_id"
    return 0
  fi
  return 1
}

docker_image_owned_id() {
  local inspection inspected_run image_id extra
  if ! inspection="$(docker_cmd image inspect --format \
    '{{ printf "%s\t%s" (index .Config.Labels "io.ferrocrate.parity-run") .Id }}' \
    "$1" 2>/dev/null)"; then
    return 1
  fi
  IFS=$'\t' read -r inspected_run image_id extra <<<"$inspection"
  if [[ "$inspected_run" == "$run_id" && "$image_id" =~ ^sha256:[0-9a-f]{64}$ && -z "$extra" ]]; then
    printf '%s\n' "$image_id"
    return 0
  fi
  return 1
}

remove_container() {
  local engine="$1" container="$2" container_id
  if [[ "$engine" == docker ]]; then
    if container_id="$(docker_container_owned_id "$container")"; then
      docker_cmd rm -f "$container_id" >/dev/null 2>&1 || true
    fi
  else
    ferro_cmd rm -f "$container" >/dev/null 2>&1 || true
  fi
}

remove_volume() {
  local engine="$1" volume="$2"
  if [[ "$engine" == docker ]]; then
    # Docker volumes have no immutable object ID. Select and remove unused
    # volumes by the exact run label inside one daemon request instead of
    # authorizing one mutable name and resolving it again during deletion.
    docker_cmd volume prune --all --force --filter "label=$owner_label" \
      >/dev/null 2>&1 || true
  else
    ferro_cmd volume rm "$volume" >/dev/null 2>&1 || true
  fi
}

remove_image() {
  local image_ref="$1" image_id
  if image_id="$(docker_image_owned_id "$image_ref")"; then
    docker_cmd image rm "$image_id" >/dev/null 2>&1 || true
  fi
}

docker_image_tag_absent() {
  local image_ids
  if ! image_ids="$(docker_cmd image ls --quiet --filter "reference=$1" 2>/dev/null)"; then
    return 1
  fi
  [[ -z "$image_ids" ]]
}

cleanup() {
  # Clean only exact labels generated by this run. The cold-pull tag is reset
  # only under the caller's explicit dedicated-Docker contract.
  local resource
  for resource in "${docker_containers[@]}"; do
    remove_container docker "$resource"
  done
  for resource in "${docker_volumes[@]}"; do
    remove_volume docker "$resource"
  done
  for resource in "${docker_images[@]}"; do
    remove_image "$resource"
  done
  if (( isolated_docker )); then
    docker_cmd image rm "$pull_image" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$work_root"
}
trap cleanup EXIT

prepare_docker_fixture() {
  if ! docker_cmd image inspect "$image" >/dev/null 2>&1; then
    docker_cmd pull "$image" >/dev/null
  fi
}

prepare_ferro_fixture() {
  local operation="$1" round="$2"
  current_ferro_runtime="$work_root/ferro-runtime/${operation}-${round}"
  mkdir -p "$current_ferro_runtime"
  if [[ "$operation" != pull-alpine-3-19-cold ]]; then
    ferro_cmd pull "$image" >/dev/null
  fi
}

container_run() {
  local engine="$1"
  shift
  if [[ "$engine" == docker ]]; then
    docker_cmd run --label "$owner_label" "$@"
  else
    ferro_cmd run "$@"
  fi
}

volume_create_cmd() {
  local engine="$1" volume="$2"
  if [[ "$engine" == docker ]]; then
    docker_cmd volume create --label "$owner_label" "$volume"
  else
    ferro_cmd volume create "$volume"
  fi
}

record_sample() {
  local operation="$1" engine="$2" round="$3"
  shift 3
  local started ended elapsed status=ok
  rm -f -- "$bench_elapsed_file"
  started="$(date +%s%N)"
  if ! "$@" >"$work_root/${operation}-${engine}-${round}.log" 2>&1; then
    status=failed
    failures=$((failures + 1))
  fi
  ended="$(date +%s%N)"
  if [[ -s "$bench_elapsed_file" ]]; then
    elapsed="$(cat "$bench_elapsed_file")"
  else
    elapsed="$(awk -v started="$started" -v ended="$ended" 'BEGIN { printf "%.6f", (ended - started) / 1000000000 }')"
  fi
  printf '%s\t%s\t%s\t%s\t%s\n' "$operation" "$engine" "$round" "$elapsed" "$status" >>"$samples_tmp"
  # Continue after a failed timed invocation so the evidence has a row for
  # every attempted command and the summary can mark that median unavailable.
  return 0
}

record_unavailable() {
  local operation="$1" engine="$2" round="$3"
  printf '%s\t%s\t%s\t0.000000\tunavailable\n' \
    "$operation" "$engine" "$round" >>"$samples_tmp"
}

new_name() {
  local operation="$1" engine="$2" round="$3"
  printf '%s-%s-%s-%s' "$run_prefix" "$operation" "$engine" "$round"
}

run_to_exit() {
  local engine="$1" round="$2" name
  name="$(new_name run-to-exit "$engine" "$round")"
  if [[ "$engine" == docker ]]; then
    docker_containers+=("$name")
  fi
  record_sample run-to-exit "$engine" "$round" container_run "$engine" --name "$name" --network none "$image" /bin/true
  remove_container "$engine" "$name"
}

start_detached() {
  local engine="$1" round="$2" name
  name="$(new_name start-detached "$engine" "$round")"
  if [[ "$engine" == docker ]]; then
    docker_containers+=("$name")
  fi
  container_run "$engine" -d --name "$name" --network none "$image" /bin/sh -c 'sleep 120' >/dev/null
  if [[ "$engine" == docker ]]; then
    engine_cmd "$engine" stop --time 1 "$name" >/dev/null
  else
    engine_cmd "$engine" stop --timeout 1 "$name" >/dev/null
  fi
  record_sample start-detached "$engine" "$round" engine_cmd "$engine" start "$name"
  remove_container "$engine" "$name"
}

stop_t_1() {
  local engine="$1" round="$2" name
  name="$(new_name stop-t-1 "$engine" "$round")"
  if [[ "$engine" == docker ]]; then
    docker_containers+=("$name")
  fi
  container_run "$engine" -d --name "$name" --network none "$image" /bin/sh -c 'sleep 120' >/dev/null
  if [[ "$engine" == docker ]]; then
    record_sample stop-t-1 "$engine" "$round" engine_cmd "$engine" stop --time 1 "$name"
  else
    record_sample stop-t-1 "$engine" "$round" engine_cmd "$engine" stop --timeout 1 "$name"
  fi
  remove_container "$engine" "$name"
}

exec_bin_true() {
  local engine="$1" round="$2" name
  name="$(new_name exec-bin-true "$engine" "$round")"
  if [[ "$engine" == docker ]]; then
    docker_containers+=("$name")
  fi
  container_run "$engine" -d --name "$name" --network none "$image" /bin/sh -c 'sleep 120' >/dev/null
  record_sample exec-bin-true "$engine" "$round" engine_cmd "$engine" exec "$name" /bin/true
  remove_container "$engine" "$name"
}

logs_1000_lines() {
  local engine="$1" round="$2" name
  name="$(new_name logs-1000-lines "$engine" "$round")"
  if [[ "$engine" == docker ]]; then
    docker_containers+=("$name")
  fi
  container_run "$engine" -d --name "$name" --network none "$image" /bin/sh -c \
    'i=0; while [ "$i" -lt 1000 ]; do echo "line-$i"; i=$((i + 1)); done' >/dev/null
  engine_cmd "$engine" wait "$name" >/dev/null
  record_sample logs-1000-lines "$engine" "$round" engine_cmd "$engine" logs "$name"
  remove_container "$engine" "$name"
}

ps_a() {
  local engine="$1" round="$2"
  if [[ "$engine" == docker ]]; then
    record_sample ps-a "$engine" "$round" engine_cmd "$engine" ps -a
  else
    record_sample ps-a "$engine" "$round" engine_cmd "$engine" containers --all
  fi
}

images_list() {
  local engine="$1" round="$2"
  record_sample images-list "$engine" "$round" engine_cmd "$engine" images
}

volume_create() {
  local engine="$1" round="$2" name
  name="$(new_name volume-create "$engine" "$round")"
  if [[ "$engine" == docker ]]; then
    docker_volumes+=("$name")
  fi
  record_sample volume-create "$engine" "$round" volume_create_cmd "$engine" "$name"
  remove_volume "$engine" "$name"
}

pull_alpine_3_19_cold() {
  local engine="$1" round="$2"
  if [[ "$engine" == docker && "$isolated_docker" == 1 ]]; then
    # This destructive reset is permitted only by the explicit dedicated
    # Docker-engine contract. A successful empty lookup is required after the
    # reset; removal failure alone must never turn a warm pull into evidence.
    docker_cmd image rm "$pull_image" >/dev/null 2>&1 || true
    if ! docker_image_tag_absent "$pull_image"; then
      record_unavailable pull-alpine-3-19-cold "$engine" "$round"
      return
    fi
  fi
  record_sample pull-alpine-3-19-cold "$engine" "$round" engine_cmd "$engine" pull "$pull_image"
  if [[ "$engine" == docker && "$isolated_docker" == 1 ]]; then
    docker_cmd image rm "$pull_image" >/dev/null 2>&1 || true
  fi
}

build_context="$work_root/build-context"
mkdir -p "$build_context"
printf 'FROM scratch\nCOPY payload /payload\n' >"$build_context/Dockerfile"
printf 'ferrocrate parity benchmark\n' >"$build_context/payload"

build_once() {
  local engine="$1" tag="$2" no_cache="$3"
  if [[ "$engine" == docker ]]; then
    if [[ "$no_cache" == 1 ]]; then
      (cd "$build_context" && docker_cmd build --no-cache --label "$owner_label" --tag "$tag" .)
    else
      (cd "$build_context" && docker_cmd build --label "$owner_label" --tag "$tag" .)
    fi
  else
    (cd "$build_context" && ferro_cmd build --dockerfile Dockerfile --tag "$tag")
  fi
}

build_copy_only_no_cache() {
  local engine="$1" round="$2" tag
  tag="$(new_name build-copy-only-no-cache "$engine" "$round"):latest"
  if [[ "$engine" == docker ]]; then
    docker_images+=("$tag")
  fi
  record_sample build-copy-only-no-cache "$engine" "$round" build_once "$engine" "$tag" 1
}

build_copy_only_cached() {
  local engine="$1" round="$2" tag
  tag="$(new_name build-copy-only-cached "$engine" "$round"):latest"
  if [[ "$engine" == docker ]]; then
    docker_images+=("$tag")
  fi
  build_once "$engine" "$tag" 0 >/dev/null
  record_sample build-copy-only-cached "$engine" "$round" build_once "$engine" "$tag" 0
}

run_operation() {
  local operation="$1" engine="$2" round="$3"
  # Docker's image store is shared unless the caller explicitly asserts a
  # dedicated daemon. In the default mode, preserve honest evidence rather
  # than timing a potentially warm pull as "cold".
  if [[ "$operation" == pull-alpine-3-19-cold && "$isolated_docker" == 0 ]]; then
    record_unavailable "$operation" "$engine" "$round"
    return
  fi
  if [[ "$engine" == ferro ]]; then
    prepare_ferro_fixture "$operation" "$round"
  fi
  case "$operation" in
    run-to-exit) run_to_exit "$engine" "$round" ;;
    start-detached) start_detached "$engine" "$round" ;;
    stop-t-1) stop_t_1 "$engine" "$round" ;;
    exec-bin-true) exec_bin_true "$engine" "$round" ;;
    logs-1000-lines) logs_1000_lines "$engine" "$round" ;;
    ps-a) ps_a "$engine" "$round" ;;
    images-list) images_list "$engine" "$round" ;;
    volume-create) volume_create "$engine" "$round" ;;
    pull-alpine-3-19-cold) pull_alpine_3_19_cold "$engine" "$round" ;;
    build-copy-only-no-cache) build_copy_only_no_cache "$engine" "$round" ;;
    build-copy-only-cached) build_copy_only_cached "$engine" "$round" ;;
  esac
}

rounds_for() {
  case "$1" in
    pull-alpine-3-19-cold|build-copy-only-no-cache|build-copy-only-cached) printf '%s\n' "$slow_rounds" ;;
    *) printf '%s\n' "$rounds" ;;
  esac
}

median_for() {
  local operation="$1" engine="$2" expected_rounds="$3"
  local values
  values="$(awk -F '\t' -v operation="$operation" -v engine="$engine" -v expected="$expected_rounds" '
    $1 == operation && $2 == engine {
      samples++
      if ($5 != "ok") incomplete = 1
      values[samples] = $4
    }
    END {
      if (incomplete || samples != expected) { print "n/a"; exit }
      for (i = 1; i <= samples; i++) print values[i]
    }
  ' "$samples_tmp")"
  if [[ "$values" == n/a ]]; then
    printf 'n/a\n'
    return
  fi
  printf '%s\n' "$values" | sort -n | awk '
    { values[NR] = $1 }
    END {
      if (NR % 2) { printf "%.6f\n", values[(NR + 1) / 2] }
      else { printf "%.6f\n", (values[NR / 2] + values[NR / 2 + 1]) / 2 }
    }
  '
}

operation_label() {
  case "$1" in
    run-to-exit) echo 'run to exit (attached, /bin/true)' ;;
    start-detached) echo 'start detached' ;;
    stop-t-1) echo 'stop (t=1)' ;;
    exec-bin-true) echo 'exec /bin/true' ;;
    logs-1000-lines) echo 'logs (1000 lines)' ;;
    ps-a) echo 'ps -a' ;;
    images-list) echo 'images list' ;;
    volume-create) echo 'volume create' ;;
    pull-alpine-3-19-cold) echo 'pull alpine:3.19 (cold)' ;;
    build-copy-only-no-cache) echo 'build, COPY-only, no cache' ;;
    build-copy-only-cached) echo 'build, COPY-only, cached' ;;
  esac
}

printf 'operation\tengine\tround\telapsed_seconds\tstatus\n' >"$samples_tmp"
prepare_docker_fixture
for operation in "${operation_ids[@]}"; do
  operation_rounds="$(rounds_for "$operation")"
  for ((round = 1; round <= operation_rounds; round++)); do
    run_operation "$operation" docker "$round"
    run_operation "$operation" ferro "$round"
  done
done

cp "$samples_tmp" "$samples_file"
{
  printf 'generated_at_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'host=%s\n' "$(uname -srmo)"
  printf 'git_commit=%s\n' "$(git -C "$repo_root" rev-parse --short HEAD 2>/dev/null || echo unknown)"
  printf 'docker_version=%s\n' "$(docker_cmd version --format '{{.Client.Version}}' 2>/dev/null || echo unavailable)"
  printf 'ferro_cli=%s\n' "$ferro_bin"
  printf 'image=%s\n' "$image"
  printf 'pull_image=%s\n' "$pull_image"
  printf 'cold_pull_rounds_available=%s\n' "$isolated_docker"
  printf 'isolated_docker_contract=%s\n' "$isolated_docker"
  printf 'docker_config_isolated=true\n'
  printf 'rounds=%s\nslow_rounds=%s\ntimeout_seconds=%s\n' "$rounds" "$slow_rounds" "$timeout_seconds"
} >"$metadata_file"

{
  echo '# Docker vs FerroCrate parity benchmark'
  echo
  echo "Generated from paired command samples. Raw evidence: \`samples.tsv\`; environment: \`metadata.txt\`."
  echo
  echo '| Operation | Docker median (s) | FerroCrate median (s) | Delta | Winner |'
  echo '|---|---:|---:|---:|---|'
  for operation in "${operation_ids[@]}"; do
    operation_rounds="$(rounds_for "$operation")"
    docker_median="$(median_for "$operation" docker "$operation_rounds")"
    ferro_median="$(median_for "$operation" ferro "$operation_rounds")"
    if [[ "$docker_median" == n/a || "$ferro_median" == n/a ]]; then
      delta='n/a'
      winner='n/a'
    else
      delta="$(awk -v docker="$docker_median" -v ferro="$ferro_median" 'BEGIN { printf "%+.1f%%", ((ferro - docker) * 100) / docker }')"
      winner="$(awk -v docker="$docker_median" -v ferro="$ferro_median" 'BEGIN { print (ferro < docker) ? "FerroCrate" : ((ferro > docker) ? "Docker" : "tie") }')"
    fi
    printf '| %s | %s | %s | %s | %s |\n' "$(operation_label "$operation")" "$docker_median" "$ferro_median" "$delta" "$winner"
  done
} >"$summary_tmp"
mv "$summary_tmp" "$summary_file"

printf 'Docker parity benchmark complete: %s\n' "$output_dir"
if (( failures > 0 )); then
  echo "${failures} timed samples failed; inspect $samples_file" >&2
  exit 1
fi
