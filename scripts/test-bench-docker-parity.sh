#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
runner="$repo_root/scripts/bench-docker-parity.sh"

bash -n "$runner"

expected_operations=(
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

tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/ferrocrate-docker-parity-test.XXXXXX")"
trap 'rm -rf -- "$tmp_root"' EXIT
output_dir="$tmp_root/not-created"

mapfile -t listed_operations < <("$runner" --output-dir "$output_dir" --list)
if [[ "${#listed_operations[@]}" -ne "${#expected_operations[@]}" ]]; then
  echo "expected ${#expected_operations[@]} benchmark operations, got ${#listed_operations[@]}" >&2
  exit 1
fi
for index in "${!expected_operations[@]}"; do
  if [[ "${listed_operations[$index]}" != "${expected_operations[$index]}" ]]; then
    echo "unexpected operation at position $index: ${listed_operations[$index]:-<missing>}" >&2
    exit 1
  fi
done
if [[ -e "$output_dir" ]]; then
  echo "--list must not create its output directory" >&2
  exit 1
fi

for args in \
  '--rounds 0' \
  '--rounds 101' \
  '--slow-rounds 0' \
  '--slow-rounds 101' \
  '--timeout 0' \
  '--timeout 301'; do
  if "$runner" --list $args >/dev/null 2>&1; then
    echo "accepted invalid bounded configuration: $args" >&2
    exit 1
  fi
done

# Docker must only be reached through docker_cmd so preflight, cleanup, and
# metadata collection receive the same timeout as measured commands.
if rg -n '^[[:space:]]*docker[[:space:]]' "$runner" >/dev/null; then
  echo "found an unbounded direct Docker invocation" >&2
  exit 1
fi
grep -Fq 'timeout --foreground --kill-after=5s' "$runner"
grep -Fq 'FERROCRATE_DOCKER_PARITY_ISOLATED_DOCKER' "$runner"
grep -Fq 'od -An -N16 -tx1 /dev/urandom' "$runner"
grep -Fq 'io.ferrocrate.parity-run' "$runner"
for function_name in start_detached stop_t_1 exec_bin_true logs_1000_lines; do
  function_body="$(awk -v function_name="$function_name" '
    $0 == function_name "() {" { capture = 1 }
    capture { print }
    capture && $0 == "}" { exit }
  ' "$runner")"
  registration_line="$(printf '%s\n' "$function_body" | grep -n 'docker_containers+=' | head -n1 | cut -d: -f1)"
  setup_line="$(printf '%s\n' "$function_body" | grep -n 'container_run ' | head -n1 | cut -d: -f1 || true)"
  if [[ -z "$registration_line" || -z "$setup_line" || "$registration_line" -ge "$setup_line" ]]; then
    echo "$function_name does not register its planned container before setup" >&2
    exit 1
  fi
done

fixture_dir="$repo_root/scripts/test-fixtures/docker-parity"
fake_output="$tmp_root/fake-output"
set +e
PATH="$fixture_dir:$PATH" \
  FERROCRATE_BIN="$fixture_dir/ferro-cli" \
  FAKE_DOCKER_FAIL_PS_A=1 \
  "$runner" --rounds 1 --slow-rounds 1 --timeout 1 --output-dir "$fake_output" \
  >"$tmp_root/partial-failure.stdout" 2>"$tmp_root/partial-failure.stderr"
partial_failure_status=$?
set -e
if [[ "$partial_failure_status" -eq 0 ]]; then
  echo "benchmark accepted a deliberately failed timed sample" >&2
  exit 1
fi
grep -qx $'ps-a\tdocker\t1\t[0-9.]*\tfailed' "$fake_output/samples.tsv"
grep -Fq '| ps -a | n/a |' "$fake_output/summary.md"

if PATH="$fixture_dir:$PATH" \
  FERROCRATE_BIN="$fixture_dir/ferro-cli" \
  FERROCRATE_DOCKER_PARITY_IMAGE=alpine:3.19 \
  "$runner" --rounds 1 --slow-rounds 1 --timeout 1 --output-dir "$tmp_root/equal-images" \
  >"$tmp_root/equal-images.stdout" 2>"$tmp_root/equal-images.stderr"; then
  echo "benchmark accepted a fixture image equal to the cold-pull image" >&2
  exit 1
fi
grep -Fq 'must differ from FERROCRATE_DOCKER_PARITY_PULL_IMAGE' "$tmp_root/equal-images.stderr"

cold_output="$tmp_root/cold-output"
cold_log="$tmp_root/cold.log"
PATH="$fixture_dir:$PATH" \
  FERROCRATE_BIN="$fixture_dir/ferro-cli" \
  FAKE_DOCKER_LOG="$cold_log" \
  "$runner" --rounds 1 --slow-rounds 2 --timeout 1 --output-dir "$cold_output" \
  >"$tmp_root/cold.stdout" 2>"$tmp_root/cold.stderr"
grep -qx $'pull-alpine-3-19-cold\tdocker\t1\t0\.000000\tunavailable' "$cold_output/samples.tsv"
grep -qx $'pull-alpine-3-19-cold\tdocker\t2\t0\.000000\tunavailable' "$cold_output/samples.tsv"
grep -Fq '| pull alpine:3.19 (cold) | n/a | n/a | n/a | n/a |' "$cold_output/summary.md"
if grep -Fxq 'pull alpine:3.19' "$cold_log"; then
  echo "shared Docker engine recorded a cold pull as measured evidence" >&2
  exit 1
fi

isolated_output="$tmp_root/isolated-output"
isolated_log="$tmp_root/isolated.log"
PATH="$fixture_dir:$PATH" \
  FERROCRATE_BIN="$fixture_dir/ferro-cli" \
  FERROCRATE_DOCKER_PARITY_ISOLATED_DOCKER=1 \
  FAKE_DOCKER_LOG="$isolated_log" \
  FAKE_DOCKER_STATE="$tmp_root/isolated-state" \
  "$runner" --rounds 1 --slow-rounds 2 --timeout 1 --output-dir "$isolated_output" \
  >"$tmp_root/isolated.stdout" 2>"$tmp_root/isolated.stderr"
grep -qx $'pull-alpine-3-19-cold\tdocker\t1\t[0-9.]*\tok' "$isolated_output/samples.tsv"
grep -qx $'pull-alpine-3-19-cold\tdocker\t2\t[0-9.]*\tok' "$isolated_output/samples.tsv"
if grep -Fq '| pull alpine:3.19 (cold) | n/a |' "$isolated_output/summary.md"; then
  echo "isolated Docker contract did not produce a cold-pull median" >&2
  exit 1
fi
[[ "$(grep -Fxc 'pull alpine:3.19' "$isolated_log")" -eq 2 ]]

blocked_eviction_output="$tmp_root/blocked-eviction-output"
blocked_eviction_log="$tmp_root/blocked-eviction.log"
PATH="$fixture_dir:$PATH" \
  FERROCRATE_BIN="$fixture_dir/ferro-cli" \
  FERROCRATE_DOCKER_PARITY_ISOLATED_DOCKER=1 \
  FAKE_DOCKER_FAIL_PULL_EVICTION=1 \
  FAKE_DOCKER_LOG="$blocked_eviction_log" \
  FAKE_DOCKER_STATE="$tmp_root/blocked-eviction-state" \
  "$runner" --rounds 1 --slow-rounds 1 --timeout 1 --output-dir "$blocked_eviction_output" \
  >"$tmp_root/blocked-eviction.stdout" 2>"$tmp_root/blocked-eviction.stderr"
grep -qx $'pull-alpine-3-19-cold\tdocker\t1\t0\.000000\tunavailable' \
  "$blocked_eviction_output/samples.tsv"
grep -Fq '| pull alpine:3.19 (cold) | n/a |' "$blocked_eviction_output/summary.md"
if grep -Fxq 'pull alpine:3.19' "$blocked_eviction_log"; then
  echo "benchmark timed a Docker pull after failing to prove the tag absent" >&2
  exit 1
fi

cleanup_log="$tmp_root/cleanup.log"
set +e
PATH="$fixture_dir:$PATH" \
  FERROCRATE_BIN="$fixture_dir/ferro-cli" \
  FAKE_DOCKER_FAIL_RUN=1 \
  FAKE_DOCKER_LOG="$cleanup_log" \
  FAKE_DOCKER_STATE="$tmp_root/cleanup-state" \
  "$runner" --rounds 1 --slow-rounds 1 --timeout 1 --output-dir "$tmp_root/cleanup-output" \
  >"$tmp_root/cleanup.stdout" 2>"$tmp_root/cleanup.stderr"
cleanup_failure_status=$?
set -e
if [[ "$cleanup_failure_status" -eq 0 ]]; then
  echo "benchmark accepted a failed setup command" >&2
  exit 1
fi
grep -Eq '^container inspect --format .*\.Id.*ferrocrate-parity-.*-start-detached-docker-1$' \
  "$cleanup_log"
grep -Fxq 'rm -f 1111111111111111111111111111111111111111111111111111111111111111' \
  "$cleanup_log"

foreign_log="$tmp_root/foreign.log"
set +e
PATH="$fixture_dir:$PATH" \
  FERROCRATE_BIN="$fixture_dir/ferro-cli" \
  FAKE_DOCKER_FAIL_RUN=1 \
  FAKE_DOCKER_FOREIGN_CONTAINER=1 \
  FAKE_DOCKER_LOG="$foreign_log" \
  FAKE_DOCKER_STATE="$tmp_root/foreign-state" \
  "$runner" --rounds 1 --slow-rounds 1 --timeout 1 --output-dir "$tmp_root/foreign-output" \
  >"$tmp_root/foreign.stdout" 2>"$tmp_root/foreign.stderr"
foreign_failure_status=$?
set -e
if [[ "$foreign_failure_status" -eq 0 ]]; then
  echo "benchmark accepted a failed foreign-collision setup command" >&2
  exit 1
fi
grep -Eq '^container inspect --format .*ferrocrate-parity-.*-start-detached-docker-1$' "$foreign_log"
if grep -Eq '^rm -f ferrocrate-parity-.*-start-detached-docker-1$' "$foreign_log"; then
  echo "benchmark removed an unowned colliding container" >&2
  exit 1
fi
if grep -Eq '^rm -f [0-9a-f]{64}$' "$foreign_log"; then
  echo "benchmark removed a container whose inspected label was foreign" >&2
  exit 1
fi

race_log="$tmp_root/replacement-races.log"
PATH="$fixture_dir:$PATH" \
  FERROCRATE_BIN="$fixture_dir/ferro-cli" \
  FAKE_DOCKER_REPLACE_AFTER_INSPECT=1 \
  FAKE_DOCKER_LOG="$race_log" \
  FAKE_DOCKER_STATE="$tmp_root/replacement-races-state" \
  "$runner" --rounds 1 --slow-rounds 1 --timeout 1 \
  --output-dir "$tmp_root/replacement-races-output" \
  >"$tmp_root/replacement-races.stdout" 2>"$tmp_root/replacement-races.stderr"
grep -Fxq 'rm -f 1111111111111111111111111111111111111111111111111111111111111111' \
  "$race_log"
if grep -Eq '^rm -f ferrocrate-parity-' "$race_log"; then
  echo "container cleanup resolved a mutable name after its ownership check" >&2
  exit 1
fi
grep -Fxq 'image rm sha256:2222222222222222222222222222222222222222222222222222222222222222' \
  "$race_log"
if grep -Eq '^image rm (-f )?ferrocrate-parity-' "$race_log"; then
  echo "image cleanup resolved a mutable tag after its ownership check" >&2
  exit 1
fi
grep -Eq '^volume prune --all --force --filter label=io\.ferrocrate\.parity-run=[0-9a-f]{32}$' \
  "$race_log"
if grep -Eq '^volume rm ferrocrate-parity-' "$race_log"; then
  echo "volume cleanup used a racy inspect-then-remove-by-name sequence" >&2
  exit 1
fi
if grep -Eq '^replacement-(container|image|volume)-deleted ' "$race_log"; then
  echo "cleanup deleted a replacement created after ownership inspection" >&2
  exit 1
fi

alias_log="$tmp_root/same-id-foreign-alias.log"
PATH="$fixture_dir:$PATH" \
  FERROCRATE_BIN="$fixture_dir/ferro-cli" \
  FAKE_DOCKER_SAME_ID_FOREIGN_ALIAS=1 \
  FAKE_DOCKER_LOG="$alias_log" \
  FAKE_DOCKER_STATE="$tmp_root/same-id-foreign-alias-state" \
  "$runner" --rounds 1 --slow-rounds 1 --timeout 1 \
  --output-dir "$tmp_root/same-id-foreign-alias-output" \
  >"$tmp_root/same-id-foreign-alias.stdout" 2>"$tmp_root/same-id-foreign-alias.stderr"
grep -Fxq 'image rm sha256:2222222222222222222222222222222222222222222222222222222222222222' \
  "$alias_log"
grep -Fxq 'foreign-image-alias-preserved' "$alias_log"
if grep -Fxq 'foreign-image-alias-deleted' "$alias_log"; then
  echo "forced image cleanup deleted a foreign alias sharing the run-owned image ID" >&2
  exit 1
fi

echo "docker parity benchmark contract tests passed"
