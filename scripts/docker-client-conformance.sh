#!/usr/bin/env bash
# Generate a Docker-client conformance scoreboard against an isolated
# FerroCrate Docker-compatible daemon.
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ferro_bin="${FERROCRATE_BIN:-$repo_root/target/debug/ferro-cli}"
fixture="$repo_root/tests/fixtures/real-app/compose.yml"
output="$repo_root/docs/compatibility/parity-scoreboard.md"
execution_log="$repo_root/target/docker-client-conformance/docker-client-conformance.log"
command_timeout="${FERROCRATE_CONFORMANCE_TIMEOUT_SECONDS:-240}"
daemon_timeout="${FERROCRATE_CONFORMANCE_DAEMON_TIMEOUT_SECONDS:-20}"

usage() {
  cat <<'USAGE'
Usage: scripts/docker-client-conformance.sh [options]

Run genuine Docker and Compose clients against an isolated FerroCrate daemon,
record every declared invocation, and atomically generate a Markdown scoreboard.

Options:
  --output <path>  Markdown scoreboard (default: docs/compatibility/parity-scoreboard.md)
  --log <path>     Tab-separated execution log (default: target/docker-client-conformance/docker-client-conformance.log)
  -h, --help       Show this help

Required environment:
  DOCKER_BUILDKIT=0

Optional environment:
  FERROCRATE_BIN                                  ferro-cli executable
  FERROCRATE_CONFORMANCE_TIMEOUT_SECONDS          per-client timeout (default: 240)
  FERROCRATE_CONFORMANCE_DAEMON_TIMEOUT_SECONDS   daemon readiness timeout (default: 20)
USAGE
}

harness_error() {
  echo "HARNESS ERROR: $*" >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      [[ $# -ge 2 ]] || harness_error "--output requires a path"
      output="$2"
      shift 2
      ;;
    --log)
      [[ $# -ge 2 ]] || harness_error "--log requires a path"
      execution_log="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      harness_error "unknown option: $1"
      ;;
  esac
done

[[ -n "$output" && "$output" != *$'\n'* ]] || harness_error "--output must be a non-empty path without newlines"
[[ -n "$execution_log" && "$execution_log" != *$'\n'* ]] || harness_error "--log must be a non-empty path without newlines"
[[ "$output" != "$execution_log" ]] || harness_error "--output and --log must be different paths"
[[ ! -d "$output" ]] || harness_error "--output must not be an existing directory: $output"
[[ ! -d "$execution_log" ]] || harness_error "--log must not be an existing directory: $execution_log"
[[ "$command_timeout" =~ ^[1-9][0-9]*$ ]] && (( command_timeout <= 600 )) ||
  harness_error "FERROCRATE_CONFORMANCE_TIMEOUT_SECONDS must be an integer in 1..600"
[[ "$daemon_timeout" =~ ^[1-9][0-9]*$ ]] && (( daemon_timeout <= 120 )) ||
  harness_error "FERROCRATE_CONFORMANCE_DAEMON_TIMEOUT_SECONDS must be an integer in 1..120"
[[ "${DOCKER_BUILDKIT:-}" == 0 ]] || harness_error "DOCKER_BUILDKIT=0 is required for FerroCrate's classic builder"
[[ "$(uname -s)" == Linux ]] || harness_error "the Docker-compatible daemon is Linux-only"
[[ -x "$ferro_bin" ]] || harness_error "missing executable ferro-cli: $ferro_bin"
command -v docker >/dev/null 2>&1 || harness_error "docker CLI is unavailable"
command -v timeout >/dev/null 2>&1 || harness_error "timeout is required"
command -v setsid >/dev/null 2>&1 || harness_error "setsid is required for bounded daemon cleanup"
command -v awk >/dev/null 2>&1 || harness_error "awk is required"
[[ -x /bin/busybox ]] || harness_error "/bin/busybox is required for the offline image fixture"
[[ -f "$fixture" ]] || harness_error "missing Compose fixture: $fixture"
[[ -f "$repo_root/tests/fixtures/real-app/webroot/index.html" ]] || harness_error "incomplete Compose fixture: webroot/index.html"
[[ -f "$repo_root/tests/fixtures/real-app/apiroot/index.json" ]] || harness_error "incomplete Compose fixture: apiroot/index.json"

output_parent="$(dirname "$output")"
log_parent="$(dirname "$execution_log")"
mkdir -p "$output_parent" || harness_error "cannot create output directory: $output_parent"
mkdir -p "$log_parent" || harness_error "cannot create log directory: $log_parent"

work_root="$(mktemp -d "${TMPDIR:-/tmp}/ferrocrate-client-conformance.XXXXXX")" ||
  harness_error "cannot create temporary work directory"
runtime_dir="$work_root/runtime"
docker_config="$work_root/docker-config"
context_dir="$work_root/context"
outputs_dir="$work_root/outputs"
mkdir -p "$runtime_dir" "$docker_config" "$context_dir" "$outputs_dir" ||
  harness_error "cannot initialize temporary work directory"

socket="$runtime_dir/docker.sock"
host="unix://$socket"
log_tmp="$work_root/executions.tsv"
scoreboard_tmp=""
daemon_pid=""
daemon_ready=0
run_id="scoreboard"
run_prefix="ferrocrate-conformance-$run_id"
owner_label="io.ferrocrate.conformance-run=$run_id"
image="$run_prefix:latest"
container="$run_prefix-main"
attach_container="$run_prefix-attach"
compose_project="$run_prefix-compose"
host_port=18093

cleanup() {
  local fixture_pids
  if [[ "$daemon_ready" == 1 ]]; then
    timeout --foreground --kill-after=3s 15s \
      env DOCKER_HOST="$host" DOCKER_CONFIG="$docker_config" DOCKER_BUILDKIT=0 \
      docker compose --project-name "$compose_project" --file "$fixture" down --timeout 2 \
      >/dev/null 2>&1 || true
    timeout --foreground --kill-after=3s 15s \
      env DOCKER_HOST="$host" DOCKER_CONFIG="$docker_config" DOCKER_BUILDKIT=0 \
      docker rm --force "$container" "$attach_container" >/dev/null 2>&1 || true
    timeout --foreground --kill-after=3s 15s \
      env DOCKER_HOST="$host" DOCKER_CONFIG="$docker_config" DOCKER_BUILDKIT=0 \
      docker image rm --force "$image" >/dev/null 2>&1 || true
  fi
  if [[ -n "$daemon_pid" ]]; then
    kill -TERM -- "-$daemon_pid" 2>/dev/null || kill "$daemon_pid" 2>/dev/null || true
    for _ in $(seq 1 20); do
      kill -0 "$daemon_pid" 2>/dev/null || break
      sleep 0.05
    done
    kill -KILL -- "-$daemon_pid" 2>/dev/null || kill -KILL "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
  fi
  if [[ -d "$runtime_dir" ]]; then
    fixture_pids="$(ps -eo pid=,args= | awk -v root="$runtime_dir" 'index($0, root) && /\/bwrap/ { print $1 }')"
    if [[ -n "$fixture_pids" ]]; then
      kill -TERM $fixture_pids 2>/dev/null || true
      sleep 0.1
      kill -KILL $fixture_pids 2>/dev/null || true
    fi
  fi
  [[ -z "$scoreboard_tmp" ]] || rm -f -- "$scoreboard_tmp"
  rm -rf -- "$work_root"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cp /bin/busybox "$context_dir/busybox" || harness_error "cannot copy /bin/busybox into build fixture"
chmod 0755 "$context_dir/busybox" || harness_error "cannot make build fixture executable"
printf 'offline conformance fixture\n' >"$context_dir/marker.txt" || harness_error "cannot write build fixture"
printf 'FROM scratch\nLABEL io.ferrocrate.conformance-run="%s"\nCOPY busybox /bin/busybox\nCOPY marker.txt /marker.txt\n' \
  "$run_id" >"$context_dir/Dockerfile" || harness_error "cannot write Dockerfile fixture"
printf 'conformance-copy-marker\n' >"$work_root/copy-marker.txt" || harness_error "cannot write copy fixture"
printf 'contract-password\n' >"$work_root/login-password.txt" || harness_error "cannot write login fixture"

rootless_netns="${FERROCRATE_ROOTLESS_NETNS:-1}"
network_backend="${FERROCRATE_NETWORK_BACKEND:-iptables}"
setsid env \
  FERROCRATE_RUNTIME_DIR="$runtime_dir" \
  FERROCRATE_ROOTLESS_NETNS="$rootless_netns" \
  FERROCRATE_NETWORK_BACKEND="$network_backend" \
  "$ferro_bin" daemon --docker-compat --socket "$socket" \
  >"$work_root/daemon.stdout" 2>"$work_root/daemon.stderr" &
daemon_pid=$!

for (( attempt = 0; attempt < daemon_timeout * 10; attempt++ )); do
  if [[ -S "$socket" ]]; then
    daemon_ready=1
    break
  fi
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    daemon_message="$(tail -n 20 "$work_root/daemon.stderr" 2>/dev/null | tr '\n' ' ')"
    harness_error "FerroCrate daemon exited before readiness${daemon_message:+: $daemon_message}"
  fi
  sleep 0.1
done
if [[ "$daemon_ready" != 1 ]]; then
  daemon_message="$(tail -n 20 "$work_root/daemon.stderr" 2>/dev/null | tr '\n' ' ')"
  harness_error "FerroCrate daemon socket was not ready within ${daemon_timeout}s${daemon_message:+: $daemon_message}"
fi

printf 'sequence\tid\tarea\tcommand\texit_code\tstatus\tduration_ms\n' >"$log_tmp"
sequence=0
pass_count=0
fail_count=0
error_count=0
record_stdin="/dev/null"

shell_command() {
  local rendered="docker" argument
  for argument in "$@"; do
    argument="${argument//$work_root/<workdir>}"
    argument="${argument//$repo_root/<repo>}"
    printf -v argument '%q' "$argument"
    rendered+=" $argument"
  done
  printf '%s' "$rendered"
}

record_command() {
  local id="$1" area="$2"
  shift 2
  local command_text started ended duration exit_code status stdout_file stderr_file
  sequence=$((sequence + 1))
  printf -v stdout_file '%s/%03d.stdout' "$outputs_dir" "$sequence"
  printf -v stderr_file '%s/%03d.stderr' "$outputs_dir" "$sequence"
  command_text="$(shell_command "$@")"
  started="$(date +%s%N)"
  if timeout --foreground --kill-after=5s "${command_timeout}s" \
    env DOCKER_HOST="$host" DOCKER_CONFIG="$docker_config" DOCKER_BUILDKIT=0 \
      FERROCRATE_CONFORMANCE_RECORD_ID="$id" docker "$@" \
      <"$record_stdin" >"$stdout_file" 2>"$stderr_file"; then
    exit_code=0
  else
    exit_code=$?
  fi
  ended="$(date +%s%N)"
  duration=$(((ended - started) / 1000000))
  case "$exit_code" in
    0)
      status=PASS
      pass_count=$((pass_count + 1))
      ;;
    124|126|127|137)
      status=ERROR
      error_count=$((error_count + 1))
      ;;
    *)
      status=FAIL
      fail_count=$((fail_count + 1))
      ;;
  esac
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$sequence" "$id" "$area" "$command_text" "$exit_code" "$status" "$duration" >>"$log_tmp"
  record_stdin="/dev/null"
}

# Client identity and engine prerequisites.
record_command cli-version client version
record_command compose-version compose compose version
record_command engine-info client info

# Offline image and broad container lifecycle prerequisites. These calls are
# deliberately unconditional: one failed command must not suppress later rows.
record_command image-build image build --tag "$image" "$context_dir"
record_command image-inspect image image inspect "$image"
record_command container-create container create --label "$owner_label" --name "$container" \
  --publish "127.0.0.1:${host_port}:8080" "$image" /bin/busybox sleep 120
record_command container-start container start "$container"
record_command container-inspect container inspect "$container"
record_command container-list container ps --all
record_command container-port container port "$container" 8080/tcp
record_command container-copy-in container cp "$work_root/copy-marker.txt" "$container":/copy-marker.txt
record_command container-diff container diff "$container"
record_command container-update container update --memory 64m --pids-limit 64 "$container"
record_command container-export container container export --output "$work_root/container-export.tar" "$container"
record_command container-stop container stop --time 1 "$container"
record_command container-wait container wait "$container"
record_command container-logs container logs "$container"
record_command container-remove container rm "$container"

# Save/remove/load makes both archive directions meaningful rather than merely
# probing their help or argument parsing paths.
record_command image-save image save --output "$work_root/image-save.tar" "$image"
record_command image-remove image image rm "$image"
record_command image-load image load --input "$work_root/image-save.tar"
record_command image-list image images "$image"

# Attach uses a finite workload so a conforming client closes naturally.
record_command attach-container-create container create --label "$owner_label" --name "$attach_container" \
  --network none "$image" /bin/busybox sh -c '/bin/busybox sleep 2; echo ferrocrate-conformance-attach'
record_command attach-container-start container start "$attach_container"
record_command container-attach container attach --no-stdin --sig-proxy=false "$attach_container"
record_command attach-container-wait container wait "$attach_container"
record_command attach-container-remove container rm --force "$attach_container"

# Discovery/auth use isolated Docker credentials. Login intentionally targets
# a closed local endpoint; a nonzero response remains useful, recorded parity
# evidence without sending credentials to an external registry.
record_command registry-search registry search busybox --limit 5
record_stdin="$work_root/login-password.txt"
record_command registry-login registry login --username conformance --password-stdin 127.0.0.1:1
record_command registry-logout registry logout 127.0.0.1:1

# Genuine Compose plugin invocations against the repository's representative
# four-service application fixture.
record_command compose-up compose compose --ansi never --project-name "$compose_project" \
  --file "$fixture" up --detach
record_command compose-ps compose compose --ansi never --project-name "$compose_project" \
  --file "$fixture" ps --all
record_command compose-logs compose compose --ansi never --project-name "$compose_project" \
  --file "$fixture" logs --no-color
record_command compose-down compose compose --ansi never --project-name "$compose_project" \
  --file "$fixture" down --timeout 10
record_command system-prune cleanup system prune --force

generated_at="$(date -u +%Y-%m-%d)"
host_metadata="$(uname -srm)"
ferro_version="$(timeout --kill-after=5s "${command_timeout}s" \
  "$ferro_bin" --version 2>/dev/null | head -n 1)"
docker_client_version="$(awk '/^ Version:/ { print $2; exit }' "$outputs_dir/001.stdout")"
docker_server_version="$(awk '/^Server:/ { server = 1; next } server && /^[[:space:]]+Version:/ { print $2; exit }' "$outputs_dir/001.stdout")"
compose_version="$(head -n 1 "$outputs_dir/002.stdout" | tr '\t\r\n' '   ' | sed 's/[[:space:]]*$//')"
display_execution_log="$execution_log"
if [[ "$display_execution_log" == "$repo_root/"* ]]; then
  display_execution_log="${display_execution_log#"$repo_root/"}"
fi
[[ -n "$ferro_version" ]] || ferro_version="unavailable"
[[ -n "$docker_client_version" ]] || docker_client_version="unavailable"
[[ -n "$docker_server_version" ]] || docker_server_version="unavailable"
[[ -n "$compose_version" ]] || compose_version="unavailable"

scoreboard_tmp="$(mktemp "$output_parent/.parity-scoreboard.tmp.XXXXXX")" ||
  harness_error "cannot create atomic scoreboard file"
{
  cat <<EOF
# Docker Client Parity Scoreboard

This file is generated by \`scripts/docker-client-conformance.sh\`. Every result
row below is rendered from the recorded execution log; command failures do not
stop later invocations.

## Reproducibility metadata

- Generated (UTC date): $generated_at
- Host: $host_metadata
- FerroCrate: $ferro_version
- Docker client: $docker_client_version
- Docker-compatible server: $docker_server_version
- Compose client: $compose_version
- Endpoint: isolated \`DOCKER_HOST=unix://<temporary-runtime>/docker.sock\`
- Builder: \`DOCKER_BUILDKIT=0\`
- Per-command timeout: ${command_timeout}s
- Compose fixture: \`tests/fixtures/real-app/compose.yml\`
- Execution log: \`$display_execution_log\`
- Command placeholders: \`<repo>\` is the repository root and \`<workdir>\` is
  the isolated temporary run directory.

## Totals

| Status | Count |
| --- | ---: |
| PASS | $pass_count |
| FAIL | $fail_count |
| ERROR | $error_count |
| **Total** | **$sequence** |

\`FAIL\` means the Docker/Compose client executed and returned a nonzero exit.
\`ERROR\` means the bounded invocation timed out or could not be launched.
Harness/setup errors exit 2 before replacing this file and are not represented
as command-result rows.

## Command results

| # | ID | Area | Executed command | Exit | Status |
| ---: | --- | --- | --- | ---: | --- |
EOF
  while IFS=$'\t' read -r row_sequence row_id row_area row_command row_exit row_status _row_duration; do
    [[ "$row_sequence" == sequence ]] && continue
    row_command="${row_command//|/\\|}"
    printf '| %s | %s | %s | `%s` | %s | %s |\n' \
      "$row_sequence" "$row_id" "$row_area" "$row_command" "$row_exit" "$row_status"
  done <"$log_tmp"
} >"$scoreboard_tmp" || harness_error "cannot render scoreboard"

log_publish_tmp="$(mktemp "$log_parent/.docker-client-conformance.tmp.XXXXXX")" ||
  harness_error "cannot create atomic execution log"
cp "$log_tmp" "$log_publish_tmp" || harness_error "cannot stage execution log"
mv -f -- "$log_publish_tmp" "$execution_log" || harness_error "cannot publish execution log"
mv -f -- "$scoreboard_tmp" "$output" || harness_error "cannot publish scoreboard"
scoreboard_tmp=""

echo "Docker client conformance complete: PASS=$pass_count FAIL=$fail_count ERROR=$error_count TOTAL=$sequence"
if (( fail_count > 0 || error_count > 0 )); then
  exit 1
fi
exit 0
