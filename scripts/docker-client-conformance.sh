#!/usr/bin/env bash
# Generate a Docker-client conformance scoreboard against an isolated
# FerroCrate Docker-compatible daemon.
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$repo_root/scripts/process-tree-ownership.sh"
ferro_bin="${FERROCRATE_BIN:-$repo_root/target/debug/ferro-cli}"
fixture="$repo_root/tests/fixtures/real-app/compose.yml"
if [[ "${DOCKER_BUILDKIT:-}" == 1 ]]; then
  output="$repo_root/docs/evidence/docker-client-conformance/2026-08-24-buildkit-fallback.md"
  execution_log="$repo_root/docs/evidence/docker-client-conformance/2026-08-24-buildkit-fallback.tsv"
else
  output="$repo_root/docs/compatibility/parity-scoreboard.md"
  execution_log="$repo_root/docs/evidence/docker-client-conformance/2026-08-23-parity-scoreboard.tsv"
fi
command_timeout="${FERROCRATE_CONFORMANCE_TIMEOUT_SECONDS:-240}"
daemon_timeout="${FERROCRATE_CONFORMANCE_DAEMON_TIMEOUT_SECONDS:-20}"

usage() {
  cat <<'USAGE'
Usage: scripts/docker-client-conformance.sh [options]

Run genuine Docker and Compose clients against an isolated FerroCrate daemon,
record every declared invocation, and atomically generate a Markdown scoreboard.

Options:
  --output <path>  Markdown scoreboard (defaults are mode-specific)
  --log <path>     Tab-separated execution log (defaults are mode-specific)
  -h, --help       Show this help

Required environment:
  DOCKER_BUILDKIT=0  Run and require the supported classic build row.
  DOCKER_BUILDKIT=1  Run the same matrix, qualifying the expected BuildKit
                     compatibility error on the build row only.

Optional environment:
  FERROCRATE_BIN                                  ferro-cli executable
  FERROCRATE_COMPOSE_BIN                          alternate standalone Compose executable
  FERROCRATE_CONFORMANCE_TIMEOUT_SECONDS          per-client timeout (default: 240)
  FERROCRATE_CONFORMANCE_DAEMON_TIMEOUT_SECONDS   daemon readiness timeout (default: 20)
  FERROCRATE_CONFORMANCE_STRESS                    1 adds a CPU-loaded 10x foreground/scale row
  FERROCRATE_PEER_AUTH                            pidfd (default) or legacy-peercred
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
builder_mode="${DOCKER_BUILDKIT:-}"
[[ "$builder_mode" == 0 || "$builder_mode" == 1 ]] ||
  harness_error "DOCKER_BUILDKIT must be 0 (classic) or 1 (BuildKit fallback qualification)"
peer_auth_mode="${FERROCRATE_PEER_AUTH:-pidfd}"
[[ "$peer_auth_mode" == pidfd || "$peer_auth_mode" == legacy-peercred ]] ||
  harness_error "FERROCRATE_PEER_AUTH must be pidfd or legacy-peercred"
stress_mode="${FERROCRATE_CONFORMANCE_STRESS:-0}"
[[ "$stress_mode" == 0 || "$stress_mode" == 1 ]] ||
  harness_error "FERROCRATE_CONFORMANCE_STRESS must be 0 or 1"
[[ "$(uname -s)" == Linux ]] || harness_error "the Docker-compatible daemon is Linux-only"
[[ -x "$ferro_bin" ]] || harness_error "missing executable ferro-cli: $ferro_bin"
command -v docker >/dev/null 2>&1 || harness_error "docker CLI is unavailable"
compose_bin="${FERROCRATE_COMPOSE_BIN:-}"
if [[ -n "$compose_bin" ]]; then
  [[ -x "$compose_bin" ]] || harness_error "FERROCRATE_COMPOSE_BIN is not executable: $compose_bin"
  compose_client=("$compose_bin")
else
  compose_client=(docker compose)
fi
command -v timeout >/dev/null 2>&1 || harness_error "timeout is required"
command -v setsid >/dev/null 2>&1 || harness_error "setsid is required for bounded daemon cleanup"
command -v unshare >/dev/null 2>&1 || harness_error "unshare is required for isolated rootful network conformance"
command -v ip >/dev/null 2>&1 || harness_error "ip is required for isolated rootful network conformance"
command -v slirp4netns >/dev/null 2>&1 || harness_error "slirp4netns is required for isolated network egress"
command -v awk >/dev/null 2>&1 || harness_error "awk is required"
command -v ps >/dev/null 2>&1 || harness_error "ps is required for descendant cleanup"
command -v sha256sum >/dev/null 2>&1 || harness_error "sha256sum is required"
command -v ldd >/dev/null 2>&1 || harness_error "ldd is required to verify the offline image fixture"
websocat_bin="${FERROCRATE_CONFORMANCE_WEBSOCAT:-}"
if [[ -z "$websocat_bin" ]]; then
  websocat_bin="$(command -v websocat 2>/dev/null || true)"
fi
if [[ -z "$websocat_bin" && -x /tmp/ferrocrate-websocat/bin/websocat ]]; then
  websocat_bin=/tmp/ferrocrate-websocat/bin/websocat
fi
[[ -x "$websocat_bin" ]] || harness_error "websocat is required for WebSocket attach conformance"
busybox_bin=""
if [[ -n "${FERROCRATE_CONFORMANCE_BUSYBOX:-}" ]]; then
  busybox_candidates=("$FERROCRATE_CONFORMANCE_BUSYBOX")
else
  busybox_candidates=(/bin/busybox.static /usr/bin/busybox-static /bin/busybox)
fi
for candidate in "${busybox_candidates[@]}"; do
  [[ -x "$candidate" ]] || continue
  ldd_output="$(ldd "$candidate" 2>&1 || true)"
  if grep -Fq 'not a dynamic executable' <<<"$ldd_output"; then
    busybox_bin="$candidate"
    break
  fi
done
[[ -n "$busybox_bin" ]] ||
  harness_error "a statically linked BusyBox is required for the FROM-scratch fixture; install busybox-static"
[[ -f "$fixture" ]] || harness_error "missing Compose fixture: $fixture"
[[ -f "$repo_root/tests/fixtures/real-app/webroot/index.html" ]] || harness_error "incomplete Compose fixture: webroot/index.html"
[[ -f "$repo_root/tests/fixtures/real-app/apiroot/index.json" ]] || harness_error "incomplete Compose fixture: apiroot/index.json"

# The real connect/disconnect rows require CAP_NET_ADMIN. Run the entire
# isolated harness in a disposable user+network namespace so both the Docker
# client peer identity and the daemon share the same trusted user namespace;
# no host bridge, route, or firewall state is touched.
if [[ "${EUID}" -ne 0 && "${FERROCRATE_CONFORMANCE_USERNS:-0}" != 1 ]]; then
  namespace_sync="$(mktemp -d "${TMPDIR:-/tmp}/ferrocrate-conformance-userns.XXXXXX")" \
    || harness_error "cannot create user namespace synchronization directory"
  mkfifo "$namespace_sync/go" "$namespace_sync/ready" "$namespace_sync/child-ready" \
    || harness_error "cannot create user namespace synchronization pipes"
  exec 7<>"$namespace_sync/child-ready"
  exec 8<>"$namespace_sync/go"
  exec 9<>"$namespace_sync/ready"
  unshare --user --map-root-user --mount --net bash -c '
    mkdir -p "$5/read-only-run" "$5/xdg"
    resolv_link="$(readlink /etc/resolv.conf 2>/dev/null || true)"
    if [[ "$resolv_link" == ../run/* ]]; then
      resolv_relative="${resolv_link#../run/}"
      mkdir -p "$5/read-only-run/$(dirname "$resolv_relative")"
      printf "nameserver 10.0.2.3\n" >"$5/read-only-run/$resolv_relative"
    else
      printf "nameserver 10.0.2.3\n" >"$5/resolv.conf"
      mount --bind "$5/resolv.conf" /etc/resolv.conf
    fi
    mount --bind "$5/read-only-run" /run
    mount -o remount,bind,ro /run
    ip link set lo up
    printf r >"$6"
    IFS= read -r -n1 <"$1"
    exec env XDG_RUNTIME_DIR="$5/xdg" FERROCRATE_CONFORMANCE_USERNS=1 FERROCRATE_PEER_AUTH="$7" bash "$2" --output "$3" --log "$4"
  ' bash "$namespace_sync/go" "$0" "$output" "$execution_log" "$namespace_sync" \
    "$namespace_sync/child-ready" "$peer_auth_mode" &
  namespace_pid=$!
  if ! IFS= read -r -n1 -t 10 <&7; then
    kill "$namespace_pid" 2>/dev/null || true
    wait "$namespace_pid" 2>/dev/null || true
    rm -rf -- "$namespace_sync"
    harness_error "isolated user/network namespace did not become ready"
  fi
  slirp4netns --configure --mtu=65520 --ready-fd=9 "$namespace_pid" tap0 \
    >"$namespace_sync/slirp.log" 2>&1 &
  slirp_pid=$!
  if ! IFS= read -r -n1 -t 10 <&9; then
    kill "$namespace_pid" "$slirp_pid" 2>/dev/null || true
    wait "$namespace_pid" "$slirp_pid" 2>/dev/null || true
    slirp_message="$(tr '\n' ' ' <"$namespace_sync/slirp.log")"
    rm -rf -- "$namespace_sync"
    harness_error "slirp4netns did not configure isolated egress${slirp_message:+: $slirp_message}"
  fi
  printf x >&8
  wait "$namespace_pid"
  namespace_status=$?
  kill "$slirp_pid" 2>/dev/null || true
  wait "$slirp_pid" 2>/dev/null || true
  exec 7>&-
  exec 8>&-
  exec 9>&-
  if [[ "${FERROCRATE_CONFORMANCE_KEEP_WORKDIR:-0}" != 1 ]]; then
    rm -rf -- "$namespace_sync"
  else
    printf 'conformance work directory retained under %s\n' "$namespace_sync" >&2
  fi
  exit "$namespace_status"
fi
if [[ "${FERROCRATE_CONFORMANCE_USERNS:-0}" == 1 ]]; then
  ip link set lo up || harness_error "cannot enable loopback in conformance network namespace"
  if ! ip link show ferro0 >/dev/null 2>&1; then
    ip link add ferro0 type bridge || harness_error "cannot create isolated default bridge"
    ip addr add 10.0.0.1/24 dev ferro0 || harness_error "cannot address isolated default bridge"
    ip link set ferro0 up || harness_error "cannot enable isolated default bridge"
  fi
fi

output_parent="$(dirname "$output")"
log_parent="$(dirname "$execution_log")"
mkdir -p "$output_parent" || harness_error "cannot create output directory: $output_parent"
mkdir -p "$log_parent" || harness_error "cannot create log directory: $log_parent"

canonical_publication_path() {
  local path="$1" parent base canonical_parent
  parent="$(dirname -- "$path")"
  base="$(basename -- "$path")"
  canonical_parent="$(cd "$parent" && pwd -P)" || return 1
  printf '%s/%s\n' "$canonical_parent" "$base"
}

output="$(canonical_publication_path "$output")" || harness_error "cannot resolve output path: $output"
execution_log="$(canonical_publication_path "$execution_log")" || harness_error "cannot resolve log path: $execution_log"
[[ "$output" != "$execution_log" ]] || harness_error "--output and --log must be different paths"
output_parent="$(dirname "$output")"
log_parent="$(dirname "$execution_log")"

work_root="$(mktemp -d "${TMPDIR:-/tmp}/ferrocrate-client-conformance.XXXXXX")" ||
  harness_error "cannot create temporary work directory"
runtime_dir="$work_root/runtime"
state_dir="$work_root/state"
docker_config="$work_root/docker-config"
context_dir="$work_root/context"
compose_parity_dir="$work_root/compose-parity"
outputs_dir="$work_root/outputs"
cgroup_root="$work_root/cgroup"
mkdir -p "$runtime_dir" "$state_dir" "$docker_config" "$context_dir" "$compose_parity_dir/watch-source" "$outputs_dir" "$cgroup_root" ||
  harness_error "cannot initialize temporary work directory"
printf 'cpu memory pids\n' >"$cgroup_root/cgroup.controllers" ||
  harness_error "cannot initialize isolated cgroup controller fixture"
: >"$cgroup_root/cgroup.subtree_control" ||
  harness_error "cannot initialize isolated cgroup subtree fixture"

# Execute an immutable, run-private snapshot. The daemon and version probe use
# the same bytes named by the published hash even if a concurrent build replaces
# the configured executable while the conformance run is in flight.
ferro_snapshot="$work_root/ferro-cli.snapshot"
cp -- "$ferro_bin" "$ferro_snapshot" || harness_error "cannot snapshot FerroCrate binary: $ferro_bin"
chmod 0500 "$ferro_snapshot" || harness_error "cannot make FerroCrate binary snapshot executable"
binary_sha256="$(sha256sum "$ferro_snapshot" | awk '{ print $1 }')" ||
  harness_error "cannot hash the FerroCrate binary snapshot"
source_commit="$(git -C "$repo_root" rev-parse HEAD 2>/dev/null)" ||
  harness_error "cannot resolve the FerroCrate source commit"

socket="$runtime_dir/docker.sock"
host="unix://$socket"
log_tmp="$work_root/executions.tsv"
scoreboard_tmp=""
log_publish_tmp=""
output_backup=""
log_backup=""
publish_active=0
publish_output_had_prior=0
publish_log_had_prior=0
publish_output_installed=0
publish_log_installed=0
daemon_pid=""
daemon_tracker_pid=""
daemon_process_registry="$work_root/daemon-processes.tsv"
daemon_ready=0
run_id="scoreboard"
run_prefix="ferrocrate-conformance-$run_id"
owner_label="io.ferrocrate.conformance-run=$run_id"
image="$run_prefix:latest"
tagged_image="$run_prefix:tagged"
container="$run_prefix-main"
attach_container="$run_prefix-attach"
volume="$run_prefix-volume"
network="$run_prefix-network"
write_only_log_container="$run_prefix-write-only-log"
secondary_network="$run_prefix-secondary"
alias_network="$run_prefix-alias-network"
alias_target="$run_prefix-alias-target"
detached_wait_container="$run_prefix-detached-wait"
created_wait_container="$run_prefix-created-wait"
compose_project="$run_prefix-compose"
compose_parity_project="$run_prefix-parity-compose"
compose_frontend_network="${compose_project}_frontend"
compose_backend_network="${compose_project}_backend"
host_port=18093
process_token_base="ferrocrate-conformance-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
daemon_process_token="$process_token_base-daemon"
stress_burner_pid=""
stress_burner_token="$process_token_base-stress-burner"
cleanup_sequence=0

process_has_token() {
  local pid="$1" variable="$2" value="$3" entry
  [[ "$pid" =~ ^[1-9][0-9]*$ && -r "/proc/$pid/environ" ]] || return 1
  while IFS= read -r -d '' entry; do
    [[ "$entry" == "$variable=$value" ]] && return 0
  done <"/proc/$pid/environ" 2>/dev/null
  return 1
}

owned_processes() {
  local variable="$1" value="$2" environ_file pid
  grep -lFzx -- "$variable=$value" /proc/[0-9]*/environ 2>/dev/null |
    while IFS= read -r environ_file; do
      pid="${environ_file#/proc/}"
      printf '%s\n' "${pid%/environ}"
    done
}

terminate_owned_processes() {
  local variable="$1" value="$2" pid
  local -a pids=()
  mapfile -t pids < <(owned_processes "$variable" "$value")
  for pid in "${pids[@]}"; do
    process_has_token "$pid" "$variable" "$value" || continue
    kill -TERM "$pid" 2>/dev/null || true
  done
  for _ in $(seq 1 50); do
    mapfile -t pids < <(owned_processes "$variable" "$value")
    ((${#pids[@]} == 0)) && return 0
    sleep 0.02
  done
  mapfile -t pids < <(owned_processes "$variable" "$value")
  for pid in "${pids[@]}"; do
    process_has_token "$pid" "$variable" "$value" || continue
    kill -KILL "$pid" 2>/dev/null || true
  done
  return 0
}

run_bounded_owned() {
  local bound="$1" kill_after="$2" token="$3"
  shift 3
  local status supervisor_pid tracker_pid="" registry
  registry="$work_root/processes-$token.tsv"
  # `&` implicitly rebinds stdin to /dev/null in non-interactive shells;
  # the explicit inheritance keeps caller-provided stdin (login passwords).
  timeout --signal=TERM --kill-after="${kill_after}s" "${bound}s" \
    env FERROCRATE_CONFORMANCE_PROCESS_TOKEN="$token" "$@" <&0 &
  supervisor_pid=$!
  if ! ferrocrate_start_process_tracker "$supervisor_pid" "$registry" tracker_pid; then
    kill -TERM -- "-$supervisor_pid" 2>/dev/null || kill -TERM "$supervisor_pid" 2>/dev/null || true
    wait "$supervisor_pid" 2>/dev/null || true
    return 125
  fi
  wait "$supervisor_pid"
  status=$?
  ferrocrate_terminate_process_tree "$tracker_pid" "$registry"
  terminate_owned_processes FERROCRATE_CONFORMANCE_PROCESS_TOKEN "$token"
  rm -f -- "$registry"
  return "$status"
}

next_cleanup_token() {
  cleanup_sequence=$((cleanup_sequence + 1))
  printf '%s-cleanup-%s' "$process_token_base" "$cleanup_sequence"
}

restore_evidence_pair() {
  local output_had_prior="$1" log_had_prior="$2"
  local output_installed="$3" log_installed="$4" restore_failed=0
  [[ "$output_installed" == 0 ]] || rm -f -- "$output"
  [[ "$log_installed" == 0 ]] || rm -f -- "$execution_log"
  if [[ "$output_had_prior" == 1 && ( -e "$output_backup" || -L "$output_backup" ) ]]; then
    if mv -fT -- "$output_backup" "$output"; then
      output_backup=""
    else
      restore_failed=1
    fi
  fi
  if [[ "$log_had_prior" == 1 && ( -e "$log_backup" || -L "$log_backup" ) ]]; then
    if mv -fT -- "$log_backup" "$execution_log"; then
      log_backup=""
    else
      restore_failed=1
    fi
  fi
  return "$restore_failed"
}

publish_evidence_pair() {
  publish_output_had_prior=0
  publish_log_had_prior=0
  publish_output_installed=0
  publish_log_installed=0
  output_backup="$(mktemp "$output_parent/.parity-scoreboard.previous.XXXXXX")" || return 1
  rm -f -- "$output_backup" || return 1
  log_backup="$(mktemp "$log_parent/.docker-client-conformance.previous.XXXXXX")" || return 1
  rm -f -- "$log_backup" || return 1
  publish_active=1

  if [[ -e "$output" || -L "$output" ]]; then
    mv -fT -- "$output" "$output_backup" || return 1
    publish_output_had_prior=1
  fi
  if [[ -e "$execution_log" || -L "$execution_log" ]]; then
    if ! mv -fT -- "$execution_log" "$log_backup"; then
      restore_evidence_pair "$publish_output_had_prior" "$publish_log_had_prior" \
        "$publish_output_installed" "$publish_log_installed" && publish_active=0
      return 1
    fi
    publish_log_had_prior=1
  fi
  if ! mv -fT -- "$scoreboard_tmp" "$output"; then
    restore_evidence_pair "$publish_output_had_prior" "$publish_log_had_prior" \
      "$publish_output_installed" "$publish_log_installed" && publish_active=0
    return 1
  fi
  publish_output_installed=1
  if ! mv -fT -- "$log_publish_tmp" "$execution_log"; then
    restore_evidence_pair "$publish_output_had_prior" "$publish_log_had_prior" \
      "$publish_output_installed" "$publish_log_installed" && publish_active=0
    return 1
  fi
  publish_log_installed=1

  rm -f -- "$output_backup" "$log_backup"
  output_backup=""
  log_backup=""
  scoreboard_tmp=""
  log_publish_tmp=""
  publish_active=0
  return 0
}

cleanup() {
  local fixture_pids cleanup_token
  if [[ -n "$stress_burner_pid" ]] \
      && process_has_token "$stress_burner_pid" FERROCRATE_CONFORMANCE_PROCESS_TOKEN "$stress_burner_token"; then
    kill -TERM "$stress_burner_pid" 2>/dev/null || true
    wait "$stress_burner_pid" 2>/dev/null || true
    stress_burner_pid=""
  fi
  if [[ "$daemon_ready" == 1 ]]; then
    cleanup_token="$(next_cleanup_token)"
    run_bounded_owned 15 3 "$cleanup_token" \
      env DOCKER_HOST="$host" DOCKER_CONFIG="$docker_config" DOCKER_BUILDKIT=0 \
        "${compose_client[@]}" --project-name "$compose_project" --file "$fixture" down --timeout 2 \
      >/dev/null 2>&1 || true
    cleanup_token="$(next_cleanup_token)"
    run_bounded_owned 15 3 "$cleanup_token" \
      env DOCKER_HOST="$host" DOCKER_CONFIG="$docker_config" DOCKER_BUILDKIT=0 \
        "${compose_client[@]}" --project-name "$compose_parity_project" \
          --file "$compose_parity_dir/compose.yml" --profile optional down --timeout 2 \
      >/dev/null 2>&1 || true
    cleanup_token="$(next_cleanup_token)"
    run_bounded_owned 15 3 "$cleanup_token" \
      env DOCKER_HOST="$host" DOCKER_CONFIG="$docker_config" DOCKER_BUILDKIT=0 \
        docker rm --force "$container" "$attach_container" "$write_only_log_container" "$alias_target" \
      >/dev/null 2>&1 || true
    cleanup_token="$(next_cleanup_token)"
    run_bounded_owned 15 3 "$cleanup_token" \
      env DOCKER_HOST="$host" DOCKER_CONFIG="$docker_config" DOCKER_BUILDKIT=0 \
        docker network rm "$network" "$secondary_network" "$alias_network" >/dev/null 2>&1 || true
    cleanup_token="$(next_cleanup_token)"
    run_bounded_owned 15 3 "$cleanup_token" \
      env DOCKER_HOST="$host" DOCKER_CONFIG="$docker_config" DOCKER_BUILDKIT=0 \
        docker network rm "$compose_frontend_network" "$compose_backend_network" \
      >/dev/null 2>&1 || true
    cleanup_token="$(next_cleanup_token)"
    run_bounded_owned 15 3 "$cleanup_token" \
      env DOCKER_HOST="$host" DOCKER_CONFIG="$docker_config" DOCKER_BUILDKIT=0 \
        docker image rm --force "$image" >/dev/null 2>&1 || true
  fi
  if [[ -n "$daemon_pid" ]]; then
    if process_has_token "$daemon_pid" FERROCRATE_CONFORMANCE_PROCESS_TOKEN "$daemon_process_token"; then
      kill -TERM -- "-$daemon_pid" 2>/dev/null || kill "$daemon_pid" 2>/dev/null || true
    fi
    ferrocrate_terminate_process_tree "$daemon_tracker_pid" "$daemon_process_registry"
    daemon_tracker_pid=""
    wait "$daemon_pid" 2>/dev/null || true
  fi
  terminate_owned_processes FERROCRATE_CONFORMANCE_PROCESS_TOKEN "$daemon_process_token"
  if [[ -d "$runtime_dir" ]]; then
    fixture_pids="$(ps -eo pid=,args= | awk -v root="$runtime_dir" 'index($0, root) && /\/bwrap/ { print $1 }')"
    if [[ -n "$fixture_pids" ]]; then
      kill -TERM $fixture_pids 2>/dev/null || true
      sleep 0.1
      kill -KILL $fixture_pids 2>/dev/null || true
    fi
  fi
  if [[ "$publish_active" == 1 ]]; then
    # A signal can arrive after mv succeeds but before the following assignment.
    # A vanished staging path proves that member reached its destination.
    if [[ -n "$scoreboard_tmp" && ! -e "$scoreboard_tmp" && ! -L "$scoreboard_tmp" ]]; then
      publish_output_installed=1
    fi
    if [[ -n "$log_publish_tmp" && ! -e "$log_publish_tmp" && ! -L "$log_publish_tmp" ]]; then
      publish_log_installed=1
    fi
    restore_evidence_pair "$publish_output_had_prior" "$publish_log_had_prior" \
      "$publish_output_installed" "$publish_log_installed" || true
    publish_active=0
  fi
  [[ -z "$scoreboard_tmp" ]] || rm -f -- "$scoreboard_tmp"
  [[ -z "$log_publish_tmp" ]] || rm -f -- "$log_publish_tmp"
  # FERROCRATE_CONFORMANCE_KEEP_WORKDIR=1 preserves per-command stdout and
  # stderr for failure diagnosis; the default removes everything.
  if [[ "${FERROCRATE_CONFORMANCE_KEEP_WORKDIR:-0}" != 1 ]]; then
    rm -rf -- "$work_root"
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cp "$busybox_bin" "$context_dir/busybox" || harness_error "cannot copy $busybox_bin into build fixture"
chmod 0755 "$context_dir/busybox" || harness_error "cannot make build fixture executable"
printf 'offline conformance fixture\n' >"$context_dir/marker.txt" || harness_error "cannot write build fixture"
printf 'FROM scratch\nLABEL io.ferrocrate.conformance-run="%s"\nCOPY busybox /bin/busybox\nCOPY marker.txt /marker.txt\n' \
  "$run_id" >"$context_dir/Dockerfile" || harness_error "cannot write Dockerfile fixture"
printf 'conformance-copy-marker\n' >"$work_root/copy-marker.txt" || harness_error "cannot write copy fixture"
printf 'contract-password\n' >"$work_root/login-password.txt" || harness_error "cannot write login fixture"
printf 'initial\n' >"$compose_parity_dir/watch-source/marker.txt" || harness_error "cannot write watch fixture"
cat >"$compose_parity_dir/compose.yml" <<EOF || harness_error "cannot write Compose parity fixture"
services:
  optional:
    image: $image
    profiles: [optional]
    command: ["/bin/busybox", "sleep", "120"]
  worker:
    image: $image
    command: ["/bin/busybox", "sleep", "120"]
  watcher:
    image: $image
    command: ["/bin/busybox", "sleep", "120"]
    develop:
      watch:
        - action: sync
          path: ./watch-source
          target: /
EOF

# The harness already runs inside a disposable root-mapped user+network
# namespace, so exercise the real bridge/connect path there. Callers can still
# opt into the rootless slirp path explicitly for targeted qualification.
rootless_netns="${FERROCRATE_ROOTLESS_NETNS:-0}"
network_backend="${FERROCRATE_NETWORK_BACKEND:-iptables}"
setsid env \
  FERROCRATE_CONFORMANCE_PROCESS_TOKEN="$daemon_process_token" \
  FERROCRATE_HOME="$state_dir" \
  FERROCRATE_RUNTIME_DIR="$runtime_dir" \
  FERROCRATE_ROOTLESS_NETNS="$rootless_netns" \
  FERROCRATE_CGROUP_ROOT="$cgroup_root" \
  FERROCRATE_NETWORK_BACKEND="$network_backend" \
  "$ferro_snapshot" daemon --docker-compat --peer-auth "$peer_auth_mode" --socket "$socket" \
  >"$work_root/daemon.stdout" 2>"$work_root/daemon.stderr" &
daemon_pid=$!
ferrocrate_start_process_tracker "$daemon_pid" "$daemon_process_registry" daemon_tracker_pid ||
  harness_error "cannot start daemon descendant tracker"

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
expected_daemon_error_message=""
record_docker_buildkit=0
record_env=()

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
  local command_text started ended duration exit_code status stdout_file stderr_file command_token
  sequence=$((sequence + 1))
  printf -v stdout_file '%s/%03d.stdout' "$outputs_dir" "$sequence"
  printf -v stderr_file '%s/%03d.stderr' "$outputs_dir" "$sequence"
  local -a client_command=(docker "$@")
  if [[ "$1" == compose && -n "$compose_bin" ]]; then
    client_command=("$compose_bin" "${@:2}")
  fi
  command_text="$(shell_command "$@")"
  if ((${#record_env[@]})); then
    command_text="${record_env[*]} $command_text"
  fi
  started="$(date +%s%N)"
  command_token="$process_token_base-client-$sequence"
  if run_bounded_owned "$command_timeout" 5 "$command_token" \
      env DOCKER_HOST="$host" DOCKER_CONFIG="$docker_config" DOCKER_BUILDKIT="$record_docker_buildkit" "${record_env[@]}" \
        FERROCRATE_CONFORMANCE_RECORD_ID="$id" "${client_command[@]}" \
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
  record_docker_buildkit=0
  record_env=()
}

record_command_expect() {
  local id="$1" area="$2" expected_stdout="$3" require_empty_stderr="$4"
  shift 4
  local command_text started ended duration exit_code status stdout_file stderr_file command_token
  local -a client_command=(docker "$@")
  if [[ "$1" == compose && -n "$compose_bin" ]]; then
    client_command=("$compose_bin" "${@:2}")
  fi
  sequence=$((sequence + 1))
  printf -v stdout_file '%s/%03d.stdout' "$outputs_dir" "$sequence"
  printf -v stderr_file '%s/%03d.stderr' "$outputs_dir" "$sequence"
  command_text="$(shell_command "$@") [expected stdout: $expected_stdout]"
  started="$(date +%s%N)"
  command_token="$process_token_base-client-$sequence"
  if run_bounded_owned "$command_timeout" 5 "$command_token" \
      env DOCKER_HOST="$host" DOCKER_CONFIG="$docker_config" DOCKER_BUILDKIT=0 \
        FERROCRATE_CONFORMANCE_RECORD_ID="$id" "${client_command[@]}" \
      >"$stdout_file" 2>"$stderr_file"; then
    exit_code=0
  else
    exit_code=$?
  fi
  ended="$(date +%s%N)"
  duration=$(((ended - started) / 1000000))
  if [[ "$exit_code" == 0 ]] \
      && { [[ "$expected_stdout" == __NONEMPTY__ && -s "$stdout_file" ]] \
        || grep -Fxq -- "$expected_stdout" "$stdout_file"; } \
      && { [[ "$require_empty_stderr" != 1 ]] || [[ ! -s "$stderr_file" ]]; }; then
    status=PASS
    pass_count=$((pass_count + 1))
  else
    status=FAIL
    fail_count=$((fail_count + 1))
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$sequence" "$id" "$area" "$command_text" "$exit_code" "$status" "$duration" >>"$log_tmp"
}

record_created_container_wait() {
  local starter_pid
  record_command created-container-create container create --name "$created_wait_container" \
    "$image" /bin/busybox true
  (
    sleep 1
    env DOCKER_HOST="$host" DOCKER_CONFIG="$docker_config" DOCKER_BUILDKIT=0 \
      docker start "$created_wait_container" >/dev/null 2>&1
  ) &
  starter_pid=$!
  record_command_expect created-container-wait container 0 0 wait "$created_wait_container"
  wait "$starter_pid" || true
  record_command created-wait-remove container rm "$created_wait_container"
}

# A command whose success is a nonzero exit WITH a daemon-mediated error
# (matches dockerd behavior for the same input). A zero exit, a timeout, or
# a client-side transport failure is a FAIL.
record_expected_daemon_error() {
  local id="$1" area="$2"
  shift 2
  local command_text started ended duration exit_code status stdout_file stderr_file command_token
  sequence=$((sequence + 1))
  printf -v stdout_file '%s/%03d.stdout' "$outputs_dir" "$sequence"
  printf -v stderr_file '%s/%03d.stderr' "$outputs_dir" "$sequence"
  command_text="$(shell_command "$@") [expected daemon error]"
  started="$(date +%s%N)"
  command_token="$process_token_base-client-$sequence"
  if run_bounded_owned "$command_timeout" 5 "$command_token" \
      env DOCKER_HOST="$host" DOCKER_CONFIG="$docker_config" DOCKER_BUILDKIT="$record_docker_buildkit" \
        FERROCRATE_CONFORMANCE_RECORD_ID="$id" docker "$@" \
      <"$record_stdin" >"$stdout_file" 2>"$stderr_file"; then
    exit_code=0
  else
    exit_code=$?
  fi
  ended="$(date +%s%N)"
  duration=$(((ended - started) / 1000000))
  if [[ "$exit_code" != 0 ]] && [[ "$exit_code" != 124 && "$exit_code" != 137 ]] \
      && grep -q "Error response from daemon" "$stderr_file" \
      && { [[ -z "$expected_daemon_error_message" ]] \
        || grep -Fq "$expected_daemon_error_message" "$stderr_file"; }; then
    status=PASS
    pass_count=$((pass_count + 1))
  else
    status=FAIL
    fail_count=$((fail_count + 1))
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$sequence" "$id" "$area" "$command_text" "$exit_code" "$status" "$duration" >>"$log_tmp"
  record_stdin="/dev/null"
  expected_daemon_error_message=""
  record_docker_buildkit=0
}

record_compose_watch_sync() {
  local id="compose-watch-sync" area="compose"
  local command_text started ended duration watch_exit probe_exit status stdout_file stderr_file command_token modifier_pid
  sequence=$((sequence + 1))
  printf -v stdout_file '%s/%03d.stdout' "$outputs_dir" "$sequence"
  printf -v stderr_file '%s/%03d.stderr' "$outputs_dir" "$sequence"
  command_text="$(shell_command compose --ansi never --project-name "$compose_parity_project" --file "$compose_parity_dir/compose.yml" watch --no-up) [bounded change-and-sync proof]"
  started="$(date +%s%N)"
  (sleep 2; printf 'synced\n' >"$compose_parity_dir/watch-source/marker.txt") &
  modifier_pid=$!
  command_token="$process_token_base-client-$sequence"
  if run_bounded_owned 8 3 "$command_token" \
      env DOCKER_HOST="$host" DOCKER_CONFIG="$docker_config" DOCKER_BUILDKIT=0 \
        "${compose_client[@]}" --ansi never --project-name "$compose_parity_project" \
          --file "$compose_parity_dir/compose.yml" watch --no-up \
      >"$stdout_file" 2>"$stderr_file"; then
    watch_exit=0
  else
    watch_exit=$?
  fi
  wait "$modifier_pid" 2>/dev/null || true
  if run_bounded_owned 10 3 "$command_token-proof" \
      env DOCKER_HOST="$host" DOCKER_CONFIG="$docker_config" DOCKER_BUILDKIT=0 \
        docker cp "${compose_parity_project}-watcher-1:/marker.txt" \
          "$work_root/watch-proof.txt" \
      >>"$stdout_file" 2>>"$stderr_file" \
      && grep -Fxq synced "$work_root/watch-proof.txt"; then
    probe_exit=0
  else
    probe_exit=1
  fi
  ended="$(date +%s%N)"
  duration=$(((ended - started) / 1000000))
  if [[ "$watch_exit" == 124 || "$watch_exit" == 143 ]] && [[ "$probe_exit" == 0 ]]; then
    status=PASS
    pass_count=$((pass_count + 1))
    watch_exit=0
  else
    status=FAIL
    fail_count=$((fail_count + 1))
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$sequence" "$id" "$area" "$command_text" "$watch_exit" "$status" "$duration" >>"$log_tmp"
}

record_websocket_attach() {
  local id="container-attach-websocket" area="container"
  local command_text started ended duration exit_code status stdout_file stderr_file command_token
  sequence=$((sequence + 1))
  printf -v stdout_file '%s/%03d.stdout' "$outputs_dir" "$sequence"
  printf -v stderr_file '%s/%03d.stderr' "$outputs_dir" "$sequence"
  command_text="websocat --binary --one-message --ws-c-uri ws://localhost/v1.45/containers/$attach_container/attach/ws?stdout=1\\&stderr=1 - ws-c:unix:<docker-socket>"
  started="$(date +%s%N)"
  command_token="$process_token_base-client-$sequence"
  if run_bounded_owned "$command_timeout" 5 "$command_token" \
      "$websocat_bin" --binary --one-message \
        --ws-c-uri="ws://localhost/v1.45/containers/$attach_container/attach/ws?stdout=1&stderr=1" \
        - "ws-c:unix:$socket" \
      >"$stdout_file" 2>"$stderr_file" \
      && grep -aFq ferrocrate-conformance-attach "$stdout_file"; then
    exit_code=0
    status=PASS
    pass_count=$((pass_count + 1))
  else
    exit_code=$?
    status=FAIL
    fail_count=$((fail_count + 1))
  fi
  ended="$(date +%s%N)"
  duration=$(((ended - started) / 1000000))
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$sequence" "$id" "$area" "$command_text" "$exit_code" "$status" "$duration" >>"$log_tmp"
}

record_foreground_output() {
  local id="run-foreground-output" area="container"
  local command_text started ended duration exit_code status stdout_file stderr_file command_token tty_output
  sequence=$((sequence + 1))
  printf -v stdout_file '%s/%03d.stdout' "$outputs_dir" "$sequence"
  printf -v stderr_file '%s/%03d.stderr' "$outputs_dir" "$sequence"
  command_text="docker run --rm alpine:3.20 echo hi && docker run --rm -t alpine:3.20 echo hi [stdout exact]"
  started="$(date +%s%N)"
  command_token="$process_token_base-client-$sequence"
  exit_code=0
  run_bounded_owned "$command_timeout" 5 "$command_token" \
    env DOCKER_HOST="$host" DOCKER_CONFIG="$docker_config" DOCKER_BUILDKIT=0 \
      docker run --rm alpine:3.20 echo hi \
    >"$stdout_file" 2>"$stderr_file" || exit_code=$?
  if [[ "$exit_code" == 0 && "$(tr -d '\r' <"$stdout_file")" == hi && ! -s "$stderr_file" ]]; then
    tty_output="$work_root/foreground-tty.stdout"
    run_bounded_owned "$command_timeout" 5 "$command_token-tty" \
      env DOCKER_HOST="$host" DOCKER_CONFIG="$docker_config" DOCKER_BUILDKIT=0 \
        docker run --rm -t alpine:3.20 echo hi \
      >"$tty_output" 2>>"$stderr_file" || exit_code=$?
    [[ "$exit_code" == 0 && "$(tr -d '\r' <"$tty_output")" == hi && ! -s "$stderr_file" ]] || exit_code=1
    printf '\nTTY invocation:\n' >>"$stdout_file"
    cat "$tty_output" >>"$stdout_file"
  else
    exit_code=1
  fi
  ended="$(date +%s%N)"
  duration=$(((ended - started) / 1000000))
  if [[ "$exit_code" == 0 ]]; then
    status=PASS
    pass_count=$((pass_count + 1))
  else
    status=FAIL
    fail_count=$((fail_count + 1))
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$sequence" "$id" "$area" "$command_text" "$exit_code" "$status" "$duration" >>"$log_tmp"
}

record_foreground_stderr() {
  local id="run-foreground-stderr" area="container"
  local command_text started ended duration exit_code status stdout_file stderr_file command_token
  sequence=$((sequence + 1))
  printf -v stdout_file '%s/%03d.stdout' "$outputs_dir" "$sequence"
  printf -v stderr_file '%s/%03d.stderr' "$outputs_dir" "$sequence"
  command_text="docker run --rm alpine:3.20 sh -c 'echo foreground-error >&2' [stderr exact]"
  started="$(date +%s%N)"
  command_token="$process_token_base-client-$sequence"
  exit_code=0
  run_bounded_owned "$command_timeout" 5 "$command_token" \
    env DOCKER_HOST="$host" DOCKER_CONFIG="$docker_config" DOCKER_BUILDKIT=0 \
      docker run --rm alpine:3.20 sh -c 'echo foreground-error >&2' \
    >"$stdout_file" 2>"$stderr_file" || exit_code=$?
  [[ "$exit_code" == 0 && ! -s "$stdout_file" && "$(tr -d '\r' <"$stderr_file")" == foreground-error ]] || exit_code=1
  ended="$(date +%s%N)"
  duration=$(((ended - started) / 1000000))
  if [[ "$exit_code" == 0 ]]; then
    status=PASS
    pass_count=$((pass_count + 1))
  else
    status=FAIL
    fail_count=$((fail_count + 1))
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$sequence" "$id" "$area" "$command_text" "$exit_code" "$status" "$duration" >>"$log_tmp"
}

record_concurrency_stress() {
  local id="concurrency-stress-10x" area="stress"
  local command_text started ended duration exit_code status stdout_file stderr_file
  local iteration probe project probe_stdout probe_stderr command_token
  local -a affinity=()
  sequence=$((sequence + 1))
  printf -v stdout_file '%s/%03d.stdout' "$outputs_dir" "$sequence"
  printf -v stderr_file '%s/%03d.stderr' "$outputs_dir" "$sequence"
  command_text="CPU burner; 50 foreground runs and compose --scale worker=3 repeated 10x"
  if command -v taskset >/dev/null 2>&1 && taskset -c 0 true >/dev/null 2>&1; then
    affinity=(taskset -c 0)
  fi
  env FERROCRATE_CONFORMANCE_PROCESS_TOKEN="$stress_burner_token" \
    "${affinity[@]}" sh -c 'while :; do :; done' &
  stress_burner_pid=$!
  started="$(date +%s%N)"
  exit_code=0
  for iteration in $(seq 1 10); do
    command_token="$process_token_base-stress-$iteration"
    probe_stdout="$work_root/stress-$iteration.stdout"
    probe_stderr="$work_root/stress-$iteration.stderr"
    for probe in 1 2 3; do
      if ! run_bounded_owned "$command_timeout" 5 "$command_token-output-$probe" \
          env DOCKER_HOST="$host" DOCKER_CONFIG="$docker_config" DOCKER_BUILDKIT=0 \
            "${affinity[@]}" docker run --rm alpine:3.20 echo hi \
          >"$probe_stdout" 2>"$probe_stderr" \
          || [[ "$(tr -d '\r' <"$probe_stdout")" != hi ]] || [[ -s "$probe_stderr" ]]; then
        printf 'iteration %s foreground stdout probe %s failed\n' \
          "$iteration" "$probe" >>"$stderr_file"
        cat "$probe_stdout" "$probe_stderr" >>"$stderr_file"
        exit_code=1
        break
      fi
    done
    [[ "$exit_code" == 0 ]] || break
    if ! run_bounded_owned "$command_timeout" 5 "$command_token-tty" \
        env DOCKER_HOST="$host" DOCKER_CONFIG="$docker_config" DOCKER_BUILDKIT=0 \
          "${affinity[@]}" docker run --rm -t alpine:3.20 echo hi \
        >"$probe_stdout" 2>"$probe_stderr" \
        || [[ "$(tr -d '\r' <"$probe_stdout")" != hi ]] || [[ -s "$probe_stderr" ]]; then
      printf 'iteration %s foreground TTY stdout failed\n' "$iteration" >>"$stderr_file"
      cat "$probe_stdout" "$probe_stderr" >>"$stderr_file"
      exit_code=1
      break
    fi
    if ! run_bounded_owned "$command_timeout" 5 "$command_token-stderr" \
        env DOCKER_HOST="$host" DOCKER_CONFIG="$docker_config" DOCKER_BUILDKIT=0 \
          "${affinity[@]}" docker run --rm alpine:3.20 sh -c 'echo foreground-error >&2' \
        >"$probe_stdout" 2>"$probe_stderr" \
        || [[ -s "$probe_stdout" ]] \
        || [[ "$(tr -d '\r' <"$probe_stderr")" != foreground-error ]]; then
      printf 'iteration %s foreground stderr failed\n' "$iteration" >>"$stderr_file"
      cat "$probe_stdout" "$probe_stderr" >>"$stderr_file"
      exit_code=1
      break
    fi
    project="${compose_parity_project}-stress-$iteration"
    if ! run_bounded_owned "$command_timeout" 5 "$command_token-scale" \
        env DOCKER_HOST="$host" DOCKER_CONFIG="$docker_config" DOCKER_BUILDKIT=0 \
          "${affinity[@]}" "${compose_client[@]}" --ansi never --project-name "$project" \
            --file "$compose_parity_dir/compose.yml" --profile optional up --detach --scale worker=3 \
        >>"$stdout_file" 2>>"$stderr_file"; then
      exit_code=1
    fi
    run_bounded_owned "$command_timeout" 5 "$command_token-down" \
      env DOCKER_HOST="$host" DOCKER_CONFIG="$docker_config" DOCKER_BUILDKIT=0 \
        "${affinity[@]}" "${compose_client[@]}" --ansi never --project-name "$project" \
          --file "$compose_parity_dir/compose.yml" --profile optional down --timeout 2 \
      >>"$stdout_file" 2>>"$stderr_file" || exit_code=1
    [[ "$exit_code" == 0 ]] || break
    printf 'iteration %s passed\n' "$iteration" >>"$stdout_file"
  done
  if process_has_token "$stress_burner_pid" FERROCRATE_CONFORMANCE_PROCESS_TOKEN "$stress_burner_token"; then
    kill -TERM "$stress_burner_pid" 2>/dev/null || true
    wait "$stress_burner_pid" 2>/dev/null || true
  fi
  stress_burner_pid=""
  ended="$(date +%s%N)"
  duration=$(((ended - started) / 1000000))
  if [[ "$exit_code" == 0 ]]; then
    status=PASS
    pass_count=$((pass_count + 1))
  else
    status=FAIL
    fail_count=$((fail_count + 1))
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$sequence" "$id" "$area" "$command_text" "$exit_code" "$status" "$duration" >>"$log_tmp"
}

# Client identity and engine prerequisites.
record_command cli-version client version
record_command compose-version compose compose version
record_command engine-info client info

# Offline image and broad container lifecycle prerequisites. These calls are
# deliberately unconditional: one failed command must not suppress later rows.
if [[ "$builder_mode" == 1 ]]; then
  # The recorded BuildKit probe is expected to reject before producing an
  # image. Seed the shared lifecycle fixture through the supported reference
  # path so later, unrelated rows remain independently meaningful.
  bootstrap_token="$process_token_base-buildkit-classic-bootstrap"
  if ! run_bounded_owned "$command_timeout" 5 "$bootstrap_token" \
      env DOCKER_HOST="$host" DOCKER_CONFIG="$docker_config" DOCKER_BUILDKIT=0 \
        docker build --tag "$image" "$context_dir" >/dev/null 2>&1; then
    harness_error "classic fixture bootstrap failed before BuildKit qualification"
  fi
  record_docker_buildkit=1
  expected_daemon_error_message="BuildKit is not supported; set DOCKER_BUILDKIT=0 to use FerroCrate's supported classic Docker builder"
  record_expected_daemon_error image-build image build --tag "$image" "$context_dir"
else
  record_command image-build image build --tag "$image" "$context_dir"
fi
record_command image-inspect image image inspect "$image"
record_command foreground-image-pull image pull alpine:3.20
record_command_expect detached-run-no-stderr container __NONEMPTY__ 1 run --detach \
  --name "$detached_wait_container" "$image" /bin/busybox sh -c 'sleep 1; exit 7'
record_command_expect running-container-wait container 7 0 wait "$detached_wait_container"
record_command_expect exited-container-wait container 7 0 wait "$detached_wait_container"
record_command detached-wait-remove container rm "$detached_wait_container"
record_created_container_wait
record_foreground_output
record_foreground_stderr
record_command container-create container create --label "$owner_label" --name "$container" \
  --publish "127.0.0.1:${host_port}:8080" "$image" /bin/busybox sleep 120
expected_daemon_error_message="Conflict. The container name \"/$container\" is already in use by container \""
record_expected_daemon_error container-create-duplicate-name container create --name "$container" \
  "$image" /bin/busybox true
record_command container-start container start "$container"
record_command container-inspect container inspect "$container"
record_command container-list container ps --all
record_command container-port container port "$container" 8080/tcp
record_command container-copy-in container cp "$work_root/copy-marker.txt" "$container":/copy-marker.txt
record_command container-diff container diff "$container"
record_command container-update container update --memory 64m --pids-limit 64 "$container"
record_command container-stats container stats --no-stream "$container"
record_command container-top container top "$container"
record_command container-export container container export --output "$work_root/container-export.tar" "$container"
record_command secondary-network-create network network create --driver bridge --subnet 172.30.240.0/24 "$secondary_network"
record_command secondary-network-connect network network connect "$secondary_network" "$container"
record_command secondary-network-disconnect network network disconnect "$secondary_network" "$container"
record_command secondary-network-remove network network rm "$secondary_network"
record_command container-stop container stop --time 1 "$container"
record_command container-wait container wait "$container"
record_command container-logs container logs "$container"
record_command container-remove container rm "$container"

# Logging-driver selection is exercised with the genuine Docker CLI. The
# default conformance binary intentionally lacks the journald feature, so the
# container remains in created state; Docker still preserves LogConfig.Type,
# and `docker logs` must return dockerd's write-only-driver error wording.
record_command log-driver-create container create --label "$owner_label" \
  --name "$write_only_log_container" --log-driver journald \
  "$image" /bin/busybox true
record_command log-driver-inspect container inspect "$write_only_log_container"
expected_daemon_error_message="configured logging driver does not support reading"
record_expected_daemon_error log-driver-read-rejected container logs "$write_only_log_container"
record_command log-driver-remove container rm "$write_only_log_container"

# Save/remove/load makes both archive directions meaningful rather than merely
# probing their help or argument parsing paths.
record_command image-save image save --output "$work_root/image-save.tar" "$image"
record_command image-remove image image rm "$image"
record_command image-load image load --input "$work_root/image-save.tar"
record_command image-list image images "$image"
record_command image-tag image tag "$image" "$tagged_image"
record_command image-tag-inspect image image inspect "$tagged_image"

# Durable named resources exercise their full Docker-client CRUD projections.
record_command volume-create volume volume create --label "$owner_label" \
  --label com.docker.compose.volume=conformance "$volume"
record_command volume-list volume volume ls
record_command_expect volume-label-inspect volume \
  "conformance|$owner_label" 0 volume inspect --format \
  '{{ printf "%s|%s=%s" (index .Labels "com.docker.compose.volume") "io.ferrocrate.conformance-run" (index .Labels "io.ferrocrate.conformance-run") }}' "$volume"
record_command volume-remove volume volume rm "$volume"
record_command network-create network network create --label "$owner_label" \
  --label com.docker.compose.network=default "$network"
record_command network-list network network ls
record_command_expect network-label-inspect network \
  "default|$owner_label" 0 network inspect --format \
  '{{ printf "%s|%s=%s" (index .Labels "com.docker.compose.network") "io.ferrocrate.conformance-run" (index .Labels "io.ferrocrate.conformance-run") }}' "$network"
record_command network-remove network network rm "$network"

# Per-network aliases must resolve through the bridge's embedded DNS from a
# distinct peer. This uses BusyBox nslookup so the row cannot pass through
# libc's /etc/hosts fallback.
record_command network-alias-create network network create --driver bridge \
  --subnet 172.30.245.0/24 "$alias_network"
record_command network-alias-target network run --detach --name "$alias_target" \
  --network "$alias_network" --network-alias conformance-alias \
  "$image" /bin/busybox sleep 120
record_command network-alias-nslookup network run --rm --network "$alias_network" \
  "$image" /bin/busybox nslookup conformance-alias
record_command network-alias-target-remove network rm --force "$alias_target"
record_command network-alias-remove network network rm "$alias_network"

# Attach uses a finite workload so a conforming client closes naturally.
record_command attach-container-create container create --label "$owner_label" --name "$attach_container" \
  --network none "$image" /bin/busybox sh -c '/bin/busybox sleep 2; echo ferrocrate-conformance-attach'
record_command attach-container-start container start "$attach_container"
record_command container-attach container attach --no-stdin --sig-proxy=false "$attach_container"
record_command attach-container-wait container wait "$attach_container"
record_websocket_attach
record_command attach-container-remove container rm --force "$attach_container"

# Discovery/auth use isolated Docker credentials. Login intentionally targets
# a closed local endpoint; a nonzero response remains useful, recorded parity
# evidence without sending credentials to an external registry.
record_command registry-search registry search busybox --limit 5
record_stdin="$work_root/login-password.txt"
# Login against an unreachable registry cannot succeed on any engine; the
# parity contract is that the daemon mediates a well-formed error (as
# dockerd does) instead of an internal failure. PASS when the client exits
# nonzero with a daemon-mediated error message.
record_expected_daemon_error registry-login registry login --username conformance --password-stdin 127.0.0.1:1
record_command registry-logout registry logout 127.0.0.1:1

# Compose profiles and scale are driven by the genuine Compose plugin. Exec
# into the profile-gated service and worker index 2 proves the client created
# the requested topology rather than merely accepting flags.
record_command compose-profile-scale-up compose compose --ansi never \
  --project-name "$compose_parity_project" --file "$compose_parity_dir/compose.yml" \
  --profile optional up --detach --scale worker=2
record_command compose-profile-inspect compose inspect \
  "${compose_parity_project}-optional-1"
record_command compose-scale-index-two compose inspect \
  "${compose_parity_project}-worker-2"
record_command compose-parity-down compose compose --ansi never \
  --project-name "$compose_parity_project" --file "$compose_parity_dir/compose.yml" \
  --profile optional down --timeout 2
record_env=(COMPOSE_PROFILES=optional)
record_command compose-profiles-env-up compose compose --ansi never \
  --project-name "$compose_parity_project" --file "$compose_parity_dir/compose.yml" up --detach
record_command compose-profiles-env-inspect compose inspect \
  "${compose_parity_project}-optional-1"
record_compose_watch_sync
record_command compose-profiles-env-down compose compose --ansi never \
  --project-name "$compose_parity_project" --file "$compose_parity_dir/compose.yml" \
  --profile optional down --timeout 2

# Genuine Compose plugin invocations against the repository's representative
# four-service application fixture.
record_command compose-network-create-frontend compose network create --driver bridge \
  --subnet 172.30.243.0/24 "$compose_frontend_network"
record_command compose-network-create-backend compose network create --driver bridge \
  --subnet 172.30.244.0/24 "$compose_backend_network"
record_command compose-up compose compose --ansi never --project-name "$compose_project" \
  --file "$fixture" up --detach
record_command compose-ps compose compose --ansi never --project-name "$compose_project" \
  --file "$fixture" ps --all
record_command compose-logs compose compose --ansi never --project-name "$compose_project" \
  --file "$fixture" logs --no-color
record_command compose-down compose compose --ansi never --project-name "$compose_project" \
  --file "$fixture" down --timeout 10
record_command compose-network-remove-frontend compose network rm "$compose_frontend_network"
record_command compose-network-remove-backend compose network rm "$compose_backend_network"
if [[ "$stress_mode" == 1 ]]; then
  record_concurrency_stress
fi
record_command system-prune cleanup system prune --force

generated_at="$(date -u +%Y-%m-%d)"
host_metadata="$(uname -srm)"
if [[ "$builder_mode" == 0 ]]; then
  builder_label='`DOCKER_BUILDKIT=0`'
else
  builder_label='BuildKit fallback (`DOCKER_BUILDKIT=1` build probe)'
fi
version_token="$process_token_base-version"
ferro_version="$(run_bounded_owned "$command_timeout" 5 "$version_token" \
  "$ferro_snapshot" --version 2>/dev/null | head -n 1)"
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
current_binary_sha256="$(sha256sum "$ferro_snapshot" | awk '{ print $1 }')" ||
  harness_error "cannot re-hash the FerroCrate binary snapshot"
[[ "$current_binary_sha256" == "$binary_sha256" ]] ||
  harness_error "FerroCrate binary snapshot changed during conformance execution"
current_source_commit="$(git -C "$repo_root" rev-parse HEAD 2>/dev/null)" ||
  harness_error "cannot re-resolve the FerroCrate source commit"
[[ "$current_source_commit" == "$source_commit" ]] ||
  harness_error "FerroCrate source commit changed during conformance execution"

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
- FerroCrate source commit: \`$source_commit\`
- FerroCrate binary SHA-256: \`$binary_sha256\`
- Docker client: $docker_client_version
- Docker-compatible server: $docker_server_version
- Compose client: $compose_version
- Endpoint: isolated \`DOCKER_HOST=unix://<temporary-runtime>/docker.sock\`
- Builder: $builder_label
- Peer authentication: \`$peer_auth_mode\`
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
publish_evidence_pair || harness_error "cannot publish scoreboard and execution log as one evidence pair"

echo "Docker client conformance complete: PASS=$pass_count FAIL=$fail_count ERROR=$error_count TOTAL=$sequence"
if (( fail_count > 0 || error_count > 0 )); then
  exit 1
fi
exit 0
