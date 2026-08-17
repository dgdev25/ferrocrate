#!/usr/bin/env bash
set -euo pipefail

# Collect a small, reproducible comparison of ten user-visible operations.  Run
# this script as root (or with a rootful Docker socket and a rootful Ferrocrate
# runtime); it deliberately never embeds or prompts for credentials.

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/../.." && pwd)}"
out="${FERROCRATE_DOCKER_COMPARISON_OUTPUT:-$repo_root/docs/evidence/performance/$(date -u +%F)-docker-comparison.md}"
ferro_bin="${FERROCRATE_BIN:-$repo_root/target/release/ferro-cli}"
image="${FERROCRATE_COMPARISON_IMAGE:-alpine:3.20}"
rounds="${FERROCRATE_COMPARISON_ROUNDS:-3}"

mkdir -p "$(dirname -- "$out")"
if [[ ! -x "$ferro_bin" ]]; then
  cargo build -p ferro-cli --release >/dev/null
fi
command -v docker >/dev/null || { echo "docker is unavailable" >&2; exit 1; }
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "rootful Docker/Ferrocrate comparison requires uid 0; rerun with sudo" >&2
  exit 77
fi

tmp_root="$(mktemp -d /tmp/ferrocrate-docker-comparison.XXXXXX)"
ferro_runtime="$tmp_root/ferro-runtime"
context="$tmp_root/context"
ferro_socket="$tmp_root/ferro.sock"
mkdir -p "$context"
cat >"$context/Dockerfile" <<'EOF'
FROM alpine:3.20
RUN printf 'ferrocrate-docker-benchmark\n' >/benchmark-marker
EOF

cleanup() {
  if [[ -n "${ferro_daemon_pid:-}" ]] && kill -0 "$ferro_daemon_pid" 2>/dev/null; then
    kill "$ferro_daemon_pid" 2>/dev/null || true
    for _ in $(seq 1 20); do
      kill -0 "$ferro_daemon_pid" 2>/dev/null || break
      sleep 0.05
    done
    if kill -0 "$ferro_daemon_pid" 2>/dev/null; then
      kill -KILL "$ferro_daemon_pid" 2>/dev/null || true
    fi
    wait "$ferro_daemon_pid" 2>/dev/null || true
  fi
  rm -rf "$tmp_root"
}
trap cleanup EXIT

declare -a names=()
declare -a docker_values=()
declare -a ferro_values=()
declare -a notes=()

median_ms() {
  local command_string="$1" samples=() start end i
  for ((i = 0; i < rounds; i++)); do
    start="$(date +%s%N)"
    if ! bash -c "$command_string" >/dev/null 2>&1; then
      echo SKIP
      return 0
    fi
    end="$(date +%s%N)"
    samples+=("$(( (end - start) / 1000000 ))")
  done
  printf '%s\n' "${samples[@]}" | sort -n | awk '{ a[NR]=$1 } END { print a[int((NR+1)/2)] }'
}

record() {
  local name="$1" docker_command="$2" ferro_command="$3" note="$4"
  names+=("$name")
  docker_values+=("$(median_ms "$docker_command")")
  ferro_values+=("$(median_ms "$ferro_command")")
  notes+=("$note")
}

ferro_env="env FERROCRATE_RUNTIME_DIR=$ferro_runtime HOME=$tmp_root FERROCRATE_NETWORK_BACKEND=iptables"
docker_run="docker run --rm --network bridge $image true"
ferro_run="$ferro_env $ferro_bin run --rm --network bridge --network-backend iptables $image true"

# 1. Pull (Docker's daemon cache and Ferrocrate's isolated store are called out
# explicitly in the report; this is a warm-cache operation after preparation).
# A cached image is sufficient for this benchmark.  Docker Hub rate limiting
# must not make an otherwise reproducible local comparison impossible.
image_prep_note="warm image cache"
if ! docker pull "$image" >/dev/null 2>&1; then
  docker image inspect "$image" >/dev/null 2>&1 || {
    echo "image $image is unavailable locally and could not be pulled" >&2
    exit 1
  }
  image_prep_note="Docker Hub pull unavailable; Docker used its cached image"
fi
ferro_pull_note="Ferrocrate uses its isolated runtime store"
if ! eval "$ferro_env $ferro_bin pull '$image'" >/dev/null 2>&1; then
  ferro_pull_note="Ferrocrate image pull unavailable; image-dependent rows may be SKIP"
fi
record "image pull (warm)" "docker pull '$image'" "$ferro_env $ferro_bin pull '$image'" "Docker uses its daemon store; $image_prep_note; $ferro_pull_note."

# 2. Run and exit an OCI image.
record "container run/exit" "$docker_run" "$ferro_run" "Both use the same OCI image and no network."

# 3. Build the same minimal Dockerfile/context.
record "Dockerfile build" "docker build -q -t ferrocrate-bench:docker '$context'" "$ferro_env $ferro_bin build --dockerfile '$context/Dockerfile' --tag ferrocrate-bench:ferro" "Minimal single-stage Dockerfile; local base image is cached."

# 4. Image listing.
record "image list" "docker image ls >/dev/null" "$ferro_env $ferro_bin images >/dev/null" "Default human-readable listing."

# 5. Network create/remove lifecycle.
network_docker='docker network create fc-bench-network-$BASHPID >/dev/null && docker network rm fc-bench-network-$BASHPID >/dev/null'
network_ferro="$ferro_env $ferro_bin network create fc-bench-network-\$BASHPID >/dev/null && $ferro_env $ferro_bin network rm fc-bench-network-\$BASHPID >/dev/null"
record "network create/remove" "$network_docker" "$network_ferro" "Default bridge/network lifecycle; privileged Ferrocrate backend."

# 6. Volume create/remove lifecycle.
volume_docker='docker volume create fc-bench-volume-$BASHPID >/dev/null && docker volume rm fc-bench-volume-$BASHPID >/dev/null'
volume_ferro="$ferro_env $ferro_bin volume create fc-bench-volume-\$BASHPID >/dev/null && $ferro_env $ferro_bin volume rm fc-bench-volume-\$BASHPID >/dev/null"
record "volume create/remove" "$volume_docker" "$volume_ferro" "Default local volume lifecycle."

# 7. Network listing before the daemon starts (the direct CLI owns the runtime
# store; the socket daemon has its own concurrent state path).
record "network list" "docker network ls" "$ferro_env $ferro_bin network ls" "Default network inventory listing."

# Start Ferrocrate's Docker-compatible socket for API measurements.
mkdir -p "$ferro_runtime"
env FERROCRATE_RUNTIME_DIR="$ferro_runtime" HOME="$tmp_root" \
  FERROCRATE_NETWORK_BACKEND=iptables "$ferro_bin" daemon \
  --docker-compat --socket "$ferro_socket" >/dev/null 2>&1 &
ferro_daemon_pid=$!
for _ in $(seq 1 50); do
  [[ -S "$ferro_socket" ]] && break
  if ! kill -0 "$ferro_daemon_pid" 2>/dev/null; then
    echo "Ferrocrate Docker-compatible daemon exited before opening its socket" >&2
    exit 1
  fi
  sleep 0.1
done
[[ -S "$ferro_socket" ]] || { echo "Ferrocrate Docker-compatible daemon did not open its socket" >&2; exit 1; }

# 8-10. Three common Docker API calls over Unix sockets.
record "API ping" "curl --silent --fail --unix-socket /var/run/docker.sock http://localhost/_ping" "curl --silent --fail --unix-socket '$ferro_socket' http://localhost/_ping" "Unix-socket API health check."
record "API version" "curl --silent --fail --unix-socket /var/run/docker.sock http://localhost/version" "curl --silent --fail --unix-socket '$ferro_socket' http://localhost/version" "Version negotiation payload."
record "API info" "curl --silent --fail --unix-socket /var/run/docker.sock http://localhost/info" "curl --silent --fail --unix-socket '$ferro_socket' http://localhost/info" "Runtime/daemon information payload."

{
  echo "# Ferrocrate vs Docker feature benchmark"
  echo
  echo "- Date (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "- Host: $(. /etc/os-release && printf '%s' \"${PRETTY_NAME:-unknown}\") / $(uname -r) / $(uname -m)"
  echo "- Docker: $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo unavailable)"
  echo "- Ferrocrate commit: $(git -C "$repo_root" rev-parse --short HEAD)"
  echo "- Image: \`$image\`; rounds per operation: $rounds; reported value is median wall-clock milliseconds."
  echo "- Privilege: this run requires rootful access to Docker and Ferrocrate networking."
  echo
  echo "This is an operational comparison, not a compatibility or production-readiness claim."
  echo "Docker's daemon/image cache and Ferrocrate's isolated runtime are different storage systems;"
  echo "the report records skips as \`SKIP\` instead of converting unsupported operations to zero."
  echo
  echo "| Feature | Docker median (ms) | Ferrocrate median (ms) | Difference (Ferrocrate-Docker) | Notes |"
  echo "|---|---:|---:|---:|---|"
  for i in "${!names[@]}"; do
    d="${docker_values[$i]}"; f="${ferro_values[$i]}"
    if [[ "$d" == SKIP || "$f" == SKIP ]]; then diff="n/a"; else diff=$((f-d)); fi
    echo "| ${names[$i]} | $d | $f | $diff | ${notes[$i]} |"
  done
  echo
  echo "## Interpretation"
  echo
  echo "These measurements compare command-path latency on one host. They do not establish"
  echo "Docker API parity, cross-distribution support, rootless qualification, eBPF traffic"
  echo "success, image-pull throughput, sustained-load behavior, or multi-host networking."
  echo "Those remain governed by the evidence and open checkboxes in \`ROADMAP.md\`."
} >"$out"

printf 'comparison report: %s\n' "$out"
