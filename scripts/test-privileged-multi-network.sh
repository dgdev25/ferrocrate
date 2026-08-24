#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'privileged multi-network failed: %s\n' "$*" >&2
  exit 1
}

[[ "$(uname -s)" == Linux ]] || fail "Linux is required"
[[ "${EUID}" -eq 0 ]] || { printf 'SKIP: root (EUID=0) is required\n'; exit 77; }
command -v docker >/dev/null || fail "docker is required"
command -v jq >/dev/null || fail "jq is required"
command -v ip >/dev/null || fail "ip is required"
[[ -x /bin/busybox ]] || fail "/bin/busybox is required"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ferro_bin="${FERROCRATE_BIN:-$repo_root/target/release/ferro-cli}"
[[ -x "$ferro_bin" ]] || fail "missing executable ferro-cli: $ferro_bin"

work_root="$(mktemp -d /tmp/ferrocrate-multinet.XXXXXX)"
runtime_dir="$work_root/runtime"
docker_config="$work_root/docker-config"
context_dir="$work_root/context"
socket="$runtime_dir/docker.sock"
host="unix://$socket"
prefix="fc-multinet-$$"
image="$prefix:latest"
net_a="$prefix-a"
net_b="$prefix-b"
subject="$prefix-subject"
peer_a="$prefix-peer-a"
peer_b="$prefix-peer-b"
daemon_pid=""
mkdir -p "$runtime_dir" "$docker_config" "$context_dir"

docker_fc() {
  env DOCKER_HOST="$host" DOCKER_CONFIG="$docker_config" DOCKER_BUILDKIT=0 docker "$@"
}

stop_daemon() {
  if [[ -n "$daemon_pid" ]]; then
    kill -TERM "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
    daemon_pid=""
  fi
}

cleanup() {
  local status=$?
  if [[ -S "$socket" ]]; then
    docker_fc rm -f "$subject" "$peer_a" "$peer_b" >/dev/null 2>&1 || true
    docker_fc network rm "$net_a" "$net_b" >/dev/null 2>&1 || true
  fi
  stop_daemon
  if [[ "$status" -ne 0 && -s "$work_root/daemon.stderr" ]]; then
    printf '%s\n' '--- daemon stderr ---' >&2
    tail -n 120 "$work_root/daemon.stderr" >&2
  fi
  rm -rf -- "$work_root"
}
trap cleanup EXIT

start_daemon() {
  env FERROCRATE_RUNTIME_DIR="$runtime_dir" FERROCRATE_NETWORK_BACKEND=iptables \
    "$ferro_bin" daemon --docker-compat --socket "$socket" \
    >"$work_root/daemon.stdout" 2>>"$work_root/daemon.stderr" &
  daemon_pid=$!
  for _ in $(seq 1 100); do
    [[ -S "$socket" ]] && return 0
    kill -0 "$daemon_pid" 2>/dev/null || fail "daemon exited before socket readiness"
    sleep 0.1
  done
  fail "daemon socket was not ready"
}

cp /bin/busybox "$context_dir/busybox"
printf 'FROM scratch\nCOPY busybox /bin/busybox\n' >"$context_dir/Dockerfile"

printf '$ start isolated FerroCrate daemon\n'
start_daemon
printf '$ docker build --tag %s <context>\n' "$image"
docker_fc build --tag "$image" "$context_dir" >/dev/null
printf '$ docker network create --subnet 172.30.241.0/24 %s\n' "$net_a"
docker_fc network create --subnet 172.30.241.0/24 "$net_a" >/dev/null
printf '$ docker network create --subnet 172.30.242.0/24 %s\n' "$net_b"
docker_fc network create --subnet 172.30.242.0/24 "$net_b" >/dev/null
for binding in "$peer_a:$net_a" "$peer_b:$net_b" "$subject:$net_a"; do
  container_name="${binding%%:*}"
  network_name="${binding#*:}"
  docker_fc create --name "$container_name" --network "$network_name" \
    "$image" /bin/busybox sleep 300 >/dev/null
  docker_fc start "$container_name" >/dev/null
done
printf '$ docker network connect %s %s\n' "$net_b" "$subject"
docker_fc network connect "$net_b" "$subject"

peer_a_ip="$(docker_fc inspect "$peer_a" | jq -er ".[0].NetworkSettings.Networks[\"$net_a\"].IPAddress")"
peer_b_ip="$(docker_fc inspect "$peer_b" | jq -er ".[0].NetworkSettings.Networks[\"$net_b\"].IPAddress")"
before="$(docker_fc inspect "$subject" | jq -c ".[0].NetworkSettings.Networks | with_entries(.value |= {EndpointID,IPAddress})")"
printf 'subject endpoints before restart: %s\n' "$before"
docker_fc exec "$subject" /bin/busybox ping -c 1 -W 2 "$peer_a_ip" >/dev/null
printf 'ping %s on %s: PASS\n' "$peer_a_ip" "$net_a"
docker_fc exec "$subject" /bin/busybox ping -c 1 -W 2 "$peer_b_ip" >/dev/null
printf 'ping %s on %s: PASS\n' "$peer_b_ip" "$net_b"

printf '$ restart FerroCrate daemon with the same runtime directory\n'
stop_daemon
rm -f -- "$socket"
start_daemon
after="$(docker_fc inspect "$subject" | jq -c ".[0].NetworkSettings.Networks | with_entries(.value |= {EndpointID,IPAddress})")"
[[ "$after" == "$before" ]] || fail "endpoint identity changed across daemon restart: before=$before after=$after"
printf 'subject endpoints after restart: %s\n' "$after"
docker_fc exec "$subject" /bin/busybox ping -c 1 -W 2 "$peer_a_ip" >/dev/null
docker_fc exec "$subject" /bin/busybox ping -c 1 -W 2 "$peer_b_ip" >/dev/null
printf 'post-restart pings on both networks: PASS\n'

printf '$ docker network disconnect %s %s\n' "$net_b" "$subject"
docker_fc network disconnect "$net_b" "$subject"
docker_fc exec "$subject" /bin/busybox ping -c 1 -W 2 "$peer_a_ip" >/dev/null
if docker_fc exec "$subject" /bin/busybox ping -c 1 -W 1 "$peer_b_ip" >/dev/null 2>&1; then
  fail "detached network $net_b remained reachable"
fi
remaining="$(docker_fc inspect "$subject" | jq -c ".[0].NetworkSettings.Networks | keys")"
[[ "$remaining" == "[\"$net_a\"]" ]] || fail "disconnect removed the wrong endpoint set: $remaining"
printf 'disconnect exactness: %s reachable, %s unreachable, endpoints=%s\n' \
  "$net_a" "$net_b" "$remaining"
printf 'privileged multi-network lifecycle: PASS\n'
