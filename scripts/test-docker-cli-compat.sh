#!/usr/bin/env bash
set -euo pipefail

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/.." && pwd)}"
bin="${FERROCRATE_BIN:-$repo_root/target/release/ferro-cli}"
strict="${FERROCRATE_DOCKER_CLI_REQUIRED:-0}"

if ! command -v docker >/dev/null 2>&1; then
  if [[ "$strict" == "1" || "$strict" == "true" ]]; then
    echo "Docker CLI is required but not installed" >&2
    exit 1
  fi
  echo "docker CLI compatibility smoke skipped (docker not installed)"
  exit 0
fi
if [[ ! -x "$bin" ]]; then
  if [[ "$strict" == "1" || "$strict" == "true" ]]; then
    echo "Ferrocrate binary is required but missing: $bin" >&2
    exit 1
  fi
  echo "docker CLI compatibility smoke skipped (missing Ferrocrate binary: $bin)"
  exit 0
fi
if [[ "$bin" -ot "$repo_root/ferro-cli/src/main.rs" ]]; then
  if [[ "$strict" == "1" || "$strict" == "true" ]]; then
    echo "Ferrocrate binary is older than the Docker-compatible source; rebuild it before the strict smoke" >&2
    exit 1
  fi
  echo "docker CLI compatibility smoke skipped (stale Ferrocrate binary: $bin)"
  exit 0
fi

runtime_dir="$(mktemp -d "${TMPDIR:-/tmp}/ferrocrate-docker-cli.XXXXXX")"
socket="$runtime_dir/docker.sock"
daemon_pid=""
cleanup() {
  if [[ -n "$daemon_pid" ]]; then
    kill "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
  fi
  rm -rf "$runtime_dir"
}
trap cleanup EXIT

FERROCRATE_RUNTIME_DIR="$runtime_dir" "$bin" daemon --docker-compat --socket "$socket" \
  >"$runtime_dir/daemon.stdout" 2>"$runtime_dir/daemon.stderr" &
daemon_pid=$!
for _ in $(seq 1 100); do
  if [[ -S "$socket" ]] && docker -H "unix://$socket" version >/dev/null 2>&1; then
    break
  fi
  sleep 0.05
done
if ! [[ -S "$socket" ]]; then
  echo "Docker-compatible socket did not start" >&2
  cat "$runtime_dir/daemon.stderr" >&2 || true
  exit 1
fi

host="unix://$socket"
docker -H "$host" version >/dev/null
docker -H "$host" info >/dev/null
docker -H "$host" ps --all >/dev/null
docker -H "$host" images >/dev/null

name="docker-cli-compat-$$"
image="docker-cli-compat-image-$$:latest"
tagged_image="docker-cli-compat-tag-$$:latest"
committed_image="docker-cli-compat-commit-$$:latest"
context_dir="$runtime_dir/context"
mkdir -p "$context_dir"
printf 'FROM scratch\nCOPY --chmod=755 busybox /bin/busybox\n' >"$context_dir/Dockerfile"
if [[ ! -x /bin/busybox ]]; then
  echo "Docker CLI lifecycle smoke requires /bin/busybox" >&2
  exit 1
fi
cp /bin/busybox "$context_dir/busybox"
chmod 0755 "$context_dir/busybox"
tar -C "$context_dir" -cf "$runtime_dir/context.tar" Dockerfile busybox
if ! command -v curl >/dev/null 2>&1; then
  echo "Docker CLI lifecycle smoke requires curl for the Docker-compatible build endpoint" >&2
  exit 1
fi
curl --fail --silent --show-error --unix-socket "$socket" \
  -H 'Content-Type: application/x-tar' \
  --data-binary "@$runtime_dir/context.tar" \
  "http://localhost/v1.45/build?dockerfile=Dockerfile&t=${image//:/%3A}" \
  >"$runtime_dir/build.jsonl"
docker -H "$host" history "$image" >/dev/null
save_archive="$runtime_dir/image-save.tar"
docker -H "$host" save "$image" -o "$save_archive" >/dev/null
tar -tf "$save_archive" | grep -qx 'manifest.json'
tar -tf "$save_archive" | grep -q '/layer.tar$'
docker -H "$host" load -i "$save_archive" >/dev/null
docker -H "$host" image inspect "$image" >/dev/null
docker -H "$host" tag "$image" "$tagged_image"
docker -H "$host" image inspect "$tagged_image" >/dev/null
docker -H "$host" image rm "$tagged_image" >/dev/null
docker -H "$host" image prune --force >/dev/null
events_file="$runtime_dir/events.jsonl"
timeout 5 docker -H "$host" events --since 0s --filter type=container \
  >"$events_file" 2>"$runtime_dir/events.stderr" &
events_pid=$!
sleep 0.2
container_id="$(docker -H "$host" create --network none --name "$name" "$image" /bin/busybox sleep 30)"
[[ -n "$container_id" ]] || { echo "docker create returned no ID" >&2; exit 1; }
docker -H "$host" inspect "$name" >/dev/null
docker -H "$host" start "$name" >/dev/null
docker -H "$host" exec "$name" /bin/busybox true >/dev/null
wait_status="$(docker -H "$host" wait "$name")"
[[ "$wait_status" == "0" ]] || {
  echo "Docker CLI wait returned unexpected status: $wait_status" >&2
  exit 1
}
docker -H "$host" logs "$name" >/dev/null
docker -H "$host" diff "$name" >/dev/null
printf 'ferrocrate-docker-cp-smoke\n' >"$runtime_dir/cp-host.txt"
docker -H "$host" cp "$runtime_dir/cp-host.txt" "$name":/
docker -H "$host" cp "$name":/cp-host.txt "$runtime_dir/cp-roundtrip.txt"
cmp "$runtime_dir/cp-host.txt" "$runtime_dir/cp-roundtrip.txt"
mkdir -p "$runtime_dir/cp-tree/sub"
printf 'ferrocrate-docker-cp-tree\n' >"$runtime_dir/cp-tree/sub/nested.txt"
docker -H "$host" cp "$runtime_dir/cp-tree" "$name":/
docker -H "$host" cp "$name":/cp-tree "$runtime_dir/cp-tree-roundtrip"
cmp "$runtime_dir/cp-tree/sub/nested.txt" "$runtime_dir/cp-tree-roundtrip/sub/nested.txt"
docker -H "$host" commit "$name" "$committed_image" >/dev/null
docker -H "$host" image inspect "$committed_image" >/dev/null
docker -H "$host" image rm "$committed_image" >/dev/null
docker -H "$host" rm "$name" >/dev/null

# Exercise the real Docker CLI hijack/attach path against a long-lived
# workload. The API-level handshake tests do not prove that the external
# client can consume the post-start raw stream and return cleanly. Use the
# explicit BusyBox applet because this scratch fixture has no /bin/sleep link.
attach_name="docker-cli-attach-$$"
docker -H "$host" create --network none --name "$attach_name" "$image" \
  /bin/busybox sh -c '/bin/busybox sleep 2; echo ferrocrate-attach-smoke; /bin/busybox sleep 30' >/dev/null
docker -H "$host" start "$attach_name" >/dev/null
attach_status=0
attach_id="$(docker -H "$host" inspect --format '{{.Id}}' "$attach_name")"
timeout -k 2 8 curl --no-buffer --silent --show-error \
  --unix-socket "$socket" -X POST \
  -H 'Connection: Upgrade' -H 'Upgrade: tcp' -H 'Content-Length: 0' \
  "http://localhost/v1.45/containers/$attach_id/attach?logs=1&stream=1&stdin=0&stdout=1&stderr=1" \
  >"$runtime_dir/attach.stdout" || attach_status=$?
grep -a -q 'ferrocrate-attach-smoke' "$runtime_dir/attach.stdout" || {
  echo "Docker attach wire stream did not receive the workload payload" >&2
  od -An -tx1 "$runtime_dir/attach.stdout" >&2 || true
  exit 1
}
if [[ "$attach_status" != 124 && "$attach_status" != 137 ]]; then
  echo "Docker CLI attach returned unexpected status: $attach_status" >&2
  exit 1
fi
docker -H "$host" rm --force "$attach_name" >/dev/null
wait "$events_pid" 2>/dev/null || true
grep -q 'container create' "$events_file" || {
  echo "Docker CLI did not receive a container create event" >&2
  cat "$events_file" >&2 || true
  cat "$runtime_dir/events.stderr" >&2 || true
  exit 1
}

echo "Docker CLI compatibility smoke passed: version/info/ps/images/build/history/save/load/tag/inspect/rmi/image-prune/create/start/wait/logs/diff/exec/cp/commit/attach/rm/events"
