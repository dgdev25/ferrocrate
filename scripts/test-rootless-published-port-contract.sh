#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d /tmp/ferrocrate-rootless-published-contract.XXXXXX)"
cleanup_fixture() {
  if [[ -f "$tmp/runtime/slirp.pid" ]]; then
    kill -TERM "$(cat "$tmp/runtime/slirp.pid")" 2>/dev/null || true
  fi
  rm -rf -- "$tmp"
}
trap cleanup_fixture EXIT

fixture_bin="$tmp/bin"
fixture_runtime="$tmp/runtime"
command_log="$tmp/commands.log"
mkdir -p "$fixture_bin" "$fixture_runtime"

cat >"$fixture_bin/ferro-cli" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$PUBLISHED_PORT_COMMAND_LOG"
case "${1:-}" in
  pull|stop|logs)
    exit 0
    ;;
  run)
    for argument in "$@"; do
      if [[ "$argument" == --detach ]]; then
        "$PUBLISHED_PORT_FAKE_SLIRP" \
          "--api-socket=$FERROCRATE_RUNTIME_DIR/containers/fixture-container/slirp4netns.sock" \
          </dev/null >/dev/null 2>&1 &
        printf '%s\n' "$!" >"$FERROCRATE_RUNTIME_DIR/slirp.pid"
        printf 'container_id=fixture-container\n'
        exit 0
      fi
    done
    echo 'fixture run stayed attached because --detach was omitted' >&2
    exit 42
    ;;
  rm)
    kill -TERM "$(cat "$FERROCRATE_RUNTIME_DIR/slirp.pid")"
    exit 0
    ;;
  *)
    echo "unexpected ferro-cli command: $*" >&2
    exit 97
    ;;
esac
EOF

cat >"$fixture_bin/slirp4netns" <<'EOF'
#!/usr/bin/env bash
printf 'slirp4netns\n' >"/proc/$$/comm"
trap 'sleep 1; exit 0' TERM
while :; do
  sleep 0.1
done
EOF

cat >"$fixture_bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
output=""
while (( $# )); do
  if [[ "$1" == -o ]]; then
    output="$2"
    shift 2
  else
    shift
  fi
done
[[ -n "$output" ]]
printf 'ferro-rootless-published-ok\n' >"$output"
EOF

cat >"$fixture_bin/ss" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
chmod 0755 "$fixture_bin"/*

PATH="$fixture_bin:$PATH" \
FERROCRATE_NETWORK_CLI="$fixture_bin/ferro-cli" \
FERROCRATE_RUNTIME_DIR="$fixture_runtime" \
FERROCRATE_ROOTLESS_PUBLISH_PORT=18991 \
FERROCRATE_ROOTLESS_PUBLISH_WAIT_SECONDS=1 \
FERROCRATE_ROOTLESS_PUBLISH_TIMEOUT=2 \
PUBLISHED_PORT_COMMAND_LOG="$command_log" \
PUBLISHED_PORT_FAKE_SLIRP="$fixture_bin/slirp4netns" \
  bash "$repo_root/scripts/test-rootless-published-port.sh"

grep -Fqx \
  'run --detach --name ferro-rootless-publish-18991 --network bridge --network-backend iptables --publish 18991:8080/tcp busybox:1.36 sh -c mkdir -p /www; printf ferro-rootless-published-ok\\n >/www/index.html; httpd -f -p 8080 -h /www' \
  "$command_log"
grep -Fqx 'stop fixture-container' "$command_log"
grep -Fqx 'rm fixture-container' "$command_log"
slirp_pid="$(cat "$fixture_runtime/slirp.pid")"
for _ in $(seq 1 30); do
  kill -0 "$slirp_pid" 2>/dev/null || break
  sleep 0.1
done
if kill -0 "$slirp_pid" 2>/dev/null; then
  echo "rootless published-port fixture left slirp4netns running: $slirp_pid" >&2
  exit 1
fi

echo 'rootless published-port detached-run contract passed'
