#!/usr/bin/env bash
# Reproducible two-host Fleet browser demo.  Runtime state is deliberately
# outside the checkout so source trees and credentials never mix.
set -euo pipefail

repo_root="$(cd "$(dirname -- "$0")/.." && pwd)"
state_root="${FLEET_DEMO_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/ferrocrate-fleet-demo}"
guest_name="${FLEET_DEMO_GUEST_NAME:-ferro-ubuntu-01}"
guest_user="${FLEET_DEMO_GUEST_USER:-lyle}"
guest_host="${FLEET_DEMO_GUEST_HOST:-192.168.122.9}"
guest_manager_host="${FLEET_DEMO_GUEST_MANAGER_HOST:-192.168.122.1}"
arm_user="${FLEET_DEMO_ARM_USER:-ubuntu}"
arm_host="${FLEET_DEMO_ARM_HOST:-132.145.25.108}"
arm_repo="${FLEET_DEMO_ARM_REPO:-~/ferrocrate-fleet}"
cluster_id="${FLEET_DEMO_CLUSTER_ID:-fleet-demo}"
ui_addr="127.0.0.1:58443"
ui_url="http://${ui_addr}"

die() { echo "fleet-demo: $*" >&2; exit 1; }
note() { echo "fleet-demo: $*" >&2; }
pid_alive() {
  [[ -s "$1" ]] || return 1
  local pid; pid="$(<"$1")"
  [[ "$pid" =~ ^[1-9][0-9]*$ ]] && kill -0 "$pid" 2>/dev/null \
    && ! ps -o stat= -p "$pid" 2>/dev/null | grep -q '^[[:space:]]*Z'
}
require() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }

usage() {
  cat <<'EOF'
usage: scripts/fleet-demo.sh [up|down|--status|verify|--refresh-login]

Starts the local manager, libvirt x86_64 guest, and Oracle A1 agent, then
prints the short-lived browser login credentials. Runtime CA, credentials,
logs, and PID files live in FLEET_DEMO_STATE_DIR (default:
$XDG_STATE_HOME/ferrocrate-fleet-demo, or $HOME/.local/state/ferrocrate-fleet-demo).

Commands:
  up        build and start the reproducible two-host fleet (default)
  down      stop agents, SSH forwards, manager/UI, then shut down the guest
  --status  print manager/UI process and both host connection states
  verify    require both hosts connected; run and read logs on each host
  --refresh-login  mint replacement browser credentials without restarting services
EOF
}

for_command() {
  ssh -o BatchMode=yes -o ConnectTimeout=10 "$@"
}

guest_ssh() { for_command "${guest_user}@${guest_host}" "$@"; }
arm_ssh() { for_command "${arm_user}@${arm_host}" "$@"; }

ship_guest_binary() {
  local source="$1" destination="/var/tmp/$(basename -- "$1")" expected actual
  expected="$(sha256sum "$source" | awk '{print $1}')"
  actual="$(guest_ssh "sha256sum '$destination' 2>/dev/null | awk '{print \$1}'" 2>/dev/null || true)"
  if [[ "$actual" == "$expected" ]]; then
    note "using matching staged guest binary $destination"
    return
  fi
  # stage beside the live binary and rename over it: a running agent keeps the old inode open, and
  # writing the file in place fails with "text file busy".
  scp -q "$source" "${guest_user}@${guest_host}:$destination.new" || die "could not stage $(basename -- "$source") on the guest (scp failed: check free space under /var/tmp and the guest user's write access)"
  guest_ssh "chmod 700 '$destination.new' && mv -f '$destination.new' '$destination'" || die "could not install staged guest binary: $destination"
}

ensure_layout() {
  umask 077
  mkdir -p "$state_root" "$state_root/pids" "$state_root/pki" "$state_root/ui"
  chmod 700 "$state_root" "$state_root/pids" "$state_root/pki" "$state_root/ui"
}

generate_bytes() { openssl rand "$1" >"$2"; chmod 600 "$2"; }

create_pki() {
  if [[ -f "$state_root/pki/node-ca.pem" && -f "$state_root/pki/manager.pem" && -f "$state_root/pki/operator.pem" && -f "$state_root/pki/controller-grant.key" ]]; then
    return
  fi
  if [[ -f "$state_root/pki/node-ca.pem" && -f "$state_root/manager.sqlite" ]]; then
    die "persisted CA state is incomplete; refusing to replace credentials for an existing manager database"
  fi
  rm -f "$state_root/pki"/*
  note "creating persisted node and administrator CAs under $state_root/pki"
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 -sha256 \
    -subj "/CN=ferrocrate-fleet-demo-node-ca" \
    -keyout "$state_root/pki/node-ca.key" -out "$state_root/pki/node-ca.pem" >/dev/null 2>&1
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 -sha256 \
    -subj "/CN=ferrocrate-fleet-demo-admin-ca" \
    -keyout "$state_root/pki/admin-ca.key" -out "$state_root/pki/admin-ca.pem" >/dev/null 2>&1
  openssl req -newkey rsa:2048 -nodes -sha256 -subj "/CN=localhost" \
    -keyout "$state_root/pki/manager.key" -out "$state_root/pki/manager.csr" >/dev/null 2>&1
  openssl x509 -req -days 30 -sha256 -in "$state_root/pki/manager.csr" \
    -CA "$state_root/pki/node-ca.pem" -CAkey "$state_root/pki/node-ca.key" -CAcreateserial \
    -extfile <(printf '%s\n' 'subjectAltName=DNS:localhost,IP:127.0.0.1' 'extendedKeyUsage=serverAuth') \
    -out "$state_root/pki/manager.pem" >/dev/null 2>&1
  openssl req -newkey rsa:2048 -nodes -sha256 \
    -subj "/CN=ferrocrate\\/${cluster_id}\\/administrator" \
    -keyout "$state_root/pki/operator.key" -out "$state_root/pki/operator.csr" >/dev/null 2>&1
  openssl x509 -req -days 30 -sha256 -in "$state_root/pki/operator.csr" \
    -CA "$state_root/pki/admin-ca.pem" -CAkey "$state_root/pki/admin-ca.key" -CAcreateserial \
    -extfile <(printf '%s\n' 'extendedKeyUsage=clientAuth') -out "$state_root/pki/operator.pem" >/dev/null 2>&1
  generate_bytes 32 "$state_root/pki/controller-grant.key"
  generate_bytes 32 "$state_root/pki/controller-envelope.key"
  generate_bytes 32 "$state_root/pki/manager-signing.key"
}

build_local() {
  note "building local x86_64 release binaries (CARGO_BUILD_JOBS=6)"
  (cd "$repo_root" && CARGO_BUILD_JOBS=6 cargo build --release -p ferro-mgr --bin ferro-mgr --bin ferro-agent -p ferro-cli)
}

start_manager() {
  if pid_alive "$state_root/pids/manager"; then return; fi
  note "starting ferro-mgr"
  local manager_signing
  manager_signing="$(base64 -w0 "$state_root/pki/manager-signing.key")"
  setsid env \
    FERROCRATE_CLUSTER_ID="$cluster_id" \
    FERROCRATE_MANAGER_SIGNING_KEY="$manager_signing" \
    FERROCRATE_MANAGER_ADDR=0.0.0.0:55051 \
    FERROCRATE_CONTROL_ADDR=0.0.0.0:55053 \
    FERROCRATE_ADMIN_ADDR=127.0.0.1:55052 \
    FERROCRATE_MANAGER_TLS_CERT="$state_root/pki/manager.pem" \
    FERROCRATE_MANAGER_TLS_KEY="$state_root/pki/manager.key" \
    FERROCRATE_NODE_CA_CERT="$state_root/pki/node-ca.pem" \
    FERROCRATE_NODE_CA_KEY="$state_root/pki/node-ca.key" \
    FERROCRATE_ADMIN_CA_CERT="$state_root/pki/admin-ca.pem" \
    FERROCRATE_MANAGER_DB="$state_root/manager.sqlite" \
    FERROCRATE_CONTROLLER_GRANT_KEY_ID=fleet-demo-controller \
    FERROCRATE_CONTROLLER_GRANT_SIGNING_KEY_FILE="$state_root/pki/controller-grant.key" \
    FERROCRATE_CONTROLLER_ENVELOPE_SIGNING_KEY_FILE="$state_root/pki/controller-envelope.key" \
    FERROCRATE_CONTROLLER_GRANT_ISSUER=fleet-demo-controller \
    FERROCRATE_CONTROLLER_ALLOWED_NODES_JSON='["lab-x86","oracle-arm"]' \
    FERROCRATE_CONTROLLER_RESOURCES_JSON='{}' \
    nohup "$repo_root/target/release/ferro-mgr" >>"$state_root/manager.log" 2>&1 &
  echo $! >"$state_root/pids/manager"
  wait_port 127.0.0.1 55052 "manager admin listener"
}

start_ui() {
  if pid_alive "$state_root/pids/ui"; then
    if operate_session >/dev/null 2>&1; then
      return
    fi
    note "Fleet UI login expired; restarting it"
    stop_pid "$state_root/pids/ui" 'Fleet UI' || die "Fleet UI did not stop before restart"
  fi
  note "starting Fleet browser UI"
  setsid env FERROCRATE_CLUSTER_ID="$cluster_id" \
    nohup "$repo_root/target/release/ferro-mgr" fleet-ui --listen "$ui_addr" --insecure-loopback \
      --admin-endpoint https://127.0.0.1:55052 --admin-domain localhost \
      --admin-server-ca "$state_root/pki/node-ca.pem" \
      --operator-cert "$state_root/pki/operator.pem" --operator-key "$state_root/pki/operator.key" \
      --state-dir "$state_root/ui" >>"$state_root/ui.log" 2>&1 &
  echo $! >"$state_root/pids/ui"
  wait_port 127.0.0.1 58443 "Fleet UI"
}

wait_port() {
  local host="$1" port="$2" label="$3";
  for _ in $(seq 1 30); do
    (echo >"/dev/tcp/$host/$port") >/dev/null 2>&1 && return
    sleep 1
  done
  die "$label did not become ready; see $state_root/*.log"
}

ensure_guest() {
  require virsh
  local domstate
  domstate="$(virsh domstate "$guest_name" 2>/dev/null || true)"
  if [[ "$domstate" != running ]]; then
    note "starting libvirt guest $guest_name"
    virsh start "$guest_name" >/dev/null || die "could not start libvirt guest $guest_name"
  fi
  for _ in $(seq 1 60); do
    guest_ssh true >/dev/null 2>&1 && return
    sleep 2
  done
  die "guest ${guest_user}@${guest_host} did not accept SSH; report-qualified account is lyle"
}

prepare_arm_repo() {
  note "shipping matching source bundle and building aarch64 agent on Oracle A1"
  local bundle="$state_root/ferrocrate-fleet.bundle" assets="$state_root/fleet-ui-dist.tar.gz"
  (cd "$repo_root" && git bundle create "$bundle" HEAD)
  (cd "$repo_root/apps/ferro-desktop-ui" && tar -czf "$assets" dist)
  scp -q "$bundle" "$assets" "${arm_user}@${arm_host}:/tmp/"
  arm_ssh "set -e; . \$HOME/.cargo/env || { echo 'Oracle Rust environment is unavailable at ~/.cargo/env' >&2; exit 2; }; if [ -d $arm_repo/.git ]; then cd $arm_repo; test -z \"\$(git status --porcelain)\" || { echo 'remote repo is dirty' >&2; exit 2; }; git fetch /tmp/ferrocrate-fleet.bundle HEAD; git checkout --detach FETCH_HEAD; else git clone /tmp/ferrocrate-fleet.bundle $arm_repo; cd $arm_repo; fi; tar -xzf /tmp/fleet-ui-dist.tar.gz -C apps/ferro-desktop-ui; CARGO_BUILD_JOBS=2 cargo build --release -p ferro-mgr --bin ferro-agent -p ferro-cli --bin ferro-cli"
}

start_reverse_forwards() {
  if pid_alive "$state_root/pids/arm-forward"; then return; fi
  note "starting Oracle reverse forwards for enrollment and control"
  ssh -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 -N \
    -R 127.0.0.1:55051:127.0.0.1:55051 -R 127.0.0.1:55053:127.0.0.1:55053 \
    "${arm_user}@${arm_host}" >>"$state_root/arm-forward.log" 2>&1 &
  echo $! >"$state_root/pids/arm-forward"
  sleep 2
  pid_alive "$state_root/pids/arm-forward" || die "Oracle reverse forwards failed; see $state_root/arm-forward.log"
}

login_session() {
  local credential_path="$1"
  [[ -f "$credential_path" ]] || die "Fleet UI login credential is missing; run up"
  curl --fail --silent --show-error -X POST "$ui_url/fleet/login" -H 'content-type: application/json' \
    --data "{\"credential\":\"$(tr -d '\n' <"$credential_path")\"}" | jq -er '.token'
}

operate_session() { login_session "$state_root/ui/operate.login"; }

invoke() {
  local token="$1" command="$2" body="$3"
  curl --fail --silent --show-error -X POST "$ui_url/__tauri/$command" \
    -H "authorization: Bearer $token" -H 'content-type: application/json' --data "$body"
}

issue_token() {
  local token="$1" node="$2" endpoint="$3"
  invoke "$token" fleet_enrollment_token "{\"node_id\":\"$node\",\"endpoint\":\"$endpoint\"}" | jq -er '.enrollment_token'
}

enroll_guest() {
  local token="$1" remote_state='.local/state/ferrocrate-fleet-demo'
  ship_guest_binary "$repo_root/target/release/ferro-agent"
  ship_guest_binary "$repo_root/target/release/ferro-cli"
  if ! guest_ssh "test -s \$HOME/$remote_state/agent.pem"; then
    local enrollment; enrollment="$(issue_token "$token" lab-x86 "$guest_host")"
    guest_ssh "mkdir -p \$HOME/$remote_state; chmod 700 \$HOME/$remote_state"
    scp -q "$state_root/pki/node-ca.pem" "${guest_user}@${guest_host}:/var/tmp/fleet-node-ca.pem"
    guest_ssh "/var/tmp/ferro-agent enroll --node-id lab-x86 --endpoint $guest_host --token '$enrollment' --manager-endpoint https://$guest_manager_host:55051 --server-ca /var/tmp/fleet-node-ca.pem --tls-domain localhost --cert-out \$HOME/$remote_state/agent.pem --key-out \$HOME/$remote_state/agent.key --node-ca-out \$HOME/$remote_state/node-ca.pem"
  fi
  guest_ssh "mkdir -p \$HOME/$remote_state/runtime; chmod 700 \$HOME/$remote_state/runtime; pkill -x ferro-agent || true; FERROCRATE_HOME=\$HOME/$remote_state/runtime FERROCRATE_RUNTIME_DIR=\$HOME/$remote_state/runtime nohup /var/tmp/ferro-agent fleet --node-id lab-x86 --control-endpoint https://$guest_manager_host:55053 --server-ca \$HOME/$remote_state/node-ca.pem --cert \$HOME/$remote_state/agent.pem --key \$HOME/$remote_state/agent.key --tls-domain localhost --runtime-exe /var/tmp/ferro-cli >\$HOME/$remote_state/agent.log 2>&1 </dev/null &"
}

enroll_arm() {
  local token="$1" arm_state='.local/state/ferrocrate-fleet-demo'
  if ! arm_ssh "test -s \$HOME/$arm_state/agent.pem"; then
    local enrollment; enrollment="$(issue_token "$token" oracle-arm "$arm_host")"
    scp -q "$state_root/pki/node-ca.pem" "${arm_user}@${arm_host}:/tmp/fleet-node-ca.pem"
    arm_ssh "mkdir -p \$HOME/$arm_state; chmod 700 \$HOME/$arm_state; $arm_repo/target/release/ferro-agent enroll --node-id oracle-arm --endpoint $arm_host --token '$enrollment' --manager-endpoint https://127.0.0.1:55051 --server-ca /tmp/fleet-node-ca.pem --tls-domain localhost --cert-out \$HOME/$arm_state/agent.pem --key-out \$HOME/$arm_state/agent.key --node-ca-out \$HOME/$arm_state/node-ca.pem"
  fi
  arm_ssh "mkdir -p \$HOME/$arm_state/runtime; chmod 700 \$HOME/$arm_state/runtime; pkill -x ferro-agent || true; FERROCRATE_HOME=\$HOME/$arm_state/runtime FERROCRATE_RUNTIME_DIR=\$HOME/$arm_state/runtime nohup $arm_repo/target/release/ferro-agent fleet --node-id oracle-arm --control-endpoint https://127.0.0.1:55053 --server-ca \$HOME/$arm_state/node-ca.pem --cert \$HOME/$arm_state/agent.pem --key \$HOME/$arm_state/agent.key --tls-domain localhost --runtime-exe $arm_repo/target/release/ferro-cli >\$HOME/$arm_state/agent.log 2>&1 </dev/null &"
}

snapshot() { invoke "$(operate_session)" get_fleet_snapshot '{}'; }

wait_connected() {
  for _ in $(seq 1 30); do
    local state; state="$(snapshot 2>/dev/null || true)"
    if jq -e '[.hosts[] | select(.node_id == "lab-x86" or .node_id == "oracle-arm") | select(.connected == true)] | length == 2' >/dev/null <<<"$state"; then return; fi
    sleep 2
  done
  die "both hosts did not connect; inspect $state_root/{manager,ui,arm-forward}.log and remote agent.log files"
}

print_logins() {
  local operate view
  operate="$(tr -d '\n' <"$state_root/ui/operate.login")"
  view="$(tr -d '\n' <"$state_root/ui/view.login")"
  printf 'Operate URL: %s\nOperate token: %s\nView URL: %s\nView token: %s\n' "$ui_url" "$operate" "$ui_url" "$view"
}

refresh_login_credential() {
  local credential_path="$1" session credential temporary
  session="$(login_session "$credential_path")" || return
  credential="$(curl --fail --silent --show-error -X POST "$ui_url/fleet/refresh-login" \
    -H "authorization: Bearer $session" | jq -er '.credential')" || return
  temporary="$(mktemp "${credential_path}.XXXXXX")"
  printf '%s\n' "$credential" >"$temporary"
  chmod 600 "$temporary"
  mv -f "$temporary" "$credential_path"
}

refresh_login() {
  require curl; require jq
  pid_alive "$state_root/pids/ui" || die "Fleet UI is not running; run up"
  refresh_login_credential "$state_root/ui/operate.login" \
    || die "Fleet UI login credential expired; run up to restart the UI"
  refresh_login_credential "$state_root/ui/view.login" \
    || die "Fleet UI view login credential expired; run up to restart the UI"
  note "refreshed Fleet UI login credentials without restarting it"
  print_logins
}

up() {
  require cargo; require curl; require jq; require openssl; require ssh; require scp; require git; require setsid
  ensure_layout; create_pki; build_local; start_manager; ensure_guest; prepare_arm_repo; start_reverse_forwards; start_ui
  local token; token="$(operate_session)"
  enroll_guest "$token"; enroll_arm "$token"; wait_connected; print_logins
}

wait_for_pid_exit() {
  local path="$1" label="$2"
  for _ in $(seq 1 50); do
    pid_alive "$path" || return
    sleep 0.1
  done
  note "$label did not exit after SIGTERM"
  return 1
}

stop_pid() {
  local path="$1" label="$2"
  if pid_alive "$path"; then
    local pid; pid="$(<"$path")"
    kill -- "-$pid" 2>/dev/null || kill "$pid" 2>/dev/null || true
    wait_for_pid_exit "$path" "$label" || return
  fi
  rm -f "$path"
  note "stopped $label"
}

down() {
  [[ -d "$state_root" ]] || exit 0
  guest_ssh 'pkill -x ferro-agent || true' >/dev/null 2>&1 || true
  arm_ssh 'pkill -x ferro-agent || true' >/dev/null 2>&1 || true
  stop_pid "$state_root/pids/arm-forward" 'Oracle reverse forwards' || true
  stop_pid "$state_root/pids/ui" 'Fleet UI' || true
  stop_pid "$state_root/pids/manager" 'manager' || true
  if command -v virsh >/dev/null 2>&1 && [[ "$(virsh domstate "$guest_name" 2>/dev/null || true)" == running ]]; then
    virsh shutdown "$guest_name" >/dev/null || true
    note "requested shutdown for $guest_name"
  fi
}

status() {
  printf 'manager: %s\nui: %s\narm reverse forwards: %s\n' \
    "$(pid_alive "$state_root/pids/manager" && echo up || echo down)" \
    "$(pid_alive "$state_root/pids/ui" && echo up || echo down)" \
    "$(pid_alive "$state_root/pids/arm-forward" && echo up || echo down)"
  if pid_alive "$state_root/pids/ui" && command -v jq >/dev/null 2>&1; then
    snapshot | jq -r '.hosts[] | select(.node_id == "lab-x86" or .node_id == "oracle-arm") | "\(.node_id): \(if .connected then "connected" else "disconnected" end)"' || true
  else
    printf 'lab-x86: unknown (Fleet UI is down)\noracle-arm: unknown (Fleet UI is down)\n'
  fi
}

verify() {
  require curl; require jq
  wait_connected
  local token name result host
  token="$(operate_session)"
  for host in lab-x86 oracle-arm; do
    name="fleet-demo-verify-${host}-$(date +%s)"
    result="$(invoke "$token" fleet_command "{\"node_id\":\"$host\",\"action\":\"run_container\",\"arguments\":{\"name\":\"$name\",\"image\":\"alpine:3.20\",\"command\":[\"/bin/sh\",\"-c\",\"echo fleet-verify-$host\"]}}")"
    jq -e '.exit_code == 0' >/dev/null <<<"$result" || die "run round-trip failed on $host: $result"
    result="$(invoke "$token" fleet_command "{\"node_id\":\"$host\",\"action\":\"container_logs\",\"arguments\":{\"container\":\"$name\"}}")"
    jq -e --arg expected "fleet-verify-$host" '.exit_code == 0 and (.stdout | contains($expected))' >/dev/null <<<"$result" || die "logs round-trip failed on $host: $result"
    note "verified run/logs round-trip on $host"
  done
}

case "${1:-up}" in
  up) up ;;
  down) down ;;
  --status) status ;;
  --refresh-login) refresh_login ;;
  verify) verify ;;
  --help|-h) usage ;;
  *) usage >&2; exit 2 ;;
esac
