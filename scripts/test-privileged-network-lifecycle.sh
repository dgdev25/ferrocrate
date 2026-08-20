#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'privileged network lifecycle failed: %s\n' "$*" >&2
  exit 1
}

skip() {
  printf 'SKIP: %s\n' "$*"
  exit 77
}

[[ "$(uname -s)" == Linux ]] || fail "Linux is required"
command -v ip >/dev/null || fail "ip is required"
command -v jq >/dev/null || fail "jq is required"
command -v ping >/dev/null || fail "ping is required"

[[ "${EUID}" -eq 0 ]] || skip "root (EUID=0) is required"
cap_eff="$(awk '/^CapEff:/{print $2}' /proc/self/status)"
[[ -n "$cap_eff" ]] || skip "effective capabilities are unreadable"
(( (16#${cap_eff} & 0x1000) != 0 )) || skip "effective cap_net_admin is required"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ferro_cli=""
if command -v ferro-cli >/dev/null; then
  ferro_cli="$(command -v ferro-cli)"
elif [[ -x "$repo_root/target/debug/ferro-cli" ]]; then
  ferro_cli="$repo_root/target/debug/ferro-cli"
elif [[ -x "$repo_root/target/release/ferro-cli" ]]; then
  ferro_cli="$repo_root/target/release/ferro-cli"
else
  fail "ferro-cli is required"
fi

unset FERROCRATE_NETWORK_KERNEL_STATE || true

prefix="fcnet103-$$-$(date +%s)-${RANDOM}"
ns_name="${prefix}"
ep_ns="${prefix}-ep"
if_id="$(printf '%s' "$prefix" | sha256sum | awk '{print substr($1,1,10)}')"
veth_host="vh${if_id}"
veth_ep="ve${if_id}"
runtime_dir="$(mktemp -d "/tmp/${prefix}-runtime.XXXXXX")"
net_name="${prefix}-net"
test_image="${FERROCRATE_NETWORK_TEST_IMAGE:-alpine:3.19}"
image_store="${FERROCRATE_NETWORK_IMAGE_STORE:-}"
network_backend="${FERROCRATE_NETWORK_BACKEND:-iptables}"
case "$network_backend" in
  iptables|nftables) ;;
  *) fail "unsupported FERROCRATE_NETWORK_BACKEND=$network_backend (use iptables or nftables)" ;;
esac
subnet="172.30.203.0/24"
expected_cidr="172.30.203.1/24"
endpoint_cidr="172.30.203.2/24"
gateway="172.30.203.1"
ipv6_subnet="fd42:203::/64"
ipv6_gateway="fd42:203::1"
endpoint_ipv6="fd42:203::2/64"
bridge_suffix="$(printf 'ferro-net-bridge-v1%s' "$net_name" | sha256sum | awk '{print substr($1,1,12)}')"
bridge_name="fc-${bridge_suffix}"

cleanup() {
  if ip netns list 2>/dev/null | awk '{print $1}' | grep -Fxq -- "$ep_ns"; then
    ip netns delete "$ep_ns" || true
  fi
  if ip netns list 2>/dev/null | awk '{print $1}' | grep -Fxq -- "$ns_name"; then
    ip netns delete "$ns_name" || true
  fi
  if ip -o link show "$veth_host" >/dev/null 2>&1; then
    ip link delete "$veth_host" || true
  fi
  if ip -o link show "$veth_ep" >/dev/null 2>&1; then
    ip link delete "$veth_ep" || true
  fi
  if ip -o link show "$bridge_name" >/dev/null 2>&1; then
    ip link delete "$bridge_name" || true
  fi
  if [[ -d "$runtime_dir" ]]; then
    rm -rf -- "$runtime_dir"
  fi
}
trap cleanup EXIT

# Linux CLI commands intentionally scope their image store beneath the runtime
# directory.  An explicit store lets a privileged fixture reuse a trusted,
# caller-preloaded image without reaching an external registry; the default
# remains fully isolated and unchanged.
if [[ -n "$image_store" ]]; then
  [[ -d "$image_store" ]] || fail "configured image store is not a directory: $image_store"
  ln -s -- "$image_store" "$runtime_dir/images"
  [[ -f "${image_store}.sqlite" ]] ||
    fail "configured image store database is missing: ${image_store}.sqlite"
  ln -s -- "${image_store}.sqlite" "$runtime_dir/images.sqlite"
fi

ferro_net() {
  ip netns exec "$ns_name" env \
    -u FERROCRATE_NETWORK_KERNEL_STATE \
    FERROCRATE_RUNTIME_DIR="$runtime_dir" \
    HOME="$runtime_dir" \
    "$ferro_cli" "$@"
}

# Pull the fixture before entering the isolated namespace; the namespace has
# no external route, while the image store is shared with the public run path.
if [[ "${FERROCRATE_NETWORK_SKIP_PULL:-0}" == 1 ]]; then
  image_listing="$(env FERROCRATE_RUNTIME_DIR="$runtime_dir" HOME="$runtime_dir" \
    "$ferro_cli" images 2>/dev/null || true)"
  grep -Fq -- "$test_image" <<<"$image_listing" ||
    fail "configured image store does not contain ${test_image}"
else
  env FERROCRATE_RUNTIME_DIR="$runtime_dir" HOME="$runtime_dir" \
    "$ferro_cli" pull "$test_image" >/dev/null \
    || fail "unable to prepare test image ${test_image}"
fi

ip netns add "$ns_name"
ip netns exec "$ns_name" ip link set lo up

run_killed_create() {
  local phase="$1"
  local fault_runtime fault_name fault_bridge journal pid deadline recovery
  fault_runtime="$(mktemp -d "/tmp/${prefix}-${phase}.runtime.XXXXXX")"
  fault_name="${net_name}-${phase,,}"
  fault_bridge_suffix="$(printf 'ferro-net-bridge-v1%s' "$fault_name" | sha256sum | awk '{print substr($1,1,12)}')"
  fault_bridge="fc-${fault_bridge_suffix}"
  journal="$fault_runtime/network-operations.journal"

  ip netns exec "$ns_name" env \
    FERROCRATE_RUNTIME_DIR="$fault_runtime" HOME="$fault_runtime" \
    FERROCRATE_ENABLE_TEST_FAULTS=1 FERROCRATE_NETWORK_KILL_AT="$phase" \
    "$ferro_cli" network create --subnet "$subnet" "$fault_name" \
    >"$fault_runtime/create.log" 2>&1 &
  pid=$!
  deadline=$((SECONDS + 10))
  while kill -0 "$pid" 2>/dev/null && (( SECONDS < deadline )); do
    if [[ -f "$journal" ]] && grep -aFq "\"phase\":\"$phase\"" "$journal"; then
      kill -KILL "$pid" 2>/dev/null || true
      break
    fi
    sleep 0.01
  done
  if ! grep -aFq "\"phase\":\"$phase\"" "$journal" 2>/dev/null; then
    kill -KILL "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    fail "did not observe ${phase} checkpoint for ${fault_name}"
  fi
  wait "$pid" 2>/dev/null || true

  recovery="$(ip netns exec "$ns_name" env \
    FERROCRATE_RUNTIME_DIR="$fault_runtime" HOME="$fault_runtime" \
    "$ferro_cli" network ls 2>&1)" \
    || fail "fresh runtime could not inspect ${phase} recovery"
  case "$phase" in
    IntentDurable)
      grep -F "$fault_name" <<<"$recovery" >/dev/null \
        && fail "IntentDurable recovery falsely published ${fault_name}"
      ;;
    IdentityObserved|StoreCommitted)
      grep -F "$fault_name" <<<"$recovery" >/dev/null \
        || fail "${phase} recovery did not publish ${fault_name}"
      ip netns exec "$ns_name" env \
        FERROCRATE_RUNTIME_DIR="$fault_runtime" HOME="$fault_runtime" \
        "$ferro_cli" network rm "$fault_name" >/dev/null \
        || fail "${phase} recovered network could not be removed"
      ;;
  esac
  ip -n "$ns_name" link delete "$fault_bridge" 2>/dev/null || true
  rm -rf -- "$fault_runtime"
}

run_killed_create IntentDurable
run_killed_create IdentityObserved
run_killed_create StoreCommitted

ferro_net network create --subnet "$subnet" --ipv6-subnet "$ipv6_subnet" \
  --ipv6-gateway "$ipv6_gateway" "$net_name"

# -d is required: plain `ip -j link` omits linkinfo.info_kind.
link_json="$(ip -n "$ns_name" -j -d link show "$bridge_name")"
addr_json="$(ip -n "$ns_name" -j addr show "$bridge_name")"

link_diag="$(jq -c --arg name "$bridge_name" '
  if type != "array" or length != 1 then
    {error: "expected one-element array", raw: .}
  else
    {
      ifname: .[0].ifname,
      expected_ifname: $name,
      ifindex: .[0].ifindex,
      info_kind: .[0].linkinfo.info_kind,
      flags: .[0].flags,
      operstate: .[0].operstate
    }
  end
' <<<"$link_json" 2>/dev/null || printf '%s' "$link_json")"

jq -e --arg name "$bridge_name" '
  (type == "array") and (length == 1)
  and .[0].ifname == $name
  and (.[0].ifindex | type == "number") and .[0].ifindex > 0
  and .[0].linkinfo.info_kind == "bridge"
  and ((.[0].flags | index("UP")) != null)
' <<<"$link_json" >/dev/null \
  || fail "bridge name/kind/ifindex/UP assertion failed for ${bridge_name}: ${link_diag}"

addr_diag="$(jq -c --arg cidr "$expected_cidr" '
  if type != "array" or length != 1 then
    {error: "expected one-element array", raw: .}
  else
    {
      expected_cidr: $cidr,
      inet: [.[0].addr_info[]? | select(.family == "inet") | "\(.local)/\(.prefixlen)"]
    }
  end
' <<<"$addr_json" 2>/dev/null || printf '%s' "$addr_json")"

jq -e --arg cidr "$expected_cidr" '
  (type == "array") and (length == 1)
  and (
    .[0].addr_info
    | map(select(.family == "inet") | "\(.local)/\(.prefixlen)")
    | index($cidr)
  ) != null
' <<<"$addr_json" >/dev/null \
  || fail "bridge CIDR assertion failed for ${bridge_name} expected ${expected_cidr}: ${addr_diag}"

jq -e --arg addr "$ipv6_gateway" '
  (type == "array") and (length == 1)
  and ((.[0].addr_info | map(select(.family == "inet6") | .local) | index($addr)) != null)
' <<<"$addr_json" >/dev/null \
  || fail "bridge IPv6 address assertion failed for ${bridge_name} expected ${ipv6_gateway}"

printf 'privileged network lifecycle: create observed %s cidr=%s\n' "$bridge_name" "$expected_cidr"

ip netns add "$ep_ns"
ip link add "$veth_host" type veth peer name "$veth_ep"
ip link set "$veth_host" netns "$ns_name"
ip link set "$veth_ep" netns "$ep_ns"
ip -n "$ns_name" link set "$veth_host" master "$bridge_name"
ip -n "$ns_name" link set "$veth_host" up
ip -n "$ep_ns" link set lo up
ip -n "$ep_ns" addr add "$endpoint_cidr" dev "$veth_ep"
ip -n "$ep_ns" addr add "$endpoint_ipv6" dev "$veth_ep" nodad
ip -n "$ep_ns" link set "$veth_ep" up
ip -n "$ep_ns" -6 route add "$ipv6_subnet" dev "$veth_ep"

ip netns exec "$ep_ns" ping -c 1 -W 2 "$gateway" >/dev/null \
  || fail "endpoint ${endpoint_cidr} failed to ping gateway ${gateway}"
ip netns exec "$ep_ns" ping -6 -c 1 -W 2 "$ipv6_gateway" >/dev/null \
  || fail "endpoint ${endpoint_ipv6} failed to ping gateway ${ipv6_gateway}"

printf 'privileged network lifecycle: endpoint %s pinged gateway %s\n' "$endpoint_cidr" "$gateway"

# Exercise the public container path. The command intentionally omits --rm so
# an exited record remains an extant association and must still block rm.
run_output="$(ferro_net run "$test_image" --network "$net_name" \
  --network-backend "$network_backend" -- sleep 60)" \
  || fail "public run failed on named network"
container_id="$(sed -n 's/.*container_id=\([^ ]*\).*/\1/p' <<<"$run_output" | head -n 1)"
[[ -n "$container_id" ]] || fail "public run did not return a container id"
container_pid="$(sed -n 's/.*pid=\([^ ]*\).*/\1/p' <<<"$run_output" | head -n 1)"
[[ -n "$container_pid" ]] || fail "public run did not return a container pid"

if ferro_net network rm "$net_name" >"$runtime_dir/rm-associated.log" 2>&1; then
  fail "network rm succeeded while container ${container_id} was associated"
fi
grep -F "in use by extant container association" "$runtime_dir/rm-associated.log" \
  >/dev/null || fail "network rm refused association with an unexpected error"

kill "$container_pid" 2>/dev/null || true
deadline=$((SECONDS + 5))
while kill -0 "$container_pid" 2>/dev/null && (( SECONDS < deadline )); do
  sleep 0.01
done
ferro_net rm "$container_id" \
  || fail "public container removal failed after association refusal"

run_killed_delete() {
  local fault_runtime fault_name fault_bridge_suffix fault_bridge journal pid deadline recovery
  fault_runtime="$(mktemp -d "/tmp/${prefix}-Removed.runtime.XXXXXX")"
  fault_name="${net_name}-removed"
  fault_bridge_suffix="$(printf 'ferro-net-bridge-v1%s' "$fault_name" | sha256sum | awk '{print substr($1,1,12)}')"
  fault_bridge="fc-${fault_bridge_suffix}"
  journal="$fault_runtime/network-operations.journal"
  ip netns exec "$ns_name" env FERROCRATE_RUNTIME_DIR="$fault_runtime" HOME="$fault_runtime" \
    "$ferro_cli" network create --subnet "$subnet" "$fault_name" >/dev/null \
    || fail "checkpoint delete fixture create failed"
  ip netns exec "$ns_name" env FERROCRATE_RUNTIME_DIR="$fault_runtime" HOME="$fault_runtime" \
    FERROCRATE_ENABLE_TEST_FAULTS=1 FERROCRATE_NETWORK_KILL_AT=Removed \
    "$ferro_cli" network rm "$fault_name" >"$fault_runtime/delete.log" 2>&1 &
  pid=$!
  deadline=$((SECONDS + 10))
  while kill -0 "$pid" 2>/dev/null && (( SECONDS < deadline )); do
    if [[ -f "$journal" ]] && grep -aFq '"phase":"Removed"' "$journal"; then
      kill -KILL "$pid" 2>/dev/null || true
      break
    fi
    sleep 0.01
  done
  if ! grep -aFq '"phase":"Removed"' "$journal" 2>/dev/null; then
    kill -KILL "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    fail "did not observe Removed checkpoint for ${fault_name}"
  fi
  wait "$pid" 2>/dev/null || true
  recovery="$(ip netns exec "$ns_name" env \
    FERROCRATE_RUNTIME_DIR="$fault_runtime" HOME="$fault_runtime" \
    "$ferro_cli" network ls 2>&1)" \
    || fail "fresh runtime could not inspect Removed recovery"
  if grep -F "$fault_name" <<<"$recovery" >/dev/null; then
    ip netns exec "$ns_name" env FERROCRATE_RUNTIME_DIR="$fault_runtime" HOME="$fault_runtime" \
      "$ferro_cli" network rm "$fault_name" >/dev/null \
      || fail "Removed recovery left a record that could not be finalized"
  fi
  if ip -n "$ns_name" -j link show "$fault_bridge" >/dev/null 2>&1; then
    fail "bridge ${fault_bridge} survived Removed recovery"
  fi
  rm -rf -- "$fault_runtime"
}

run_killed_delete

ip -n "$ns_name" link delete "$veth_host" || true
if ip netns list 2>/dev/null | awk '{print $1}' | grep -Fxq -- "$ep_ns"; then
  ip netns delete "$ep_ns" || true
fi

ferro_net network rm "$net_name" \
  || fail "public network rm failed for ${net_name}"

if ip -n "$ns_name" -j link show "$bridge_name" >/dev/null 2>&1; then
  fail "ip -j link still shows ${bridge_name} after network rm"
fi

networks_json="$runtime_dir/networks/networks.json"
if [[ -f "$networks_json" ]]; then
  jq -e --arg name "$net_name" '
    (type == "array") and all(.[]; .name != $name)
  ' "$networks_json" >/dev/null \
    || fail "runtime networks.json still contains ${net_name}"
fi

printf 'privileged network lifecycle: delete observed absent %s\n' "$bridge_name"
