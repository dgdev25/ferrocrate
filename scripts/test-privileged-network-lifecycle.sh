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
subnet="172.30.203.0/24"
expected_cidr="172.30.203.1/24"
endpoint_cidr="172.30.203.2/24"
gateway="172.30.203.1"
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

ferro_net() {
  ip netns exec "$ns_name" env \
    -u FERROCRATE_NETWORK_KERNEL_STATE \
    FERROCRATE_RUNTIME_DIR="$runtime_dir" \
    HOME="$runtime_dir" \
    "$ferro_cli" "$@"
}

ip netns add "$ns_name"
ip netns exec "$ns_name" ip link set lo up

ferro_net network create --subnet "$subnet" "$net_name"

link_json="$(ip -n "$ns_name" -j link show "$bridge_name")"
addr_json="$(ip -n "$ns_name" -j addr show "$bridge_name")"

jq -e --arg name "$bridge_name" '
  (type == "array") and (length == 1)
  and .[0].ifname == $name
  and (. [0].ifindex | type == "number") and .[0].ifindex > 0
  and .[0].linkinfo.info_kind == "bridge"
  and ((.[0].flags | index("UP")) != null)
' <<<"$link_json" >/dev/null \
  || fail "bridge name/kind/ifindex/UP assertion failed for ${bridge_name}"

jq -e --arg cidr "$expected_cidr" '
  (type == "array") and (length == 1)
  and (
    .[0].addr_info
    | map(select(.family == "inet") | "\(.local)/\(.prefixlen)")
    | index($cidr)
  ) != null
' <<<"$addr_json" >/dev/null \
  || fail "bridge CIDR assertion failed for ${bridge_name} expected ${expected_cidr}"

printf 'privileged network lifecycle: create observed %s cidr=%s\n' "$bridge_name" "$expected_cidr"

ip netns add "$ep_ns"
ip link add "$veth_host" type veth peer name "$veth_ep"
ip link set "$veth_host" netns "$ns_name"
ip link set "$veth_ep" netns "$ep_ns"
ip -n "$ns_name" link set "$veth_host" master "$bridge_name"
ip -n "$ns_name" link set "$veth_host" up
ip -n "$ep_ns" link set lo up
ip -n "$ep_ns" addr add "$endpoint_cidr" dev "$veth_ep"
ip -n "$ep_ns" link set "$veth_ep" up

ip netns exec "$ep_ns" ping -c 1 -W 2 "$gateway" >/dev/null \
  || fail "endpoint ${endpoint_cidr} failed to ping gateway ${gateway}"

printf 'privileged network lifecycle: endpoint %s pinged gateway %s\n' "$endpoint_cidr" "$gateway"

# Association refusal is not exercised. Public NetworkCommands is
# Create/Ls/Rm only. There is no ferro-cli network connect and no
# documented public container-run hook that writes a ContainerRecord
# onto this named network. Inventing a store put would fake the proof.
printf 'SKIP association guard: no public ferro-cli network connect or documented container-associate hook (NetworkCommands is Create/Ls/Rm only)\n'

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

# Checkpoint kill evidence is unsupported. FERROCRATE_NETWORK_KERNEL_STATE
# selects a file-backed emulator; it is not a phase-kill injector.
# No documented env or fault hook kills at IntentDurable,
# IdentityObserved, StoreCommitted, or Removed and then proves recovery
# or quarantine on a fresh runtime.
printf 'SKIP checkpoint kill evidence: no documented env/fault hook to inject process kill at IntentDurable/IdentityObserved/StoreCommitted/Removed\n'

printf 'privileged network lifecycle: delete observed absent %s\n' "$bridge_name"
