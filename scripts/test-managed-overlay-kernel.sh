#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'managed-overlay kernel gate failed: %s\n' "$*" >&2
  exit 1
}

skip() {
  printf 'SKIP: %s\n' "$*" >&2
  exit 77
}

[[ "$(uname -s)" == Linux ]] || fail "Linux is required"
command -v ip >/dev/null || fail "ip is required"
command -v wg >/dev/null || skip "wireguard-tools (wg) is required"
[[ "$(id -u)" == 0 ]] || skip "root is required"
cap_eff="$(awk '/^CapEff:/{print $2}' /proc/self/status)"
[[ -n "$cap_eff" ]] || skip "effective capabilities are unreadable"
(( (16#${cap_eff} & 0x1000) != 0 )) || skip "effective cap_net_admin is required"

prefix="fc-overlay-kernel-$$-$(date +%s)"
ns_a="${prefix}-a"
ns_b="${prefix}-b"
veth_a="va$(printf '%s' "$prefix" | sha256sum | cut -c1-9)"
veth_b="vb$(printf '%s' "$prefix" | sha256sum | cut -c1-9)"
wg_a="wga$(printf '%s' "$prefix" | sha256sum | cut -c1-8)"
wg_b="wgb$(printf '%s' "$prefix" | sha256sum | cut -c1-8)"

cleanup() {
  ip netns delete "$ns_a" 2>/dev/null || true
  ip netns delete "$ns_b" 2>/dev/null || true
}
trap cleanup EXIT

ip netns add "$ns_a"
ip netns add "$ns_b"
ip link add "$veth_a" type veth peer name "$veth_b"
ip link set "$veth_a" netns "$ns_a"
ip link set "$veth_b" netns "$ns_b"
ip -n "$ns_a" link set lo up
ip -n "$ns_b" link set lo up
ip -n "$ns_a" addr add 10.200.0.1/24 dev "$veth_a"
ip -n "$ns_b" addr add 10.200.0.2/24 dev "$veth_b"
ip -n "$ns_a" link set "$veth_a" up
ip -n "$ns_b" link set "$veth_b" up

key_a="$(wg genkey)"
key_b="$(wg genkey)"
pub_a="$(printf '%s\n' "$key_a" | wg pubkey)"
pub_b="$(printf '%s\n' "$key_b" | wg pubkey)"

ip -n "$ns_a" link add "$wg_a" type wireguard
ip -n "$ns_b" link add "$wg_b" type wireguard
ip -n "$ns_a" addr add 10.99.0.1/24 dev "$wg_a"
ip -n "$ns_b" addr add 10.99.0.2/24 dev "$wg_b"
printf '%s\n' "$key_a" | ip netns exec "$ns_a" wg set "$wg_a" private-key /dev/stdin listen-port 51820 \
  peer "$pub_b" allowed-ips 10.99.0.2/32 endpoint 10.200.0.2:51821 persistent-keepalive 1
printf '%s\n' "$key_b" | ip netns exec "$ns_b" wg set "$wg_b" private-key /dev/stdin listen-port 51821 \
  peer "$pub_a" allowed-ips 10.99.0.1/32 endpoint 10.200.0.1:51820 persistent-keepalive 1
ip -n "$ns_a" link set "$wg_a" up
ip -n "$ns_b" link set "$wg_b" up

ip netns exec "$ns_a" ping -c 2 -W 3 10.99.0.2 >/dev/null \
  || fail "encrypted packet flow from host A to host B failed"
ip netns exec "$ns_b" ping -c 2 -W 3 10.99.0.1 >/dev/null \
  || fail "encrypted packet flow from host B to host A failed"

handshake_a="$(ip netns exec "$ns_a" wg show "$wg_a" latest-handshakes | awk 'NR==1 {print $2}')"
handshake_b="$(ip netns exec "$ns_b" wg show "$wg_b" latest-handshakes | awk 'NR==1 {print $2}')"
[[ "${handshake_a:-0}" =~ ^[0-9]+$ && "$handshake_a" -gt 0 ]] \
  || fail "host A has no WireGuard handshake"
[[ "${handshake_b:-0}" =~ ^[0-9]+$ && "$handshake_b" -gt 0 ]] \
  || fail "host B has no WireGuard handshake"

printf 'managed-overlay kernel gate: bidirectional encrypted traffic and handshakes passed (%s <-> %s)\n' \
  "$ns_a" "$ns_b"
