#!/usr/bin/env bash
set -euo pipefail

# Read-only checks for host capabilities that support the network matrix.
# This does not add links, routes, firewall rules, qdiscs, or WireGuard peers.

output_file="${1:-}"
have() { command -v "$1" >/dev/null 2>&1; }
run_check() {
  local name="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    printf '%s=pass\n' "$name"
  else
    printf '%s=fail\n' "$name"
  fi
}

lines=(
  "host=$(hostname -f 2>/dev/null || hostname)"
  "kernel=$(uname -r)"
  "mtu_readback=$(run_check ip_link ip link show)"
  "mtu_json_readback=$(run_check ip_json ip -j link show)"
  "firewall_nft_readback=$(run_check nft_ruleset nft list ruleset)"
  "firewall_iptables_readback=$(run_check iptables_rules iptables -S)"
  "firewall_iptables_nat_readback=$(run_check iptables_nat iptables -t nat -S)"
  "traffic_control_readback=$(run_check tc_qdisc tc qdisc show)"
  "dns_resolver_readback=$(run_check resolvectl resolvectl status)"
  "wireguard_tool=$(run_check wireguard wg --version)"
)

if [[ -n "$output_file" ]]; then
  mkdir -p "$(dirname -- "$output_file")"
  printf '%s\n' "${lines[@]}" >"$output_file"
  printf 'host matrix supporting checks written: %s\n' "$output_file"
else
  printf '%s\n' "${lines[@]}"
fi
