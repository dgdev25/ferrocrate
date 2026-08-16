#!/usr/bin/env bash
set -euo pipefail

# Read-only capability inventory for a supported-host matrix row.
# This intentionally performs no namespace, link, firewall, or route mutation.

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/.." && pwd)}"
output_file="${1:-}"

have() { command -v "$1" >/dev/null 2>&1; }
value_or_missing() {
  if [[ $# -eq 0 ]]; then
    printf 'missing'
  elif [[ -r "$1" ]]; then
    tr '\n' ' ' <"$1" | sed 's/[[:space:]]*$//'
  else
    printf 'unreadable'
  fi
}

kernel="$(uname -srvm)"
arch="$(uname -m)"
if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  distro="${PRETTY_NAME:-${ID:-unknown}}"
else
  distro="unknown"
fi

cap_eff="$(awk '/^CapEff:/{print $2}' /proc/self/status 2>/dev/null || true)"
cap_net_admin="unknown"
if [[ "$cap_eff" =~ ^[0-9a-fA-F]+$ ]]; then
  if (( (16#${cap_eff} & 0x1000) != 0 )); then
    cap_net_admin="yes"
  else
    cap_net_admin="no"
  fi
fi

lines=(
  "repo=$repo_root"
  "distro=$distro"
  "kernel=$kernel"
  "arch=$arch"
  "uid=$(id -u)"
  "cap_net_admin=$cap_net_admin"
  "ip=$(have ip && ip -V 2>&1 || printf missing)"
  "wg=$(have wg && wg --version 2>&1 || printf missing)"
  "nft=$(have nft && nft --version 2>&1 || printf missing)"
  "iptables=$(have iptables && iptables --version 2>&1 || printf missing)"
  "tc=$(have tc && tc -V 2>&1 || printf missing)"
  "resolvectl=$(have resolvectl && resolvectl --version 2>&1 || printf missing)"
  "ping=$(have ping && ping -V 2>&1 | head -1 || printf missing)"
  "cargo=$(have cargo && cargo --version 2>&1 || printf missing)"
  "rustc=$(have rustc && rustc --version 2>&1 || printf missing)"
)

if [[ -n "$output_file" ]]; then
  mkdir -p "$(dirname -- "$output_file")"
  printf '%s\n' "${lines[@]}" >"$output_file"
  printf 'host matrix preflight written: %s\n' "$output_file"
else
  printf '%s\n' "${lines[@]}"
fi
