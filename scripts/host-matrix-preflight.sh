#!/usr/bin/env bash
set -euo pipefail

# Read-only capability inventory for a supported-host matrix row.
# This intentionally performs no namespace, link, firewall, or route mutation.

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/.." && pwd)}"
output_file="${1:-}"

have() { command -v "$1" >/dev/null 2>&1; }
version_line() {
  local output
  have "$1" || { printf 'missing'; return; }
  if output=$("$@" 2>/dev/null); then
    printf '%s' "$output" | head -1
  else
    printf 'missing'
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
  "ip=$(version_line ip -V)"
  "wg=$(version_line wg --version)"
  "nft=$(version_line nft --version)"
  "iptables=$(version_line iptables --version)"
  "tc=$(version_line tc -V)"
  "resolvectl=$(version_line resolvectl --version)"
  "ping=$(version_line ping -V)"
  "cargo=$(version_line cargo --version)"
  "rustc=$(version_line rustc --version)"
)

if [[ -n "$output_file" ]]; then
  mkdir -p "$(dirname -- "$output_file")"
  printf '%s\n' "${lines[@]}" >"$output_file"
  printf 'host matrix preflight written: %s\n' "$output_file"
else
  printf '%s\n' "${lines[@]}"
fi
