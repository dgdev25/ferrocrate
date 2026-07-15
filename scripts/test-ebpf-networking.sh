#!/usr/bin/env bash
set -euo pipefail

fail() { printf 'eBPF networking qualification failed: %s\n' "$*" >&2; exit 1; }
[[ "$(uname -s)" == Linux ]] || fail "Linux is required"
[[ "${EUID}" -eq 0 ]] || fail "run with sudo"
command -v tc >/dev/null || fail "tc is required"
mountpoint -q /sys/fs/bpf || fail "bpffs must be mounted at /sys/fs/bpf"

IFS=. read -r kernel_major kernel_minor _ <<<"$(uname -r)"
(( kernel_major > 5 || (kernel_major == 5 && kernel_minor >= 10) )) \
  || fail "kernel 5.10+ is required"

: "${FERRO_EBPF_TEST_INTERFACE:?set the host interface used for qualification}"
: "${FERRO_EBPF_TEST_IFINDEX:?set the matching host interface ifindex}"
: "${FERRO_EBPF_TEST_EXTERNAL_IPV4:?set the matching external IPv4 address}"
: "${FERRO_EBPF_TEST_NEXT_HOP_MAC:?set the route next-hop MAC address}"
: "${FERRO_EBPF_TEST_SNAT_START:?set a reserved SNAT range start}"
: "${FERRO_EBPF_TEST_SNAT_END:?set a reserved SNAT range end}"

export FERRO_EBPF_TEST_NETWORK_ID="ferro-qualify-$$"
export FERROCRATE_E2E_NETWORK_BACKEND=ebpf
export FERROCRATE_EBPF_SNAT_PORT_RANGE="${FERRO_EBPF_TEST_SNAT_START}-${FERRO_EBPF_TEST_SNAT_END}"
before_iptables="$(mktemp)"
before_nft="$(mktemp)"
after_iptables="$(mktemp)"
after_nft="$(mktemp)"
cleanup() {
  rm -f "$before_iptables" "$before_nft" "$after_iptables" "$after_nft"
  rm -rf "/sys/fs/bpf/ferrocrate/${FERRO_EBPF_TEST_NETWORK_ID}" || true
}
trap cleanup EXIT

iptables-save >"$before_iptables" 2>/dev/null || true
nft list ruleset >"$before_nft" 2>/dev/null || true

cargo test -p ferro-net --test kernel_compat -- --ignored
cargo test -p ferro-net --test ebpf_integration privileged_aya_load_detach_smoke_deferred_to_task_7 -- --ignored
cargo test --test e2e_container_lifecycle -- --ignored ebpf_network_published_port_egress_without_netfilter_changes

iptables-save >"$after_iptables" 2>/dev/null || true
nft list ruleset >"$after_nft" 2>/dev/null || true
cmp -s "$before_iptables" "$after_iptables" || fail "iptables state changed in eBPF mode"
cmp -s "$before_nft" "$after_nft" || fail "nftables state changed in eBPF mode"
[[ ! -e "/sys/fs/bpf/ferrocrate/${FERRO_EBPF_TEST_NETWORK_ID}" ]] || fail "owned eBPF pins leaked"

printf 'eBPF networking qualification passed\n'
