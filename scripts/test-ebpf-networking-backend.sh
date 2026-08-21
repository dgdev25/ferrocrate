#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname -- "$0")/.." && pwd)"
script="$repo_root/scripts/test-ebpf-networking.sh"

# The privileged qualification must opt into the explicitly experimental
# published-port path.  Without this export the e2e fixture fails closed before
# attaching the eBPF datapath, producing a false negative for kernel coverage.
grep -Fqx 'export FERROCRATE_EBPF_ALLOW_PUBLISHED_PORTS=1' "$script"
grep -Fq 'FERROCRATE_EBPF_STEP_TIMEOUT' "$script"
grep -Fq 'run_bounded' "$script"
grep -Fq 'timeout --foreground' "$script"
grep -Fq '|| true)' "$script"
grep -Fq 'FERROCRATE_EBPF_DIAGNOSTICS_DIR' "$script"
grep -Fq 'netns_before=' "$script"
grep -Fq 'ip netns del' "$script"
grep -Fq 'veth_before=' "$script"
grep -Fq 'link-netnsid' "$script"
grep -Fq 'lo_ingress_before=' "$script"
grep -Fq 'lo_egress_before=' "$script"
grep -Fq 'tc filter del dev lo' "$script"

printf '%s\n' 'ebpf-networking-backend=pass'
