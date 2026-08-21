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
grep -Fq 'setsid "$@" &' "$script"
grep -Fq 'kill -TERM -- "-${command_pid}"' "$script"
grep -Fq '|| true)' "$script"
grep -Fq 'FERROCRATE_EBPF_DIAGNOSTICS_DIR' "$script"
grep -Fq 'FERROCRATE_BRIDGE_NAME=' "$script"
grep -Fq 'netns_before=' "$script"
grep -Fq 'ip netns del' "$script"
grep -Fq 'veth_before=' "$script"
grep -Fq 'link-netnsid' "$script"
grep -Fq 'lo_ingress_before=' "$script"
grep -Fq 'lo_egress_before=' "$script"
grep -Fq 'tc filter del dev lo' "$script"
diagnostic="$repo_root/scripts/diagnose-ebpf-live.sh"
bash -n "$diagnostic"
grep -Fq 'setsid "$@"' "$diagnostic"
grep -Fq 'kill -TERM -- "-$command_pid"' "$diagnostic"
grep -Fq 'find "$target_dir" -depth -delete' "$diagnostic"
grep -Fq 'baseline_pin_dirs=' "$diagnostic"
grep -Fq 'cleanup_created_classifiers' "$diagnostic"
grep -Fq 'tc filter del dev "$dev" "$direction"' "$diagnostic"

printf '%s\n' 'ebpf-networking-backend=pass'
