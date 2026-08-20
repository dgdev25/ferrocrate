#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname -- "$0")/.." && pwd)"
script="$repo_root/scripts/test-ebpf-networking.sh"

# The privileged qualification must opt into the explicitly experimental
# published-port path.  Without this export the e2e fixture fails closed before
# attaching the eBPF datapath, producing a false negative for kernel coverage.
grep -Fqx 'export FERROCRATE_EBPF_ALLOW_PUBLISHED_PORTS=1' "$script"

printf '%s\n' 'ebpf-networking-backend=pass'
