#!/usr/bin/env bash
set -euo pipefail

# Keep the generic E2E fixture on the explicitly selected firewall backend.
# `ferro-cli run` has an ebpf CLI default, so exporting an environment variable
# alone is insufficient for this script's direct run/build-run calls.
script="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/scripts/e2e-cli.sh"

grep -Fq 'network_backend="${FERROCRATE_NETWORK_BACKEND:-iptables}"' "$script"
grep -Fq '"${BIN}" run --network-backend "${network_backend}"' "$script"
grep -Fq '"${BIN}" run --network-backend "${network_backend}" local/test:dev' "$script"

printf '%s\n' 'e2e-cli-backend=pass'
