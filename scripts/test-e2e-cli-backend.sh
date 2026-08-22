#!/usr/bin/env bash
set -euo pipefail

# Keep the generic E2E fixture on the explicitly selected firewall backend.
# `ferro-cli run` has an ebpf CLI default, so exporting an environment variable
# alone is insufficient for this script's direct run/build-run calls.
script="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/scripts/e2e-cli.sh"

grep -Fq 'network_backend="${FERROCRATE_NETWORK_BACKEND:-iptables}"' "$script"
grep -Fq 'run_network_args=(--network-backend "${network_backend}")' "$script"
grep -Fq '"${BIN}" run "${run_network_args[@]}" local/test:dev' "$script"
grep -Fq 'FERROCRATE_E2E_NETWORK_MODE:-}" == "none"' "$script"
grep -Fq 'docker_compat_ready=0' "$script"
grep -Fq 'daemon_ready_attempts="${FERROCRATE_E2E_DAEMON_READY_ATTEMPTS:-200}"' "$script"
grep -Fq 'docker_compat_unavailable=1' "$script"
grep -Fq 'SO_PEERPIDFD' "$script"
grep -Fq 'exit 77' "$script"
grep -Fq 'http://localhost/_ping' "$script"
grep -Fq 'did not become ready at /_ping' "$script"

printf '%s\n' 'e2e-cli-backend=pass'
