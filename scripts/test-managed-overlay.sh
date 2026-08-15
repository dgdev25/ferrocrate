#!/usr/bin/env bash
set -euo pipefail

repo_root="${FERROCRATE_REPO_ROOT:-${PWD}}"
if [[ ! -f "$repo_root/Cargo.toml" ]]; then
  repo_root=$(cd "$(dirname -- "$0")/.." && pwd)
fi
cd "$repo_root"

cargo test -p ferro-mgr --tests
cargo test -p ferro-netd
cargo test -p ferro-netd --test transaction_fault_matrix
cargo test -p ferro-netd --test authorization_grants key_rotation_accepts_overlap_then_rejects_retired_key
cargo test -p ferro-core managed_overlay
cargo test -p ferro-core network_backend
cargo test -p ferro-cli managed_overlay
cargo test -p ferro-cli network_backend
cargo test -p ferro-mgr --test agent_reconcile equal_revision_without_lease_extension_is_stale

if [[ "${FERROCRATE_RUN_PRIVILEGED_TESTS:-0}" != "1" ]]; then
  echo "privileged managed-overlay gate skipped; set FERROCRATE_RUN_PRIVILEGED_TESTS=1 to enable" >&2
  exit 0
fi

if [[ "$(id -u)" != "0" ]]; then
  echo "privileged managed-overlay gate requires root" >&2
  exit 1
fi

: "${FERRO_EBPF_TEST_INTERFACE:?FERRO_EBPF_TEST_INTERFACE is required}"
: "${FERRO_EBPF_TEST_IFINDEX:?FERRO_EBPF_TEST_IFINDEX is required}"
: "${FERROCRATE_NETD_WG_PRIVATE_KEY_PATH:?FERROCRATE_NETD_WG_PRIVATE_KEY_PATH is required}"

bash scripts/test-ebpf-networking.sh
echo "privileged managed-overlay prerequisites validated; two-host traffic qualification must be run with the deployment harness"
