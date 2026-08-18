#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname -- "$0")/.." && pwd)"

# The fixture is opt-in because user/mount namespaces are a host capability,
# not a property that the release gate may silently assume.  Without the opt-in
# we still compile and select the test; the test reports its explicit skip.
if [[ "${FERROCRATE_RUN_ROOTLESS_CRI_E2E:-0}" == "1" ||
      "${FERROCRATE_RUN_ROOTLESS_CRI_E2E:-}" == "true" ]]; then
  export FERROCRATE_RUN_ROOTLESS_CRI_E2E=1
  echo "[rootless-cri] running opt-in OCI lifecycle fixture"
else
  echo "[rootless-cri] prerequisite execution not requested; running boundary check"
fi

cd "$repo_root"
cargo test -p ferro-cri --test socket_integration --offline \
  cri_socket_starts_and_execs_a_real_oci_rootfs_fixture -- --nocapture

echo "rootless CRI OCI fixture gate passed (opt-in=${FERROCRATE_RUN_ROOTLESS_CRI_E2E:-0})"
