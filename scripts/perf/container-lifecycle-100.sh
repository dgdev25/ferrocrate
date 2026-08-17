#!/usr/bin/env bash
set -euo pipefail

# Rootful sustained OCI lifecycle probe. This deliberately reports a workload
# baseline, not a full chaos/resource-exhaustion qualification.
repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/../.." && pwd)}"
binary="${FERROCRATE_BIN:-$repo_root/target/release/ferro-cli}"
image="${FERROCRATE_PERF_IMAGE:-alpine:3.20}"
count="${FERROCRATE_LIFECYCLE_COUNT:-100}"
parallel="${FERROCRATE_LIFECYCLE_PARALLEL:-1}"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "perf.container_lifecycle_skipped=1"
  echo "perf.container_lifecycle_skip_reason=root_required"
  exit 77
fi
if ! [[ "$count" =~ ^[1-9][0-9]*$ && "$parallel" =~ ^[1-9][0-9]*$ ]]; then
  echo "invalid lifecycle count or parallelism" >&2
  exit 2
fi
if [[ ! -x "$binary" ]]; then
  cargo build -p ferro-cli --release >/dev/null
fi

tmp_root="$(mktemp -d /tmp/ferrocrate-lifecycle-100.XXXXXX)"
runtime_dir="${FERROCRATE_LIFECYCLE_RUNTIME_DIR:-$tmp_root/runtime}"
mkdir -p "$runtime_dir"
cleanup() { rm -rf "$tmp_root"; }
trap cleanup EXIT

env_prefix=(env "FERROCRATE_RUNTIME_DIR=$runtime_dir" "HOME=$tmp_root" "FERROCRATE_NETWORK_BACKEND=iptables")
pull_ok=1
if ! "${env_prefix[@]}" "$binary" pull "$image" >/dev/null 2>&1; then
  pull_ok=0
fi

# A single probe distinguishes a workload failure from a host that cannot
# expose the namespace identity required for OCI cleanup (common in nested CI
# or unprivileged development VMs).
probe_log="$tmp_root/probe.log"
if ! "${env_prefix[@]}" "$binary" run --rm --network none --network-backend iptables "$image" true >"$probe_log" 2>&1; then
  if grep -q "no kernel identity\|namespace identity" "$probe_log"; then
    echo "perf.container_lifecycle_skipped=1"
    echo "perf.container_lifecycle_skip_reason=namespace_identity_unavailable"
    sed -n '1,3p' "$probe_log" >&2
    exit 77
  fi
  echo "perf.container_lifecycle_probe=failed" >&2
  sed -n '1,8p' "$probe_log" >&2
  if (( pull_ok == 0 )); then
    echo "perf.container_lifecycle_skipped=1"
    echo "perf.container_lifecycle_skip_reason=image_unavailable"
    exit 77
  fi
  exit 1
fi

start_ns="$(date +%s%N)"
running=0
started=0
passed=0
failed=0
declare -a jobs=()

reap_one() {
  local pid="$1"
  if wait "$pid"; then passed=$((passed + 1)); else failed=$((failed + 1)); fi
  running=$((running - 1))
}

while (( started < count )); do
  "${env_prefix[@]}" "$binary" run --rm --network none --network-backend iptables "$image" true \
    >"$tmp_root/run-${started}.log" 2>&1 &
  jobs+=("$!")
  running=$((running + 1))
  started=$((started + 1))
  if (( running >= parallel )); then
    reap_one "${jobs[0]}"
    jobs=("${jobs[@]:1}")
  fi
done
for pid in "${jobs[@]}"; do reap_one "$pid"; done

end_ns="$(date +%s%N)"
elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))
echo "perf.container_lifecycle_count=$count"
echo "perf.container_lifecycle_parallel=$parallel"
echo "perf.container_lifecycle_passed=$passed"
echo "perf.container_lifecycle_failed=$failed"
echo "perf.container_lifecycle_elapsed_ms=$elapsed_ms"
if (( failed != 0 )); then
  for log in "$tmp_root"/run-*.log; do
    if grep -q "error:" "$log"; then
      echo "perf.container_lifecycle_first_failure=$(basename "$log")"
      sed -n '1,8p' "$log" >&2
      break
    fi
  done
  exit 1
fi
