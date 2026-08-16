#!/usr/bin/env bash
set -euo pipefail

# Produce a conservative, machine-readable capacity estimate. This is a
# planning gate, not a substitute for the sustained-load qualification suite.
repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/.." && pwd)}"
runtime_dir="${FERROCRATE_RUNTIME_DIR:-$repo_root/target/ferrocrate-runtime}"
output="${FERROCRATE_CAPACITY_OUTPUT:-$repo_root/target/capacity-plan.json}"
target="${FERROCRATE_CAPACITY_TARGET_CONTAINERS:-100}"
memory_per="${FERROCRATE_CAPACITY_MEMORY_PER_CONTAINER_BYTES:-268435456}"
pids_per="${FERROCRATE_CAPACITY_PIDS_PER_CONTAINER:-64}"
disk_per="${FERROCRATE_CAPACITY_DISK_PER_CONTAINER_BYTES:-1073741824}"

positive_integer() { [[ "$1" =~ ^[1-9][0-9]*$ ]]; }
for value in "$target" "$memory_per" "$pids_per" "$disk_per"; do
  positive_integer "$value" || {
    printf 'capacity-plan: expected positive integer, got %s\n' "$value" >&2
    exit 2
  }
done

host_cpus="${FERROCRATE_CAPACITY_HOST_CPUS:-$(nproc 2>/dev/null || printf 1)}"
host_memory="${FERROCRATE_CAPACITY_HOST_MEMORY_BYTES:-}"
host_pids="${FERROCRATE_CAPACITY_HOST_PIDS:-}"
host_disk="${FERROCRATE_CAPACITY_HOST_DISK_BYTES:-}"
if [[ -z "$host_memory" ]]; then
  host_memory=$(( $(awk '/MemTotal:/ {print $2; exit}' /proc/meminfo) * 1024 ))
fi
if [[ -z "$host_pids" ]]; then
  host_pids="$(cat /proc/sys/kernel/pid_max 2>/dev/null || printf 32768)"
fi
if [[ -z "$host_disk" ]]; then
  mkdir -p "$runtime_dir"
  host_disk=$(( $(df -Pk "$runtime_dir" | awk 'NR==2 {print $4}') * 1024 ))
fi
for value in "$host_cpus" "$host_memory" "$host_pids" "$host_disk"; do
  positive_integer "$value" || {
    printf 'capacity-plan: host capacity is not a positive integer: %s\n' "$value" >&2
    exit 2
  }
done

cpu_capacity="$host_cpus"
memory_capacity=$((host_memory / memory_per))
pid_capacity=$((host_pids / pids_per))
disk_capacity=$((host_disk / disk_per))
effective_capacity="$cpu_capacity"
(( memory_capacity < effective_capacity )) && effective_capacity="$memory_capacity"
(( pid_capacity < effective_capacity )) && effective_capacity="$pid_capacity"
(( disk_capacity < effective_capacity )) && effective_capacity="$disk_capacity"
if (( effective_capacity >= target )); then
  verdict="pass"
  exit_code=0
else
  verdict="insufficient"
  exit_code=1
fi

mkdir -p "$(dirname -- "$output")"
temporary="${output}.tmp"
printf '{\n  "target_containers": %s,\n  "estimated_capacity": %s,\n  "verdict": "%s",\n  "inputs": {"host_cpus": %s, "host_memory_bytes": %s, "host_pids": %s, "host_disk_bytes": %s, "memory_per_container_bytes": %s, "pids_per_container": %s, "disk_per_container_bytes": %s},\n  "qualification": "planning-only; sustained load and kernel fault matrices remain required"\n}\n' \
  "$target" "$effective_capacity" "$verdict" "$host_cpus" "$host_memory" "$host_pids" "$host_disk" "$memory_per" "$pids_per" "$disk_per" >"$temporary"
mv -- "$temporary" "$output"
printf 'capacity-plan: verdict=%s estimated_capacity=%s target=%s output=%s\n' \
  "$verdict" "$effective_capacity" "$target" "$output"
exit "$exit_code"
