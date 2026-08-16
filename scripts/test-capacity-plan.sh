#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname -- "$0")/.." && pwd)"
temp_dir="$(mktemp -d)"
trap 'rm -rf -- "$temp_dir"' EXIT
output="$temp_dir/capacity.json"

FERROCRATE_CAPACITY_OUTPUT="$output" \
FERROCRATE_CAPACITY_TARGET_CONTAINERS=10 \
FERROCRATE_CAPACITY_HOST_CPUS=16 \
FERROCRATE_CAPACITY_HOST_MEMORY_BYTES=4294967296 \
FERROCRATE_CAPACITY_HOST_PIDS=4096 \
FERROCRATE_CAPACITY_HOST_DISK_BYTES=10737418240 \
FERROCRATE_CAPACITY_MEMORY_PER_CONTAINER_BYTES=268435456 \
FERROCRATE_CAPACITY_PIDS_PER_CONTAINER=64 \
FERROCRATE_CAPACITY_DISK_PER_CONTAINER_BYTES=1073741824 \
  "$repo_root/scripts/capacity-plan.sh" >/dev/null
grep -q '"verdict": "pass"' "$output"
grep -q '"estimated_capacity": 10' "$output"

if FERROCRATE_CAPACITY_OUTPUT="$temp_dir/insufficient.json" \
  FERROCRATE_CAPACITY_TARGET_CONTAINERS=100 \
  FERROCRATE_CAPACITY_HOST_CPUS=2 \
  FERROCRATE_CAPACITY_HOST_MEMORY_BYTES=1073741824 \
  FERROCRATE_CAPACITY_HOST_PIDS=64 \
  FERROCRATE_CAPACITY_HOST_DISK_BYTES=1073741824 \
    "$repo_root/scripts/capacity-plan.sh" >/dev/null; then
  printf 'capacity test: insufficient fixture unexpectedly passed\n' >&2
  exit 1
fi
grep -q '"verdict": "insufficient"' "$temp_dir/insufficient.json"

if FERROCRATE_CAPACITY_TARGET_CONTAINERS=not-a-number "$repo_root/scripts/capacity-plan.sh" >/dev/null 2>&1; then
  printf 'capacity test: invalid input unexpectedly passed\n' >&2
  exit 1
fi
printf 'capacity-plan tests passed\n'
