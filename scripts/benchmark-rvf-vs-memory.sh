#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

echo "Benchmarking RVF backend..."
start_rvf="$(date +%s%N)"
FERROCRATE_AI_BACKEND=rvf cargo test -q -p ferro-mind persistent_memory_survives_reopen --features rvf-persistence
end_rvf="$(date +%s%N)"

echo "Benchmarking legacy backend..."
start_legacy="$(date +%s%N)"
FERROCRATE_AI_BACKEND=legacy cargo test -q -p ferro-mind vector_memory_insert_and_search --features rvf-persistence
end_legacy="$(date +%s%N)"

rvf_ms=$(( (end_rvf - start_rvf) / 1000000 ))
legacy_ms=$(( (end_legacy - start_legacy) / 1000000 ))

echo "RVF test elapsed: ${rvf_ms}ms"
echo "Legacy test elapsed: ${legacy_ms}ms"
echo "Done."
