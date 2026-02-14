#!/usr/bin/env bash
set -euo pipefail

echo "Testing RVF integration..."

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export FERROCRATE_AI=1
export FERROCRATE_DATA_DIR="$(mktemp -d)"
trap 'rm -rf "$FERROCRATE_DATA_DIR"' EXIT

DATA_DIR="$FERROCRATE_DATA_DIR/data/resource-predictor"
MODELS_DIR="$FERROCRATE_DATA_DIR/models"
mkdir -p "$DATA_DIR" "$MODELS_DIR"

# Seed enough data to satisfy current training minimum.
for i in $(seq 1 120); do
  cp "$ROOT_DIR/tests/fixtures/training-data.jsonl" "$DATA_DIR/sample_${i}.json"
done

echo "Test 1: Train model..."
cargo run -q -p ferro-cli -- ai train \
  --model-type resource-predictor \
  --data-dir "$FERROCRATE_DATA_DIR/data" \
  --models-dir "$MODELS_DIR" \
  --output "$FERROCRATE_DATA_DIR/test-model.rvf"

echo "Test 2: Verify model stats..."
cargo run -q -p ferro-cli -- ai stats "$FERROCRATE_DATA_DIR/test-model.rvf" | grep "total_vectors="

echo "Test 3: Branch and lineage..."
cargo run -q -p ferro-cli -- ai branch "$FERROCRATE_DATA_DIR/test-model.rvf" "$FERROCRATE_DATA_DIR/branch.rvf"
cargo run -q -p ferro-cli -- ai lineage "$FERROCRATE_DATA_DIR/branch.rvf" | grep "lineage_depth=1"

echo "Test 4: Export/import cycle..."
cargo run -q -p ferro-cli -- ai export --model-type resource-predictor --models-dir "$MODELS_DIR" --output "$FERROCRATE_DATA_DIR/export.rvf"
cargo run -q -p ferro-cli -- ai import --model-type resource-predictor --models-dir "$MODELS_DIR" --input "$FERROCRATE_DATA_DIR/export.rvf"

echo "All RVF integration tests passed."
