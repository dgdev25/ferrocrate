#!/usr/bin/env bash
set -euo pipefail

SOURCE_DIR="${1:-$HOME/.ferrocrate/models}"
TARGET_DIR="${2:-$HOME/.ferrocrate/models-rvf}"

echo "Migrating FerroCrate models to RVF"
echo "  source: $SOURCE_DIR"
echo "  target: $TARGET_DIR"

mkdir -p "$TARGET_DIR"

for model_type in resource-predictor anomaly-detector restart-policy; do
  model_dir="$SOURCE_DIR/$model_type"
  if [[ ! -d "$model_dir" ]]; then
    continue
  fi

  latest_model="$(ls -1 "$model_dir"/model_v*.bin 2>/dev/null | sort -V | tail -n 1 || true)"
  if [[ -z "$latest_model" ]]; then
    continue
  fi

  out="$TARGET_DIR/$model_type.rvf"
  echo "Exporting $model_type -> $out"
  ferrocrate ai export --model-type "$model_type" --output "$out"
done

echo "Verifying RVF artifacts..."
for rvf in "$TARGET_DIR"/*.rvf; do
  [[ -e "$rvf" ]] || continue
  ferrocrate ai stats "$rvf" --format text >/dev/null
  echo "  ok: $rvf"
done

echo "Migration complete."
