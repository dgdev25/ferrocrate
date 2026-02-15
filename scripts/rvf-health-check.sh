#!/usr/bin/env bash
set -euo pipefail

RUNTIME_DIR="${FERROCRATE_RUNTIME_DIR:-$HOME/.ferrocrate}"
MODEL_DIR="${1:-$RUNTIME_DIR/models-rvf}"
ROLLBACK_ON_FAIL="${ROLLBACK_ON_FAIL:-1}"
PARENT_MAP_FILE="${PARENT_MAP_FILE:-}"

if [[ ! -d "$MODEL_DIR" ]]; then
  echo "rvf-health: model dir not found: $MODEL_DIR"
  exit 0
fi

echo "rvf-health: checking models in $MODEL_DIR"
failed=0
checked=0

for rvf in "$MODEL_DIR"/*.rvf; do
  [[ -e "$rvf" ]] || continue
  checked=$((checked + 1))

  parent_args=()
  if [[ -n "$PARENT_MAP_FILE" && -f "$PARENT_MAP_FILE" ]]; then
    parent_file="$(awk -F',' -v f="$rvf" '$1==f{print $2}' "$PARENT_MAP_FILE" | head -n1)"
    if [[ -n "$parent_file" ]]; then
      parent_args=(--parent-file "$parent_file")
    fi
  fi

  if ferrocrate ai lineage "$rvf" --verify "${parent_args[@]}" --format text >/dev/null; then
    echo "rvf-health: ok $rvf"
  else
    echo "rvf-health: FAIL $rvf"
    failed=$((failed + 1))
  fi
done

echo "rvf-health: checked=$checked failed=$failed"

if [[ "$failed" -gt 0 ]]; then
  if [[ "$ROLLBACK_ON_FAIL" == "1" ]]; then
    echo "rvf-health: verification failed, switching ai.backend to legacy"
    FERROCRATE_RUNTIME_DIR="$RUNTIME_DIR" ferrocrate config set ai.backend legacy
  fi
  exit 1
fi

exit 0
