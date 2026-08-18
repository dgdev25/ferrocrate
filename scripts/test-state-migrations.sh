#!/usr/bin/env bash
set -euo pipefail

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/.." && pwd)}"
target_dir="${FERROCRATE_STATE_MIGRATION_TARGET:-$repo_root/target/state-migration}"
cd "$repo_root"

run_case() {
  local label="$1"
  shift
  printf '[state-migration] %s\n' "$label"
  CARGO_TARGET_DIR="$target_dir" cargo test "$@" --offline
}

# These are the compatibility-window fixtures: every legacy importer must
# preserve records, publish its readiness marker atomically, and remain
# idempotent. Keep the feature explicit so the default runtime graph stays
# Sled-free while migration support remains testable.
run_case "image and volume sled importers" \
  -p ferro-core --features legacy-sled-importers --lib migrates_legacy_sled
run_case "container SQLite snapshot import and conflict refusal" \
  -p ferro-core --features legacy-sled-importers --lib imports_sqlite_snapshot
run_case "witness journal SQLite readiness migration" \
  -p ferro-core --features legacy-sled-importers --lib sqlite_store_migrates_legacy_trees
run_case "delegation replay SQLite migration" \
  -p ferro-core --features legacy-sled-importers --lib legacy_replay_keys_migrate_idempotently

echo "state migration regression gate passed (image, volume, container, witness, delegation)"
