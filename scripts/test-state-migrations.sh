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

# The Sled compatibility importers were removed (2026-08-21). These fixtures
# pin the remaining contract: every store that can find a legacy Sled
# directory on disk must fail closed with an actionable error, must not
# rewrite or delete the legacy data, and fresh opens must stay Sled-free.
run_case "image, volume, and container legacy boundaries fail closed" \
  -p ferro-core --lib rejects_legacy
run_case "witness journal legacy boundary fails closed" \
  -p ferro-core --lib witness_open_rejects_legacy_directory_by_default
run_case "witness journal fresh opens stay Sled-free" \
  -p ferro-core --test witness_journal fresh_journal_uses_sqlite_without_creating_a_runtime_sled_store
run_case "witness journal integration legacy boundary" \
  -p ferro-core --test witness_journal rejects_legacy_storage_directory_at_open
run_case "delegation replay legacy boundary fails closed" \
  -p ferro-core --lib default_open_rejects_legacy_replay_directory
run_case "compose replay legacy boundary fails closed" \
  -p ferro-compose --lib legacy_compose_replay_requires_explicit_migration_feature

echo "state migration regression gate passed (legacy boundaries fail closed; fresh opens Sled-free)"
