# Legacy Sled store retirement

FerroCrate's runtime stores are SQLite-backed: containers
(`ferro-core/src/sqlite_container_store.rs`), images, volumes, witness
journal, CRI delegation replay, and Compose fan-out replay. The optional
`legacy-sled-importers` (ferro-core) and `legacy-sled` (ferro-compose)
features and the `sled` dependency were removed on 2026-08-21 after the
migration window closed. The feature-gated importers were verified green
immediately before removal. The detailed qualification record is retained
outside the public repository.

Current contract for a legacy Sled data directory on disk:

- Every store that detects one (image `conf` marker, volume `volumes.db`,
  container `conf` marker, `witness.sled`, delegation replay `conf` marker,
  `compose-replay.db/conf`) fails closed with an actionable error that names
  this document. No store silently ignores, rewrites, or deletes legacy
  data. Users who still need Sled-era records must use a pre-removal build
  with the importer feature to export them.

Regression coverage:

```text
cargo test -p ferro-core --lib rejects_legacy
cargo test -p ferro-core --lib default_open_rejects_legacy_replay_directory
cargo test -p ferro-core --test witness_journal
cargo test -p ferro-compose
bash scripts/test-state-migrations.sh
```

`scripts/test-default-dependency-graph.sh` verifies that the default
`ferro-core` and `ferro-compose` graphs contain none of `sled`, `fxhash`,
or `instant`. Since the removal, no feature of either crate can reintroduce
Sled.
