# Legacy sled importer boundary

FerroCrate's Compose fan-out replay store is SQLite-backed at runtime. The
historical `compose-replay.db` sled format is supported only by the explicit
`ferro-compose` `legacy-sled` feature:

```text
cargo test -p ferro-compose
cargo test -p ferro-compose --features legacy-sled
cargo test -p ferro-core --features legacy-sled-importers image_store::tests
cargo test -p ferro-core --features legacy-sled-importers volume_store::tests
cargo test -p ferro-core --features legacy-sled-importers authorization::cri_delegation::tests
```

Default builds do not include sled in `ferro-compose`'s dependency graph. If a
legacy replay directory is present without the migration feature, opening the
store fails closed with an actionable error; it never silently ignores or
rewrites the old data. The feature-gated regression test verifies byte-level
replay migration, idempotent claim rejection, and the migration marker.

The same explicit boundary now applies to the ferro-core image and volume
importers through `legacy-sled-importers`. Default core opens fail closed when
they discover a legacy Sled directory; the opt-in feature runs the importer and
retains the rollback source. The active container store and witness compatibility
importers remain separate migration work and must not be considered complete
based on this boundary.
