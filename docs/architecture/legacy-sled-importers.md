# Legacy sled importer boundary

FerroCrate's Compose fan-out replay store is SQLite-backed at runtime. The
historical `compose-replay.db` sled format is supported only by the explicit
`ferro-compose` `legacy-sled` feature:

```text
cargo test -p ferro-compose
cargo test -p ferro-compose --features legacy-sled
```

Default builds do not include sled in `ferro-compose`'s dependency graph. If a
legacy replay directory is present without the migration feature, opening the
store fails closed with an actionable error; it never silently ignores or
rewrites the old data. The feature-gated regression test verifies byte-level
replay migration, idempotent claim rejection, and the migration marker.

This boundary is one step in removing the remaining sled advisories. The
container, image, volume, CRI delegation, and witness compatibility importers
remain separate migration work and must not be considered complete based on
this Compose-only change.
