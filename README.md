# FerroCrate

AI-native container runtime written in Rust. Phase 1 focuses on core runtime primitives, image handling, storage, and a CLI surface.

## Status

Phase 1 foundations are in progress. CLI commands are wired with validation stubs and will be connected to runtime execution as the next step.

## Quick Start (Current)

```bash
# CLI surface
cargo run -p ferro-cli -- images
cargo run -p ferro-cli -- containers
cargo run -p ferro-cli -- run alpine:latest echo hello
cargo run -p ferro-cli -- build ./Dockerfile -t acme/app:dev
cargo run -p ferro-cli -- pull ghcr.io/acme/app:latest
cargo run -p ferro-cli -- push ghcr.io/acme/app:latest
```

## Development

```bash
# Run all tests
scripts/run-tests.sh
```

## Documentation

- Roadmap: `docs/ROADMAP.md`
- Security: `SECURITY.md`
- Architecture/PRD: `docs/product-requirements.md`
