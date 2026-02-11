# ADR-014: Crate Consolidation Strategy

## Status

**Accepted** (February 11, 2026 - Consolidate 8 crates to 5 core crates per AI consensus on maintainability)

## Context

The initial architecture proposed 8 separate Rust crates for FerroCrate:

1. **ferro-runtime** - Container runtime (OCI Runtime Spec v1.2)
2. **ferro-image** - Image management (OCI Image Spec v1.1)
3. **ferro-net** - Networking (eBPF + iptables/nftables)
4. **ferro-store** - Storage driver (OverlayFS)
5. **ferro-mind** - AI inference (WASM tier + fallback)
6. **ferro-compose** - Compose orchestration (docker-compose compatibility)
7. **ferro-cri** - Kubernetes CRI shim (Phase 2)
8. **ferro-cli** - CLI and main binary

**Problems with 8-Crate Model:**
- High maintenance burden for coordinating changes across crates
- Deep coupling between ferro-runtime, ferro-net, ferro-store (all manage containers)
- Difficult to version (when to bump which crates?)
- Users confused about which crate to depend on
- Each crate has separate test suite (redundancy)

**AI Consensus Recommendation:**
All 4 models agreed: Consolidate to 5 core crates with clear separation:
- ferro-core (runtime + images + storage)
- ferro-net (eBPF + fallback)
- ferro-mind (AI inference)
- ferro-compose (optional orchestration)
- ferro-cli (CLI + main)

## Decision

**Consolidate from 8 crates to 5 core crates. Group related functionality into cohesive modules.**

### Crate Structure

**1. ferro-core** (4 modules, ~2000 LOC)
- `runtime`: OCI Runtime Spec v1.2 implementation (containers, processes)
- `image`: OCI Image Spec v1.1 (manifest, layers, pull/push)
- `storage`: OverlayFS integration (rootfs mounting, layer management)
- `registry`: OCI Distribution Spec v1.1 (registry client, authentication)

**2. ferro-net** (2 modules, ~1500 LOC)
- `ebpf`: XDP/TC-based container networking
- `fallback`: iptables/nftables backend for older kernels

**3. ferro-mind** (3 modules, ~1000 LOC)
- `wasm`: Wasmtime runtime for AI inference
- `models`: Pre-trained neural networks (resource prediction, anomaly detection)
- `api`: Trait-based interface for backend selection

**4. ferro-compose** (2 modules, ~800 LOC - PHASE 2)
- `parser`: docker-compose.yml parsing and validation
- `orchestrator`: Multi-container lifecycle management

**5. ferro-cli** (2 modules, ~500 LOC)
- `main`: CLI entry point, argument parsing
- `commands`: Implementation of run, build, pull, push, etc.

### Module Dependencies

```
ferro-cli
├── ferro-core
│   ├── ferro-net
│   └── storage
├── ferro-compose
└── ferro-mind
```

**Clear dependency rules:**
- ferro-cli depends on all others
- ferro-compose depends on ferro-core
- ferro-core depends on ferro-net and storage
- ferro-mind is optional/pluggable (no dependencies on others)

### Single Workspace

```toml
# Cargo.toml (workspace root)
[workspace]
members = ["ferro-core", "ferro-net", "ferro-mind", "ferro-compose", "ferro-cli"]

[workspace.dependencies]
tokio = "1.35"
serde = "1.0"
anyhow = "1.0"
```

### Shared Dependencies

All crates share workspace dependencies; no version conflicts.

## Consequences

### Positive

- **Simpler maintenance**: 5 crates vs 8; easier to coordinate changes
- **Clearer dependencies**: Dependency graph is obvious (no circular deps)
- **Unified versioning**: Single version number (1.0.0) incremented together
- **Reduced testing duplication**: Shared integration tests in ferro-core
- **Easier documentation**: One API surface per crate vs 8 separate APIs
- **Better onboarding**: Contributors understand the structure quickly
- **Shared workspace**: `cargo workspace` commands simplify builds

### Negative

- **Larger crates**: ferro-core is ~2000 LOC (still under 500-line guideline per module)
- **Less modularity**: Cannot depend on just ferro-image without ferro-runtime
- **Breaking changes**: Changes to ferro-core affect all downstream

### Neutral

- **Semver strategy**: Must release all crates together; careful versioning needed

## Alternatives Considered

### Keep 8 Crates

**Pros:**
- Maximum modularity
- Users can depend on just ferro-image (hypothetically)

**Cons:**
- Maintenance nightmare (verified by consensus models)
- Version coordination complex
- Not worth the complexity cost

**Decision**: Rejected. 5 crates provides better balance.

### Monolithic Single Crate

**Pros:**
- Simplest version management
- Smallest API surface

**Cons:**
- ~6000 LOC in one crate (violates 500-line guideline)
- Harder to test subsystems independently
- Users forced to depend on everything

**Decision**: Rejected. 5 crates is optimal middle ground.

## Implementation Notes

**Cargo Workspace Structure:**
```bash
ferrocrate/
├── Cargo.toml (workspace definition)
├── Cargo.lock (shared for workspace)
├── ferro-core/
│   ├── Cargo.toml
│   ├── src/
│   │   ├── lib.rs
│   │   ├── runtime/
│   │   ├── image/
│   │   ├── storage/
│   │   └── registry/
│   └── tests/
├── ferro-net/
├── ferro-mind/
├── ferro-compose/
└── ferro-cli/
```

**Unified Documentation:**
```markdown
# FerroCrate Crate Guide

- **ferro-core**: Container runtime, image management, storage
- **ferro-net**: eBPF and iptables/nftables networking backends
- **ferro-mind**: AI inference with pluggable backends (WASM default)
- **ferro-compose**: Multi-container orchestration (optional, Phase 2)
- **ferro-cli**: Command-line interface and entry point
```

**Publishing to crates.io:**
```bash
# All published together
cargo publish --allow-dirty -p ferro-core
cargo publish --allow-dirty -p ferro-net
cargo publish --allow-dirty -p ferro-mind
cargo publish --allow-dirty -p ferro-compose
cargo publish --allow-dirty -p ferro-cli
```

**Version Management:**
- Bump minor version for any breaking change across workspace
- All crates released simultaneously at same version
- Example: v1.0.0 → v1.1.0 (all crates)

## Migration Path

**From 8 Crates to 5:**
1. Move ferro-runtime, ferro-image, ferro-store into ferro-core module structure
2. Create workspace with unified Cargo.toml
3. Consolidate tests
4. Update documentation
5. Release as v1.0.0 (or new major version)

## References

- [Cargo Workspaces](https://doc.rust-lang.org/cargo/reference/workspaces.html)
- [Semantic Versioning](https://semver.org/)
- Consensus Model Agreement: All 4 models recommended consolidation for long-term maintainability
- PRD Requirements: MNT-01, MNT-02, ENG-01
