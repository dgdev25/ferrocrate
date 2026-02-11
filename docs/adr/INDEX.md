# FerroCrate Architecture Decision Records (ADRs)

This directory contains Architecture Decision Records for the FerroCrate project.

## What is an ADR?

An Architecture Decision Record (ADR) captures a significant architectural decision along with its context and consequences. ADRs help future maintainers understand the "why" behind technical choices.

## Index

| ADR | Title | Status | Date |
|-----|-------|--------|------|
| [ADR-001](ADR-001-use-rust-as-primary-language.md) | Use Rust as Primary Language | Accepted | 2026-02-11 |
| [ADR-002](ADR-002-cgroups-v2-only.md) | cgroups v2 Only | Accepted | 2026-02-11 |
| [ADR-003](ADR-003-rootless-containers-by-default.md) | Rootless Containers by Default | Accepted | 2026-02-11 |
| [ADR-004](ADR-004-ebpf-for-networking.md) | eBPF for Networking | Amended | 2026-02-11 |
| [ADR-005](ADR-005-blake3-for-content-hashing.md) | Blake3 for Content Hashing | Accepted | 2026-02-11 |
| [ADR-006](ADR-006-zstd-compression.md) | Zstd Compression | Accepted | 2026-02-11 |
| [ADR-007](ADR-007-wasm-for-ai-inference.md) | WASM for AI Inference | Amended | 2026-02-11 |
| [ADR-008](ADR-008-oci-compliance.md) | OCI Compliance | Amended | 2026-02-11 |
| [ADR-009](ADR-009-no-daemon-mode-default.md) | No Daemon Mode Default | Accepted | 2026-02-11 |
| [ADR-010](ADR-010-overlayfs-as-storage-driver.md) | OverlayFS as Storage Driver | Accepted | 2026-02-11 |
| [ADR-011](ADR-011-claude-flow-as-subprocess.md) | claude-flow as Subprocess | Accepted | 2026-02-11 |
| [ADR-012](ADR-012-docker-socket-compatibility.md) | Docker Socket Compatibility | Amended | 2026-02-11 |
| [ADR-013](ADR-013-networking-fallback-strategy.md) | Networking Fallback Strategy | Accepted | 2026-02-11 |
| [ADR-014](ADR-014-crate-consolidation.md) | Crate Consolidation Strategy | Accepted | 2026-02-11 |
| [ADR-015](ADR-015-timeline-revision-and-mvp-scope.md) | Timeline Revision and MVP Scope | Accepted | 2026-02-11 |

## Status Definitions

| Status | Meaning |
|--------|---------|
| **Proposed** | Under discussion, not yet approved |
| **Accepted** | Approved and in effect |
| **Amended** | Previously accepted, refined per new consensus (AI consensus integration, Feb 2026) |
| **Deprecated** | Superseded by newer decision |
| **Superseded** | Replaced by ADR-XXX |

## ADR Format

Each ADR follows this structure:

1. **Title**: Brief description of the decision
2. **Status**: Current status (Proposed/Accepted/Deprecated/Superseded)
3. **Context**: Background and forces at play
4. **Decision**: The decision being made
5. **Consequences**: Impact of the decision (positive, negative, neutral)
6. **Alternatives Considered**: Other options evaluated
7. **References**: Related documents and resources

## Creating New ADRs

1. Copy the template from `TEMPLATE.md`
2. Number sequentially (ADR-013, ADR-014, etc.)
3. Use kebab-case for filename: `ADR-NNN-short-title.md`
4. Update this INDEX.md
5. Update `decisions.json`

## Kernel Requirements Summary

From these ADRs, the minimum kernel requirements are:

| Feature | Minimum Kernel | Recommended |
|---------|---------------|-------------|
| cgroups v2 | 4.5 | 5.10+ |
| eBPF networking | 4.18 | 5.10+ |
| OverlayFS (rootless) | 5.11 | 5.15+ |
| User namespaces | 3.8 | 4.3+ |

**FerroCrate Minimum: Linux kernel 5.10+**

## Dependency Summary

| Dependency | Purpose | Required |
|------------|---------|----------|
| Rust | Primary language | Yes |
| Linux kernel 5.10+ | OS platform (minimum; eBPF support) | Yes |
| Linux kernel 3.10+ | Fallback mode (iptables) | Yes |
| cgroups v2 | Resource management | Yes |
| OverlayFS | Storage driver | Yes |
| eBPF XDP/TC | Networking (primary) | Yes (5.10+) |
| iptables/nftables | Networking (explicit fallback) | Yes (fallback) |
| Wasmtime | WASM AI inference | Yes |
| Node.js | claude-flow (advanced AI) | Optional |

## Amended ADRs (Feb 11, 2026 - AI Consensus Integration)

The following ADRs were amended based on comprehensive AI consensus review:

| ADR | Original Decision | Amendment | Rationale |
|-----|------------------|-----------|-----------|
| ADR-004 | eBPF only, no iptables | eBPF primary + explicit iptables/nftables fallback via `--network-backend` | AI consensus recommended explicit fallback control (ADR-013) |
| ADR-007 | WASM <1ms latency | WASM 1-5ms latency with pluggable architecture | Realistic WASM performance targets; pluggable backend prevents lock-in |
| ADR-012 | Docker API 95% endpoint coverage | OCI-first primary; Docker API as optional translation layer | Industry standards alignment; long-term maintainability |
| (New) ADR-013 | N/A | Networking Fallback Strategy formalized | Explicit fallback control clarifies ambiguity in ADR-004 |
| (New) ADR-014 | N/A | Consolidate 8 crates to 5 core crates | AI consensus recommended for maintainability |
| (New) ADR-015 | 36-week timeline | 52-72 week timeline (12-18 months) | AI consensus recommended realistic delivery estimates |

## Related Documents

- [Product Requirements Document](../product-requirements.md)
- [C4 Architecture Diagrams](../architecture/) (to be created)
- [API Documentation](../api/) (to be created)
