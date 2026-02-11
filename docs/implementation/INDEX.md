# FerroCrate Implementation Index

**Version:** 1.0 | **Last Updated:** February 11, 2026

---

## 1. Executive Summary

FerroCrate is an AI-native container runtime built in Rust, designed to address the resource inefficiency, security vulnerabilities, and lack of intelligence in existing container runtimes. This implementation index provides a comprehensive roadmap for the v1.0 release.

### Key Differentiators
- **Zero idle memory** when no containers are running (vs Docker's 120-180MB)
- **Sub-100ms container startup** with intelligent resource prediction
- **Rootless by default** for enhanced security posture
- **AI-native architecture** with WASM-based inference for real-time decisions
- **Full OCI compliance** with Docker API compatibility layer

### Success Criteria (v1.0)
1. 80% functional parity with Docker CLI (covering 95% use cases)
2. All PERF-* requirements met and independently benchmarked
3. Zero critical CVEs in the runtime at launch
4. 10+ real-world Docker projects migrated successfully
5. 100+ beta testers with >7/10 satisfaction score

---

## 2. Architecture Overview

### 2.1 Component Diagram

```
+------------------------------------------------------------------+
|                        FerroCrate CLI                             |
|  +------------------------------------------------------------+  |
|  |                     Command Router                          |  |
|  |  run | build | pull | push | compose | migrate | ask      |  |
|  +------------------------------------------------------------+  |
+------------------------------------------------------------------+
           |                    |                    |
           v                    v                    v
+-------------------+  +-------------------+  +-------------------+
|    ferro-exec     |  |   ferro-store     |  |   ferro-mind      |
|  (Core Runtime)   |  | (Image Management)|  |  (AI Layer)       |
|                   |  |                   |  |                   |
| - Namespaces      |  | - OCI Client      |  | - WASM Inference  |
| - Cgroups v2      |  | - Blake3 Store    |  | - Pattern Router  |
| - Container Ops   |  | - OverlayFS       |  | - Anomaly Detect  |
| - Process Mgmt    |  | - Layer Dedup     |  | - Claude-Flow IPC |
+-------------------+  +-------------------+  +-------------------+
           |                    |                    |
           v                    v                    v
+-------------------+  +-------------------+  +-------------------+
|    ferro-net      |  |  ferro-build      |  |  ferro-compose    |
|  (Networking)     |  |  (Build System)   |  | (Orchestration)   |
|                   |  |                   |  |                   |
| - eBPF Programs   |  | - Dockerfile      |  | - Compose Parser  |
| - Bridge Networks |  | - ferrofile.toml  |  | - Service Graph   |
| - Port Forwarding |  | - Build Cache     |  | - Dependency Ord  |
| - DNS Resolution  |  | - Multi-stage     |  | - Scale/Profiles  |
+-------------------+  +-------------------+  +-------------------+
           |                    |                    |
           +--------------------+--------------------+
                                |
                                v
+------------------------------------------------------------------+
|                     Platform Layer (Linux)                        |
|  +------------+  +------------+  +------------+  +--------------+ |
|  | Namespaces |  | Cgroups v2 |  | OverlayFS  |  | eBPF         | |
|  | (pid,net,  |  | (unified   |  | (CoW       |  | (networking, | |
|  | mnt,ipc,   |  | hierarchy) |  | layers)    |  | monitoring)  | |
|  | uts,user)  |  |            |  |            |  |              | |
|  +------------+  +------------+  +------------+  +--------------+ |
+------------------------------------------------------------------+
                                |
                                v
+------------------------------------------------------------------+
|                    External Interfaces                            |
|  +------------------+  +------------------+  +------------------+ |
|  | OCI Registries   |  | Docker Socket    |  | Claude API       | |
|  | (Docker Hub,     |  | Compatibility    |  | (complex AI)     | |
|  | GHCR, ECR, GCR)  |  | (API v1.45+)     |  |                  | |
|  +------------------+  +------------------+  +------------------+ |
+------------------------------------------------------------------+
```

### 2.2 Crate Structure

| Crate | Purpose | Dependencies | Lines of Code (Est.) |
|-------|---------|--------------|---------------------|
| `ferro-exec` | Container execution (OCI runtime) | nix, caps, cgroups | ~8,000 |
| `ferro-store` | Image/storage management | oci-client, blake3, zstd | ~6,000 |
| `ferro-build` | Build system | ferro-store, dockerfile-parser | ~5,000 |
| `ferro-net` | Networking stack | aya (eBPF), smol | ~4,000 |
| `ferro-mind` | AI intelligence | wasmtime, tokio | ~3,000 |
| `ferro-compose` | Multi-container orchestration | all crates | ~4,000 |
| `ferro-mgr` | Optional management daemon | axum, tower | ~3,000 |
| `ferro-cli` | CLI binary (thin wrapper) | clap, all crates | ~2,000 |

**Total Estimated LOC:** ~35,000 lines of Rust

---

## 3. Milestone Summary

### Revised Implementation Timeline (52-72 Weeks / 12-18 Months)

**NOTE:** Original 36-week timeline has been revised to 12-18 months per AI consensus findings. Extended scope includes OCI conformance testing, networking fallbacks, GPU passthrough, and realistic WASM inference targets.

**Phase 1: MVP Foundation (Weeks 1-12)**
**Focus:** Core runtime (ferro-exec) + basic image management (ferro-store)
- Drop-in runc replacement for containers
- OCI Image Spec v1.1 compliance validation
- eBPF networking with iptables/nftables fallback

**Phase 2: Build + Compose (Weeks 13-24)**
**Focus:** Build system (ferro-build) + multi-container orchestration (ferro-compose)
- Dockerfile compatibility (95%+)
- docker-compose v3.x parsing
- CRI/K8s integration planning

**Phase 3: Intelligence Layer (Weeks 25-36)**
**Focus:** AI features (ferro-mind) with realistic latency targets
- WASM inference (1-5ms latency, pluggable architecture)
- Resource prediction models
- Anomaly detection

**Phase 4: Hardening + Docker Compat (Weeks 37-48)**
**Focus:** Security audit + optional Docker socket layer
- Security audit for unsafe blocks
- Docker API emulation (optional, not default)
- GPU/VRAM management for AI workloads

**Phase 5: CRI/K8s Integration (Weeks 49-60)**
**Focus:** Kubernetes-native operations
- CRI v1 shim (ferro-cri)
- containerd/CRI-O interoperability

**Phase 6: Production Release (Weeks 61-72)**
**Focus:** Release preparation and adoption support
- Full OCI conformance suite
- Migration tooling
- Community validation

---

### Original M0-M3 Milestone Structure (for reference)

Note: The following milestone structure has been superseded by the 6-phase plan above. Maintained for historical reference only.

**M0: Foundation (Weeks 1-4)**
**Focus:** Core runtime and container lifecycle

| Deliverable | Description | Status |
|-------------|-------------|--------|
| ferro-exec crate | Namespace/cgroup management | Not Started |
| Container create/start/stop | Basic lifecycle operations | Not Started |
| Rootless container support | User namespace mapping | Not Started |
| OCI runtime compliance | config.json bundle execution | Not Started |
| CLI skeleton | Command parsing with clap | Not Started |

**Exit Criteria:**
- Run a basic Alpine container rootless
- cgroups v2 resource limits enforced
- 100% OCI Runtime Spec compliance for basic operations

### Phase 2: ferro-store + ferro-cli (Weeks 7-14)
**Focus:** Image management and storage
**Focus:** Image management and storage

| Deliverable | Description | Status |
|-------------|-------------|--------|
| ferro-store crate | Content-addressable storage | Not Started |
| OCI registry client | Pull/push from registries | Not Started |
| Blake3 content hashing | Fast deduplication | Not Started |
| Zstd layer compression | Compressed layer handling | Not Started |
| OverlayFS integration | Layer stacking and CoW | Not Started |
| Image build (basic) | Dockerfile parsing | Not Started |

**Exit Criteria:**
- Pull image from Docker Hub
- Run pulled image as container
- File-level deduplication working
- Basic Dockerfile build succeeds

### Phase 3: ferro-build + ferro-compose (Weeks 15-20)
**Focus:** Build system and orchestration
**Focus:** Networking and CLI completeness

| Deliverable | Description | Status |
|-------------|-------------|--------|
| ferro-net crate | eBPF-based networking | Not Started |
| Bridge networking | Container network isolation | Not Started |
| Port forwarding | Host-to-container port mapping | Not Started |
| DNS resolution | Container name resolution | Not Started |
| Docker API server | Socket compatibility layer | Not Started |
| CLI completion | All core commands implemented | Not Started |

**Exit Criteria:**
- Multi-container networking works
- Docker CLI commands work against ferrocrate socket
- Port mapping functional
- VS Code Dev Containers compatible

### Phase 4: ferro-net (Weeks 21-24)
**Focus:** Container networking
**Focus:** Compose and AI features

| Deliverable | Description | Status |
|-------------|-------------|--------|
| ferro-compose crate | docker-compose.yml support | Not Started |
| ferro-mind crate | WASM inference engine | Not Started |
| Resource prediction | Memory/CPU prediction | Not Started |
| Anomaly detection | Container behavior analysis | Not Started |
| claude-flow integration | Multi-agent orchestration | Not Started |
| Migration tool | Docker-to-FerroCrate migration | Not Started |

**Exit Criteria:**
- docker-compose up works with common compose files
- AI features provide measurable value (resource savings)
- Migration tool successfully migrates Docker projects

---

## 4. Epic Summary

### EPIC-01: Runtime Core
**Milestone:** M0 | **Tasks:** 6 | **Story Points:** 34

Container lifecycle management from creation to termination. Foundation for all container operations.

**Key Requirements:**
- CLM-01 through CLM-10 (Container Lifecycle Management)
- SEC-01, SEC-04, SEC-06 (Rootless security)

**Deliverables:**
- ferro-exec crate with full lifecycle support
- OCI Runtime Spec v1.2 compliance
- cgroups v2 resource management
- User namespace isolation

### EPIC-02: Performance
**Milestone:** M1, M2 | **Tasks:** 5 | **Story Points:** 28

Achieving performance targets that differentiate FerroCrate from Docker.

**Key Requirements:**
- PERF-01 through PERF-08
- IMG-03, IMG-04, IMG-05

**Deliverables:**
- Sub-100ms container startup
- Zero idle memory consumption
- 500 MB/s image pull throughput
- 10x faster hashing with Blake3

### EPIC-03: Intelligence
**Milestone:** M3 | **Tasks:** 6 | **Story Points:** 32

AI-native features including prediction, anomaly detection, and intelligent remediation.

**Key Requirements:**
- AI-01 through AI-12

**Deliverables:**
- WASM inference engine (1-5ms latency, pluggable with native fallback)
- Resource prediction models
- Anomaly detection and alerting
- Claude-Flow integration for complex analysis

### EPIC-04: Migration
**Milestone:** M2, M3 | **Tasks:** 5 | **Story Points:** 26

Docker compatibility to minimize migration friction.

**Key Requirements:**
- COMPAT-01 through COMPAT-09
- CLI-01, CLI-02, CLI-06

**Deliverables:**
- Docker CLI syntax compatibility
- Docker socket API emulation
- Migration tool for existing deployments
- 95% Dockerfile directive support

### EPIC-05: Orchestration
**Milestone:** M3 | **Tasks:** 4 | **Story Points:** 22

Multi-container coordination and deployment.

**Key Requirements:**
- CMP-01 through CMP-07
- NET-01 through NET-10

**Deliverables:**
- docker-compose.yml v3.x support
- Service dependency ordering
- Network management
- Volume orchestration

---

## 5. Dependency Graph

```
                    [ferrocrate CLI]
                          |
         +----------------+----------------+
         |                |                |
         v                v                v
   [ferro-exec]    [ferro-store]    [ferro-compose]
         |                |                |
         |                v                |
         |         [ferro-build]           |
         |                |                |
         +--------+-------+--------+-------+
                  |                |
                  v                v
            [ferro-net]      [ferro-mind]
                  |                |
                  +--------+-------+
                           |
                           v
                    [ferro-mgr]
                  (Daemon Mode)
```

### Build Order (Topological Sort)

```
Phase 1 (No internal deps):
  - ferro-exec (core runtime)
  - ferro-net (networking)
  - ferro-mind (AI layer)

Phase 2 (Depends on Phase 1):
  - ferro-store (depends on ferro-exec for builds)
  - ferro-build (depends on ferro-store)

Phase 3 (Depends on Phase 2):
  - ferro-compose (depends on all above)
  - ferro-mgr (depends on all above)

Phase 4 (Integration):
  - ferrocrate CLI (integrates all crates)
```

### External Dependencies

| Dependency | Version | Purpose | Crate Using |
|------------|---------|---------|-------------|
| nix | 0.27 | Syscall wrappers | ferro-exec |
| caps | 0.5 | Linux capabilities | ferro-exec |
| cgroups-rs | 0.3 | cgroup management | ferro-exec |
| oci-client | 0.9 | OCI registry client | ferro-store |
| blake3 | 1.5 | Fast hashing | ferro-store |
| zstd | 0.13 | Compression | ferro-store |
| aya | 0.11 | eBPF programs | ferro-net |
| wasmtime | 19.0 | WASM runtime | ferro-mind |
| axum | 0.7 | HTTP server | ferro-mgr |
| clap | 4.4 | CLI parsing | ferrocrate |

---

## 6. Progress Tracking

### Overall Progress

| Phase | Milestone | Progress | Tasks Done | Tasks Total |
|-------|-----------|----------|------------|-------------|
| Foundation | M0 | 0% | 0 | 6 |
| Data Access | M1 | 0% | 0 | 5 |
| API Layer | M2 | 0% | 0 | 5 |
| Integration | M3 | 0% | 0 | 6 |
| **Total** | | **0%** | **0** | **22** |

### Quality Gates

Each milestone passes through a 7-step quality gate:

1. **Code Complete** - All tasks finished, no TODOs
2. **Unit Tests** - >80% line coverage, 100% unsafe coverage
3. **Integration Tests** - All PRD requirements tested
4. **Performance Tests** - All PERF-* targets met
5. **Security Audit** - cargo-audit clean, fuzzing complete
6. **Documentation** - API docs, README, examples
7. **Review Sign-off** - Code review, architecture review

### Risk Register

| Risk | Probability | Impact | Mitigation | Owner |
|------|-------------|--------|------------|-------|
| eBPF kernel compatibility | Medium | High | iptables fallback | ferro-net |
| Rootless OverlayFS perf | Medium | Medium | FUSE fallback | ferro-exec |
| Docker API edge cases | High | Medium | Document gaps | ferro-mgr |
| WASM inference accuracy | Low | Low | Tuning, fallback | ferro-mind |
| claude-flow version drift | Medium | Low | Version pinning | ferro-mind |

---

## 7. File Reference

### Implementation Documents

| Document | Path | Description |
|----------|------|-------------|
| Task Registry | [tasks.json](./tasks.json) | Complete task database |
| M0 Breakdown | [milestones/M0-foundation.md](./milestones/M0-foundation.md) | Foundation milestone |
| M1 Breakdown | [milestones/M1-data-access.md](./milestones/M1-data-access.md) | Data access milestone |
| M2 Breakdown | [milestones/M2-api-layer.md](./milestones/M2-api-layer.md) | API layer milestone |
| M3 Breakdown | [milestones/M3-integration.md](./milestones/M3-integration.md) | Integration milestone |

### Epic Documents

| Document | Path | Description |
|----------|------|-------------|
| EPIC-01 | [epics/EPIC-01-runtime-core.md](./epics/EPIC-01-runtime-core.md) | Container lifecycle |
| EPIC-02 | [epics/EPIC-02-performance.md](./epics/EPIC-02-performance.md) | Performance optimization |
| EPIC-03 | [epics/EPIC-03-intelligence.md](./epics/EPIC-03-intelligence.md) | AI/ML features |
| EPIC-04 | [epics/EPIC-04-migration.md](./epics/EPIC-04-migration.md) | Docker compatibility |
| EPIC-05 | [epics/EPIC-05-orchestration.md](./epics/EPIC-05-orchestration.md) | Multi-agent features |

### Related Documents

| Document | Path | Description |
|----------|------|-------------|
| Product Requirements | [../product-requirements.md](../product-requirements.md) | PRD v1.0 |
| ADR Index | [../adr/INDEX.md](../adr/INDEX.md) | Architecture decisions |
| ADR-001 to ADR-012 | [../adr/](../adr/) | Individual ADRs |

---

## 8. Quick Reference

### Key Performance Targets

| Metric | Target | Measurement |
|--------|--------|-------------|
| Container startup | <100ms cold, <50ms warm | Time to process running |
| Idle memory | 0 MB | RSS with no containers |
| Image pull | >500 MB/s | On 1Gbps link |
| AI inference | 1-5 ms (WASM) | WASM decision latency |
| Binary size | ~5 MB (minimal), ~12 MB (standard), ~18 MB (full), ~45 MB (full+agents) | Static stripped binary |

### Minimum Requirements

| Requirement | Version |
|-------------|---------|
| Linux kernel | 5.10+ (5.15+ recommended) |
| cgroups | v2 only |
| Rust | 1.75+ |
| Node.js | 18+ (optional, for advanced AI) |

### CLI Commands (Target Parity)

```bash
# Container operations
ferrocrate run -d alpine
ferrocrate ps
ferrocrate logs <container>
ferrocrate exec -it <container> sh
ferrocrate stop <container>
ferrocrate rm <container>

# Image operations
ferrocrate pull ubuntu:22.04
ferrocrate build -t myapp .
ferrocrate images
ferrocrate push myapp:latest

# Orchestration
ferrocrate compose up -d
ferrocrate compose down

# AI features
ferrocrate ask "why did my container crash?"
ferrocrate predict --memory web-server
```

---

## 9. Contributing

### Development Workflow

1. Pick a task from [tasks.json](./tasks.json)
2. Create feature branch: `feat/TASK-XXX-description`
3. Implement with tests (TDD preferred)
4. Run quality gate checklist
5. Submit PR with task reference

### Branch Naming

- `feat/TASK-XXX-description` - New features
- `fix/TASK-XXX-description` - Bug fixes
- `docs/TASK-XXX-description` - Documentation
- `test/TASK-XXX-description` - Test improvements

### Commit Format

```
TASK-XXX: Brief description

Detailed explanation of changes.

Refs: #issue-number
```

---

*This index is the single source of truth for implementation planning. Update it as milestones progress.*
