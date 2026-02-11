# FerroCrate SPARC Documentation

**Version:** 1.0 | **Date:** February 11, 2026 | **Status:** Draft

---

## What is FerroCrate?

FerroCrate is an AI-native container runtime built in Rust that solves five critical problems:

1. **Resource Waste** - Docker consumes 120-180MB at idle; FerroCrate: 0MB
2. **Dumb Failure Handling** - Intelligent restart vs blind restart loops
3. **Dev/Prod Split** - Same runtime everywhere, no "works on my machine"
4. **No ML/AI Awareness** - Native GPU/VRAM management for AI workloads
5. **Edge Impracticality** - Sub-20MB runtime for constrained devices

---

## SPARC Phases

This documentation follows the SPARC methodology:

```
Specification -----> Pseudocode -----> Architecture -----> Refinement -----> Completion
     |                    |                  |                  |                  |
     v                    v                  v                  v                  v
   What & Why         How (Logic)      How (Structure)     TDD Implementation   Ship It
```

---

## Documentation Index

### 1. [Specification](./specification.md)
*What FerroCrate does and why*

**Contents:**
- Container lifecycle state machine
- Image management workflows
- Network topology constraints
- Security boundaries
- Entry/exit criteria for phase completion

**Key Sections:**
- State transitions (CREATED, RUNNING, PAUSED, STOPPED, RESTARTING, REMOVED)
- Intelligent restart protocol
- Content-addressable storage workflow
- eBPF packet forwarding architecture
- Six-layer security model

**Audience:** Product managers, architects, stakeholders

---

### 2. [Pseudocode](./pseudocode.md)
*How FerroCrate works logically*

**Contents:**
- Container creation flow algorithm
- Image layer deduplication algorithm
- Resource prediction algorithm (WASM neural inference)
- Intelligent restart logic
- eBPF packet routing pseudocode
- Complexity analysis

**Key Algorithms:**
```
create_container()      -> O(n) where n = layers
predict_resources()     -> O(1) fixed neural net size
intelligent_restart()   -> O(1) map lookups + AI inference
ferro_port_forward()    -> O(1) BPF map lookup
```

**Audience:** Developers, algorithm reviewers

---

### 3. [Architecture](./architecture.md)
*How FerroCrate is structured*

**Contents:**
- Component diagram (8 crates)
- Data flow between components
- Integration with claude-flow MCP
- Binary tiers (Minimal, Standard, Full)
- Directory structure

**Components:**
| Component | Responsibility |
|-----------|---------------|
| ferro-exec | Container runtime core |
| ferro-store | Image management, CAS |
| ferro-build | Dockerfile building |
| ferro-net | Networking, eBPF |
| ferro-mind | AI intelligence layer |
| ferro-compose | Multi-container orchestration |

**Audience:** System architects, integration engineers

---

### 4. [Refinement](./refinement.md)
*How FerroCrate is tested*

**Contents:**
- Test pyramid (Unit, Integration, E2E)
- Coverage targets per component
- Fuzzing strategy for unsafe code
- Test implementation order
- Performance benchmarks

**Coverage Targets:**
- ferro-exec: 85% line, 80% branch
- ferro-store: 80% line, 75% branch
- ferro-net: 80% line, 75% branch
- **Unsafe code: 100%** (no exceptions)

**Audience:** QA engineers, security auditors

---

### 5. [Completion](./completion.md)
*How FerroCrate is deployed*

**Contents:**
- Build system (Cargo workspace)
- Cross-compilation (x86_64, aarch64, riscv64)
- Release artifacts
- Installation methods (binary, package managers, cargo)
- Docker compatibility layer
- Migration from Docker

**Installation Options:**
```bash
# Quick install
curl -sL https://get.ferrocrate.dev | sh

# Homebrew
brew install ferrocrate

# Cargo
cargo install ferrocrate

# Arch Linux (AUR)
yay -S ferrocrate-bin
```

**Audience:** DevOps engineers, system administrators

---

## Quick Reference

### Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| Rust language | Memory safety, zero-cost abstractions |
| Blake3 hashing | 10x faster than SHA-256 for dedup |
| eBPF networking | Primary path; iptables/nftables fallback |
| WASM AI inference | 1-5ms, pluggable with native fallback |
| Rootless by default | Security first |

### Performance Targets

| Metric | Target |
|--------|--------|
| Container startup (cold) | < 100ms |
| Container startup (warm) | < 50ms |
| Idle memory (no daemon) | 0 MB |
| Per-container overhead | < 2 MB |
| Binary size (stripped) | < 15 MB |
| AI inference latency | 1-5ms (WASM) |

### Differentiation from Docker

| Feature | Docker | FerroCrate |
|---------|--------|------------|
| Language | Go | Rust |
| Idle memory | 120-180 MB | 0 MB |
| Restart logic | Blind retry | AI-driven diagnosis |
| Network | iptables | eBPF |
| Hashing | SHA-256 | Blake3 |
| AI features | None | WASM + optional LLM |
| Rootless | Optional | Default |

---

## Reading Order

### For Developers
1. Specification (understand requirements)
2. Pseudocode (understand algorithms)
3. Architecture (understand structure)
4. Refinement (understand testing)

### For DevOps
1. Specification (understand features)
2. Completion (understand deployment)
3. Architecture (understand components)

### For Architects
1. Specification (understand scope)
2. Architecture (understand design)
3. Pseudocode (review algorithms)

### For Security
1. Specification (security boundaries)
2. Refinement (testing strategy)
3. Architecture (component isolation)

---

## Phase Status

| Phase | Status | Exit Criteria |
|-------|--------|---------------|
| Specification | Complete | State machines validated |
| Pseudocode | Complete | Algorithms documented |
| Architecture | Complete | Components defined |
| Refinement | In Progress | Tests passing, coverage met |
| Completion | Pending | Release published |

---

## Contributing

When contributing to FerroCrate, follow the SPARC methodology:

1. **Specification**: Document the requirement
2. **Pseudocode**: Design the algorithm
3. **Architecture**: Identify affected components
4. **Refinement**: Write tests first (TDD)
5. **Completion**: Update deployment docs

---

## Related Documents

- [Product Requirements Document](../product-requirements.md) - Full PRD
- [Architecture Decision Records](./adr/) - Key decisions
- [API Documentation](./api/) - CLI and API reference
- [Contributing Guide](./CONTRIBUTING.md) - How to contribute

---

## Contact

- **GitHub:** https://github.com/ferrocrate/ferrocrate
- **Documentation:** https://docs.ferrocrate.dev
- **Community:** https://discord.gg/ferrocrate

---

*Generated by SPARC methodology - February 2026*
