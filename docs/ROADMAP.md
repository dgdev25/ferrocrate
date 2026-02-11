# FerroCrate Development Roadmap

**Timeline**: 52-72 weeks (12-18 months) | **Status**: Planning Phase
**Version Target**: v1.0.0 Production Release

---

## Overview

This roadmap breaks down the FerroCrate implementation into 6 sequential phases with clear dependencies. Use strikethrough (`~~text~~`) to mark tasks as completed.

### Phase Structure (Updated Order)
- **Phase 1**: Foundation (Weeks 1-10) - Core runtime, image, storage
- **Phase 2**: CLI Wiring & E2E (Weeks 6-12) - Wire CLI to runtime, end-to-end tests
- **Phase 3**: Networking (Weeks 11-20) - eBPF primary, fallback backends
- **Phase 4**: Compose (Weeks 12-20) - Multi-container orchestration
- **Phase 5**: AI Layer (Weeks 11-18) - WASM inference, Tier 1 models
- **Phase 6**: Hardening & Production (Weeks 21-70, ongoing) - Performance, security, edge cases
- **Phase 7**: Kubernetes Integration (Weeks 21-32) - CRI shim, kubelet compatibility
- **Phase 8**: Documentation (Final) - Full docs after behavior stabilizes

### Deliverables by Phase (Updated Order)
- **Week 10**: Core runtime + image + storage foundations complete
- **Week 18**: MVP Ready (v0.3.0) - Full MVP with AI and networking
- **Week 32**: Kubernetes Ready (v0.5.0) - CRI integration complete
- **Week 52-72**: Production Ready (v1.0.0) - Full feature set, hardened, docs finalized

### Preferred Development Order (Updated)
1. Runtime core (namespaces, cgroups, rootless, lifecycle, rootfs)
2. Storage + image plumbing (layers, registry, tagging)
3. CLI wired to runtime + E2E tests
4. Networking (bridge/host/none, DNS, port mapping, fallback)
5. Compose (if needed before AI)
6. AI layer
7. Hardening & production readiness
8. Kubernetes integration
9. Documentation (last)

---
## PHASE 1: Foundation (Weeks 1-10)

### Runtime Implementation (OCI Runtime Spec v1.2)

- [x] ~~Set up Rust project structure with 5-crate workspace (ferro-core, ferro-net, ferro-mind, ferro-compose, ferro-cli)~~
- [x] ~~Implement OCI Runtime Spec v1.2 config.json parser~~
- [x] ~~Implement Linux namespace creation (pid, network, ipc, uts, mount)~~
- [x] ~~Implement cgroups v2 integration for resource limits (memory, cpu, pids)~~
- [x] ~~Implement rootless container execution via user namespaces~~
- [x] ~~Implement process lifecycle management (start, stop, pause, resume)~~
- [x] ~~Implement container exec functionality~~
- [x] ~~Create integration tests for basic container lifecycle~~

### Image Management (OCI Image Spec v1.1)

- [x] ~~Implement OCI Image Spec v1.1 manifest parsing (application/vnd.oci.image.manifest.v1+json)~~
- [x] ~~Implement layer extraction and rootfs construction~~
- [x] ~~Implement zstd and gzip decompression for layer tarballs~~
- [x] ~~Implement image pull from OCI registries (basic auth)~~
- [x] ~~Implement image push to OCI registries~~
- [x] ~~Implement local image storage (index database)~~
- [x] ~~Implement image tagging and reference resolution~~
- [x] ~~Create integration tests for image operations~~

### Storage Driver (OverlayFS)

- [x] ~~Implement OverlayFS mount for rootless containers (kernel 5.11+)~~
- [x] ~~Implement FUSE fallback for older kernels~~
- [x] ~~Implement layer mounting and merging~~
- [x] ~~Implement container rootfs preparation~~
- [x] ~~Implement mount cleanup on container exit~~
- [x] ~~Create integration tests for storage operations~~

### CLI Foundation (ferro-cli)

- [x] ~~Implement argument parsing infrastructure (clap or similar)~~
- [x] ~~Implement `ferrocrate run <image> [cmd]` command~~
- [x] ~~Implement `ferrocrate build <dockerfile> -t <tag>` command~~
- [x] ~~Implement `ferrocrate images` command~~
- [x] ~~Implement `ferrocrate containers` command~~
- [x] ~~Implement `ferrocrate logs <container>` command~~
- [x] ~~Implement `ferrocrate exec <container> <cmd>` command~~
- [x] ~~Implement `ferrocrate pull <image>` command~~
- [x] ~~Implement `ferrocrate push <image>` command~~
- [x] ~~Create CLI integration tests~~

### Security Baseline (Phase 1)

- [x] ~~Verify rootless container isolation (user namespace, capability dropping)~~
- [x] ~~Implement seccomp profile defaults~~
- [x] ~~Implement AppArmor/SELinux profile generation~~
- [x] ~~Run initial security audit on codebase~~
- [x] ~~Create SECURITY.md with vulnerability reporting procedure~~

### Testing Infrastructure (Phase 1)

- [x] ~~Set up test infrastructure with integration test harness~~
- [x] ~~Create test fixture for OCI container images~~
- [x] ~~Implement container lifecycle tests (create, start, stop, remove)~~
- [x] ~~Implement image operation tests (pull, push, tag)~~
- [x] ~~Implement rootless isolation tests~~
- [x] ~~Set up CI pipeline for test execution~~

### Phase 1 Milestone: MVP v0.1.0

**Deliverable**: Can run simple OCI containers rootlessly via CLI

- [x] ~~Merge all Phase 1 code~~
- [x] ~~Create v0.1.0 release tag~~
- [x] ~~Document basic usage in README~~
- [x] ~~Publish initial documentation~~

---

## PHASE 1: Foundation (Weeks 1-10)

### Runtime Implementation (OCI Runtime Spec v1.2)

- [x] ~~Set up Rust project structure with 5-crate workspace~~
- [x] ~~Implement OCI Runtime Spec v1.2 config.json parser~~
- [ ] Implement Linux namespace creation (pid, network, ipc, uts, mount)
```

---

## Notes for External Development Teams

### Getting Started

1. Clone the repository: `git clone <repo>`
2. Read `/docs/development/CONTRIBUTING.md` for development setup
3. Review Phase 1 tasks to understand the foundation
4. Each task should have a corresponding issue/PR in GitHub

### Dependencies

- **Phase 1** blocks all other phases (foundation requirement)
- **Phase 2** can run in parallel with Phase 1 (weeks 5-10 overlap)
- **Phase 3 & 4** can run in parallel (both depend only on Phase 1)
- **Phase 5** depends on Phases 1-4 complete
- **Phase 6** runs for entire project duration (weeks 21-70)

### Communication

- Use GitHub Issues for task status updates
- Use GitHub Projects board for visual progress tracking
- Weekly standup recommended for Phase 1 critical path
- Bi-weekly standups for Phases 3-6

### Quality Gates

Each phase must complete with:
- ✅ All tasks marked complete
- ✅ All integration tests passing
- ✅ Code review approved
- ✅ Documentation updated
- ✅ Security baseline met for that phase

---

## Version Milestones

| Version | Weeks | Phases Complete | Deliverable |
|---------|-------|-----------------|-------------|
| v0.1.0 | 10 | 1 | Basic container runtime |
| v0.3.0 | 18 | 1-3 | MVP with AI inference |
| v0.5.0 | 32 | 1-5 | Kubernetes CRI ready |
| v1.0.0 | 52-72 | 1-6 | Production ready |

---

**Last Updated**: February 11, 2026
**Maintained By**: FerroCrate Development Team
## PHASE 2: CLI Wiring & E2E (Weeks 6-12)

### CLI Runtime Wiring

- [x] ~~Wire `ferrocrate run` to runtime execution~~
- [x] ~~Wire `ferrocrate exec` to namespace entry~~
- [x] ~~Wire `ferrocrate logs` to container log stream~~
- [x] ~~Wire `ferrocrate images/containers` to local stores~~

### End-to-End Testing

- [x] ~~Add E2E tests for `run` and `exec`~~
- [x] ~~Add E2E tests for image pull/build/push~~
- [x] ~~Add E2E tests for container lifecycle and cleanup~~

---

## PHASE 3: Networking (Weeks 11-20)

### eBPF Primary Backend

- [ ] Implement XDP (eXpress Data Path) program loading
- [ ] Implement TC (Traffic Control) hook attachment
- [ ] Implement container network namespace isolation
- [ ] Implement veth pair creation and attachment to eBPF programs
- [ ] Implement eBPF map management (connection tracking, rules)
- [ ] Implement packet filtering and forwarding rules
- [ ] Create eBPF program tests (isolated, unit-testable)
- [ ] Create integration tests (containers with eBPF networking)

### Networking Configuration

- [ ] Implement network namespace setup for containers
- [ ] Implement DNS configuration from host
- [ ] Implement port mapping (container → host)
- [ ] Implement bridge network support (container-to-container)
- [ ] Implement host network mode option (--network=host)
- [ ] Implement none network mode option (--network=none)
- [ ] Create network configuration tests

### iptables Fallback Backend

- [ ] Implement iptables rule generation for legacy systems
- [ ] Implement explicit `--network-backend=iptables` flag
- [ ] Implement iptables rule cleanup on container exit
- [ ] Create iptables compatibility tests
- [ ] Test on kernels 3.10+ (minimum support)

### nftables Alternative Backend

- [ ] Implement nftables rule generation
- [ ] Implement explicit `--network-backend=nftables` flag
- [ ] Implement nftables rule cleanup on container exit
- [ ] Create nftables compatibility tests
- [ ] Test on kernels 3.13+ (minimum support)

### Network Integration with Rootless

- [ ] Implement network setup in rootless context
- [ ] Test eBPF with user namespaces
- [ ] Test iptables/nftables with user namespaces
- [ ] Create rootless networking edge case tests

### Networking Observability

- [ ] Implement network metrics collection (bytes in/out, packets)
- [ ] Implement connection tracking logs
- [ ] Create networking troubleshooting guide

### Phase 4 Milestone: Multi-Backend Networking

**Deliverable**: eBPF primary with explicit fallback to iptables/nftables

- [ ] Merge all Phase 4 code
- [ ] eBPF backend tested on Linux 5.10+
- [ ] iptables fallback tested on Linux 3.10+
- [ ] nftables alternative tested on Linux 3.13+
- [ ] Network integration tests passing

---
## PHASE 4: Compose (Weeks 12-20)

### Compose Execution

- [ ] Implement compose config parsing and validation
- [ ] Implement service dependency ordering
- [ ] Implement compose up/down/ps/logs
- [ ] Add compose integration tests

---

## PHASE 5: AI Layer (Weeks 11-18, depends on Phase 1)

### WASM Runtime Integration

- [ ] Integrate Wasmtime 19.0 runtime into ferro-mind
- [ ] Implement WASM module loading and validation
- [ ] Implement host function interface (metrics import)
- [ ] Implement pluggable backend architecture (trait-based)
- [ ] Create WASM module embedding in binary
- [ ] Implement graceful fallback if WASM unavailable
- [ ] Create integration tests for WASM execution

### Tier 1 Models (WASM - 1-5ms latency)

- [ ] Implement resource prediction model (memory, cpu based on image/history)
- [ ] Implement anomaly detection model (metrics deviation scoring)
- [ ] Implement restart decision model (health check → restart probability)
- [ ] Implement cache optimization model (layer reuse prediction)
- [ ] Pre-train models using synthetic data
- [ ] Create model validation tests

### Inference Engine

- [ ] Implement inference request routing (Tier 1/2/3)
- [ ] Implement Tier 1 request handler (WASM models)
- [ ] Implement Tier 2 routing stub (local LLM, future)
- [ ] Implement Tier 3 routing stub (cloud API, future)
- [ ] Implement metrics collection for inference performance
- [ ] Create inference latency tests (<5ms for Tier 1)

### Container Integration

- [ ] Collect metrics from running containers (cgroups, /proc)
- [ ] Feed metrics to inference engine
- [ ] Implement resource adjustment based on predictions
- [ ] Implement restart logic based on anomaly scores
- [ ] Create end-to-end tests (container running → metrics → prediction → action)

### Observability

- [ ] Implement structured logging for AI decisions
- [ ] Create metrics export (Prometheus format, optional)
- [ ] Implement tracing for inference requests
- [ ] Create AI debugging guide

### Phase 3 Milestone: MVP v0.3.0 (AI-Ready)

**Deliverable**: Intelligent resource allocation with Tier 1 models

- [ ] Merge all Phase 3 code
- [ ] Create v0.3.0 release tag
- [ ] Update documentation with AI features
- [ ] Publish AI benchmarks and latency measurements

---
## PHASE 6: Hardening & Production Readiness (Weeks 21-70, ongoing)

### Performance Optimization

- [ ] Profile container startup time (target: <5s)
- [ ] Profile image pull performance (target: <30s for typical images)
- [ ] Optimize eBPF program performance (minimize packet processing overhead)
- [ ] Optimize image decompression (parallelize layer extraction)
- [ ] Optimize memory usage (reduce per-container overhead)
- [ ] Create performance regression tests
- [ ] Document performance tuning options

### Security Hardening

- [ ] Implement comprehensive seccomp profiles by workload type
- [ ] Implement AppArmor/SELinux profile generation
- [ ] Run security audit by third party (if possible)
- [ ] Fix any identified vulnerabilities
- [ ] Implement runtime security monitoring (anomaly detection)
- [ ] Create security best practices guide
- [ ] Document security model in detail

### Stability & Reliability

- [ ] Implement comprehensive error handling (all error paths tested)
- [ ] Implement recovery from common failures (daemon crash, OOM, kernel panic)
- [ ] Implement health checks and self-healing
- [ ] Create chaos engineering tests (random failures, resource exhaustion)
- [ ] Test under sustained high load (100+ containers)
- [ ] Test container migration scenarios
- [ ] Create operational runbook

### Edge Cases & Compatibility

- [ ] Test with very large images (10GB+)
- [ ] Test with deeply nested directory structures
- [ ] Test with unusual image formats (unusual media types)
- [ ] Test with old Docker images (pre-1.10)
- [ ] Test with resource-constrained systems (small VPS, embedded)
- [ ] Test with slow networks (congestion simulation)
- [ ] Test with intermittent network failures
- [ ] Create comprehensive edge case test suite

### Observability & Debugging

- [ ] Implement detailed logging at all levels
- [ ] Implement structured logging (JSON output)
- [ ] Implement tracing for troubleshooting (internal spans)
- [ ] Implement metrics collection (Prometheus format)
- [ ] Create observability documentation
- [ ] Create debugging guide for common issues

### Release Infrastructure

- [ ] Set up automated release pipeline
- [ ] Implement semantic versioning scheme
- [ ] Create release notes template
- [ ] Implement changelog generation
- [ ] Set up binary distribution (GitHub releases)
- [ ] Set up package repositories (apt, yum, brew if applicable)
- [ ] Create upgrade guide

### Documentation Finalization

- [ ] Create comprehensive production deployment guide
- [ ] Create high-availability deployment guide
- [ ] Create backup and disaster recovery guide
- [ ] Create monitoring and alerting guide
- [ ] Create capacity planning guide
- [ ] Update all documentation for v1.0.0
- [ ] Create FAQ document
- [ ] Create glossary of terms

### Testing Coverage

- [ ] Achieve 80%+ code coverage across all crates
- [ ] Create fuzzing tests for critical paths (image parsing, config parsing)
- [ ] Create property-based tests (random valid inputs)
- [ ] Create stress tests (resource exhaustion)
- [ ] Create long-running stability tests (72-hour runs)

### Community & Ecosystem

- [ ] Set up community issue triage process
- [ ] Create issue templates
- [ ] Set up contribution workflow
- [ ] Create security advisory process
- [ ] Publish roadmap publicly
- [ ] Engage with OCI community
- [ ] Engage with CNCF community

### Phase 6 Milestone: Production v1.0.0

**Deliverable**: Production-ready FerroCrate runtime

- [ ] All tests passing
- [ ] Security audit complete
- [ ] Performance benchmarks acceptable
- [ ] Documentation comprehensive
- [ ] Create v1.0.0 release tag
- [ ] Announce production readiness

---
## PHASE 7: Kubernetes Integration (Weeks 21-32, depends on Phases 1-6)

### CRI Shim Implementation (ferro-cri)

- [ ] Implement Container Runtime Interface (CRI) v1 specification
- [ ] Implement gRPC service for kubelet communication
- [ ] Implement ImageService (pull, push, list images)
- [ ] Implement RuntimeService (create, start, stop containers)
- [ ] Implement PodSandbox operations
- [ ] Implement container execution and lifecycle
- [ ] Implement logging via container log storage
- [ ] Create CRI compliance tests

### kubelet Integration

- [ ] Configure kubelet to use FerroCrate as runtime (via CRI socket)
- [ ] Test basic pod creation and execution
- [ ] Test pod networking via CNI
- [ ] Test pod logs retrieval
- [ ] Test pod exec functionality
- [ ] Create kubelet integration tests

### Kubernetes Testing Environment

- [ ] Set up local Kubernetes cluster (kind, kubeadm, or similar)
- [ ] Deploy FerroCrate as CRI runtime
- [ ] Create test pod manifests (simple, with volumes, with network policies)
- [ ] Create test suite for Kubernetes workloads

### Edge Cases & Compatibility

- [ ] Test with multiple pod networks (Calico, Flannel, etc.)
- [ ] Test with PersistentVolumes and storage
- [ ] Test with ConfigMaps and Secrets
- [ ] Test with DaemonSets and StatefulSets
- [ ] Test with Helm charts
- [ ] Create comprehensive edge case test suite

### CRI Documentation

- [ ] Document CRI shim architecture
- [ ] Create Kubernetes deployment guide
- [ ] Create troubleshooting guide for Kubernetes
- [ ] Document known limitations

### Phase 5 Milestone: Kubernetes Ready (v0.5.0)

**Deliverable**: FerroCrate as working Kubernetes CRI runtime

- [ ] Merge all Phase 5 code
- [ ] Create v0.5.0 release tag
- [ ] Pass CRI compliance tests
- [ ] Successfully run realistic Kubernetes workloads
- [ ] Publish Kubernetes deployment documentation

---
## PHASE 8: Documentation & Polish (Final)

### API Documentation

- [ ] Document ferro-core public API (runtime, image, storage modules)
- [ ] Document ferro-net public API (eBPF, fallback backends)
- [ ] Document ferro-mind public API (inference interface)
- [ ] Generate OpenAPI specification for HTTP APIs (if any)
- [ ] Create API reference documentation (rustdoc)
- [ ] Create examples for each public API

### Architecture Documentation

- [ ] Create C4 Context diagram (system, containers, components)
- [ ] Create architecture decision record index with all 15 ADRs
- [ ] Document data flow (image → container → execution)
- [ ] Document crate dependencies and module boundaries
- [ ] Create sequence diagrams for key operations (run, build, pull)
- [ ] Document security architecture and isolation mechanisms

### User Documentation

- [ ] Create installation guide (from source, binary, package)
- [ ] Create quick start tutorial (run first container)
- [ ] Create build tutorial (create and run custom image)
- [ ] Create networking troubleshooting guide
- [ ] Create performance tuning guide
- [ ] Create rootless setup guide for new systems
- [ ] Create migration guide from Docker (if applicable)

### Developer Documentation

- [ ] Create contributor guide (setup, testing, code style)
- [ ] Create debugging guide (logging, tracing, profiling)
- [ ] Create 5-crate architecture overview
- [ ] Document test infrastructure and how to add tests
- [ ] Create performance benchmarking guide
- [ ] Document release process

### Code Quality

- [ ] Run clippy linter on all crates; fix warnings
- [ ] Enforce documentation on public APIs (all exports documented)
- [ ] Set up code formatter (rustfmt) in CI
- [ ] Create CONTRIBUTING.md with code standards
- [ ] Implement license header check in CI

### Security Hardening (Phase 2)

- [ ] Run cargo-audit to check for known vulnerabilities
- [ ] Implement CVE response process
- [ ] Create security policy document (SECURITY.md)
- [ ] Document threat model for rootless containers
- [ ] Review all unsafe code blocks with security focus

### Performance Baseline

- [ ] Create performance benchmark suite (container startup, image pull)
- [ ] Measure baseline performance metrics
- [ ] Document performance targets (from PRD: container start <5s, image pull <30s)
- [ ] Profile memory usage under load
- [ ] Identify initial optimization candidates

### Phase 2 Milestone: Production-Ready Documentation

**Deliverable**: Complete documentation suite for users and developers

- [ ] All documentation files reviewed and complete
- [ ] API documentation auto-generated and accurate
- [ ] Examples tested and working
- [ ] Security policy published

---
## Completion Tracking

### How to Mark Tasks as Complete

Simply replace `- [ ]` with `- [x]` or use strikethrough:

**Option 1 - Checkbox:**
```
- [x] ~~This task is complete~~
```

**Option 2 - Strikethrough only:**
```
- [ ] ~~This task is complete~~
```

### Example Completed Phase 1:

```markdown
## PHASE 1: Foundation (Weeks 1-10)

### Runtime Implementation (OCI Runtime Spec v1.2)

- [x] ~~Set up Rust project structure with 5-crate workspace~~
- [x] ~~Implement OCI Runtime Spec v1.2 config.json parser~~
- [ ] Implement Linux namespace creation (pid, network, ipc, uts, mount)
```

---

## Notes for External Development Teams

### Getting Started

1. Clone the repository: `git clone <repo>`
2. Read `/docs/development/CONTRIBUTING.md` for development setup
3. Review Phase 1 tasks to understand the foundation
4. Each task should have a corresponding issue/PR in GitHub

### Dependencies

- **Phase 1** blocks all other phases (foundation requirement)
- **Phase 2** can run in parallel with Phase 1 (weeks 5-10 overlap)
- **Phase 3 & 4** can run in parallel (both depend only on Phase 1)
- **Phase 5** depends on Phases 1-4 complete
- **Phase 6** runs for entire project duration (weeks 21-70)

### Communication

- Use GitHub Issues for task status updates
- Use GitHub Projects board for visual progress tracking
- Weekly standup recommended for Phase 1 critical path
- Bi-weekly standups for Phases 3-6

### Quality Gates

Each phase must complete with:
- ✅ All tasks marked complete
- ✅ All integration tests passing
- ✅ Code review approved
- ✅ Documentation updated
- ✅ Security baseline met for that phase

---

## Version Milestones

| Version | Weeks | Phases Complete | Deliverable |
|---------|-------|-----------------|-------------|
| v0.1.0 | 10 | 1 | Basic container runtime |
| v0.3.0 | 18 | 1-3 | MVP with AI inference |
| v0.5.0 | 32 | 1-5 | Kubernetes CRI ready |
| v1.0.0 | 52-72 | 1-6 | Production ready |

---

**Last Updated**: February 11, 2026
**Maintained By**: FerroCrate Development Team
