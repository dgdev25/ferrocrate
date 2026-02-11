# ADR-015: Timeline Revision and MVP Scope

## Status

**Accepted** (February 11, 2026 - Extended timeline from 36 to 52-72 weeks per AI consensus on realistic delivery)

## Context

The initial project timeline estimated **36 weeks (9 months)** for FerroCrate to reach production maturity. After comprehensive review by 4 consensus AI models, this estimate was identified as significantly optimistic.

**Original 36-Week Timeline Issues:**
- Underestimated scope of OCI specification implementation
- No time allocated for eBPF kernel integration and fallback testing
- WASM AI inference model development and training not included
- Kubernetes CRI shim development added as Phase 2 (4-5 weeks minimum)
- Insufficient testing time for edge cases (rootless containers, networking fallbacks)
- No buffer for dependency/security issues

**AI Consensus Assessment:**
All 4 models unanimously recommended extending timeline to 52-72 weeks (12-18 months) with realistic phase breakdown.

**Calculation:**
```
Phase 1 (Cores): 8-10 weeks   (runtime, image, storage basics)
Phase 2 (Docs): 4-6 weeks     (API, architecture, examples)
Phase 3 (AI): 6-8 weeks       (WASM models, inference tier system)
Phase 4 (Networking): 8-10 weeks (eBPF primary, iptables/nftables fallback)
Phase 5 (K8s CRI): 10-12 weeks (CRI shim, integration testing)
Phase 6 (Hardening): 16-20 weeks (performance, security, edge cases, real-world testing)
─────────────────────────────────
Total: 52-72 weeks (12-18 months)
```

## Decision

**Extend timeline from 36 weeks to 52-72 weeks (12-18 months). Phase all work based on dependency constraints and MVP scope.**

### Phase Breakdown

**Phase 1: Foundation (Weeks 1-10, ~8 weeks critical path)**
- OCI Runtime Spec v1.2 implementation (containers, processes)
- OCI Image Spec v1.1 (manifest, layers, basic pull/push)
- OverlayFS storage integration (rootless support)
- cgroups v2 management
- Basic CLI (run, build, images, containers)

**Deliverable**: Can run simple OCI containers rootlessly

**Phase 2: Documentation & Polish (Weeks 5-10, parallel with Phase 1)**
- OpenAPI specification for internal APIs
- Architecture documentation (C4 diagrams)
- User documentation (installation, basic tutorial)
- Security hardening (audit, CVE scanning)
- Rootless container testing at scale

**Deliverable**: Production-ready documentation and security baseline

**Phase 3: AI Layer (Weeks 11-18, depends on Phase 1)**
- WASM runtime integration (Wasmtime 19.0)
- Implement Tier 1 models (resource prediction, anomaly detection, restart logic)
- Tier 2 routing (local LLM optional integration)
- Integration tests with container metrics

**Deliverable**: Intelligent resource allocation (1-5ms latency)

**Phase 4: Networking (Weeks 11-20, depends on Phase 1)**
- eBPF XDP/TC implementation (modern kernels)
- iptables fallback (explicit --network-backend flag)
- nftables alternative (explicit --network-backend flag)
- Network namespace isolation testing
- Integration with rootless containers

**Deliverable**: Multi-backend networking with explicit fallback control

**Phase 5: Kubernetes Integration (Weeks 21-32, depends on Phases 1-4)**
- CRI (Container Runtime Interface) v1 shim
- Kubernetes test environment setup
- Integration with kubelet
- Pod management, logs, exec support
- Heavy testing with real Kubernetes clusters

**Deliverable**: FerroCrate as drop-in containerd/CRI-O replacement

**Phase 6: Hardening & Production Readiness (Weeks 21-70, ongoing)**
- Performance optimization and benchmarking
- Security audit and CVE response procedures
- Edge case testing (out-of-memory, hung processes, network partitions)
- Real-world workload testing (databases, web servers, batch jobs)
- Production deployment guide
- Monitoring and observability integration
- Release automation and CI/CD

**Deliverable**: Production-ready v1.0.0

### MVP Scope (Phase 1-3, Weeks 1-18)

**What's Included:**
✅ Rootless container runtime (OCI-compliant)
✅ Image management (pull, push, build)
✅ Basic OverlayFS storage
✅ AI-driven resource allocation (Tier 1)
✅ CLI with run, build, images, containers commands

**What's NOT Included (Phase 4+):**
❌ Kubernetes CRI integration (Phase 5)
❌ Complex networking (eBPF/iptables) (Phase 4)
❌ Docker socket compatibility (optional Phase 2)
❌ Compose orchestration (Phase 4)
❌ Production hardening (Phase 6)

**MVP Output:**
- Working FerroCrate binary for Linux x86_64
- Runs simple to moderate workloads
- Secure by default (rootless, no daemon)
- AI-optimized resource allocation

## Consequences

### Positive

- **Realistic delivery**: 52-72 week estimate aligns with industry standards
- **Quality focus**: Extra time for testing and hardening prevents poor releases
- **Manageable phases**: Clear dependencies prevent rework and blocking
- **Risk reduction**: 3-4 month buffer handles unexpected issues
- **Learning opportunity**: Phased approach allows market feedback integration
- **MVP satisfaction**: MVP-only teams can deliver in 18 weeks (~4.5 months)

### Negative

- **Longer wait to production**: Original 9-month target extended to 12-18 months
- **Stakeholder expectations**: Teams expecting 36 weeks must adjust plans
- **Resource commitment**: Longer timeline requires sustained staffing
- **Market window**: Competitors may move faster with lower quality

### Neutral

- **MVP positioning**: Teams focusing on MVP can demo in 18-20 weeks, iterate in production

## Alternatives Considered

### Keep 36-Week Timeline (Aggressive)

**Pros:**
- First-mover advantage
- Faster market entry

**Cons:**
- Likely delivered with critical bugs and incomplete features
- Security and performance not thoroughly tested
- Unsustainable for maintainers (burnout risk)
- Kubernetes integration missing (major market requirement)
- All 4 consensus models disagreed with this approach

**Decision**: Rejected. Quality > Speed for infrastructure software.

### 90+ Week Timeline (Ultra-Conservative)

**Pros:**
- Maximum safety margin
- Time for every edge case

**Cons:**
- Too conservative; opportunity cost high
- Market may move on
- Team motivation challenges with extended timeline

**Decision**: Rejected. 52-72 weeks provides balanced risk.

### Parallel Phases (No Sequencing)

**Pros:**
- Could theoretically finish faster

**Cons:**
- Networking and AI depend on runtime (Phase 1)
- Kubernetes depends on all other phases
- Artificial parallelism increases rework

**Decision**: Rejected. Dependency-driven phasing is more efficient.

## Implementation Notes

**Project Tracking:**
```
Phase 1 (Foundation): Dec 2025 - Feb 2026 (10 weeks)
Phase 2 (Docs/Polish): Jan 2026 - Feb 2026 (6 weeks, parallel)
Phase 3 (AI): Mar 2026 - May 2026 (8 weeks)
Phase 4 (Networking): Mar 2026 - May 2026 (10 weeks, parallel with Phase 3)
Phase 5 (K8s CRI): Jun 2026 - Aug 2026 (12 weeks)
Phase 6 (Hardening): Jan 2026 - Sep 2026 (ongoing, final 20 weeks intensive)
```

**Milestone Tracking:**
- **Week 10**: MVP delivery possible
- **Week 18**: Full MVP with AI and docs
- **Week 32**: Kubernetes-ready
- **Week 52-72**: Production v1.0.0

**Release Strategy:**
- v0.1.0 (Week 10): Tech preview with Phase 1
- v0.3.0 (Week 18): MVP-ready, Phase 1-3 complete
- v0.5.0 (Week 32): Kubernetes support, Phase 1-5 complete
- v1.0.0 (Week 52-72): Production-ready, Phase 1-6 complete

## References

- Consensus Model Agreement: All 4 models recommended 52-72 week timeline
- [Software Project Estimation](https://en.wikipedia.org/wiki/Software_project_estimation)
- Docker 1.0 released 2014 (multi-year development)
- containerd 1.0 released 2017 (multi-year development)
- CRI-O 1.0 released 2017 (multi-year development)
- PRD Requirements: DEL-01, DEL-02, MVP-01, MVP-02
