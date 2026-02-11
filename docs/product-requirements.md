# FerroCrate Product Requirements Document (PRD)

## AI-Native Container Runtime

**Version:** 1.0 | **Date:** February 11, 2026 | **Status:** Draft  
**Product Owner:** Lyle | **Technical Lead:** Claude + ruvnet

---

## 1. Problem Statement

Modern container runtimes waste resources, lack intelligence, and force a split between development and production tooling. Docker consumes 120-180MB at idle with zero containers running. Container failures trigger dumb restart loops instead of intelligent remediation. Developers use Docker Desktop; production uses containerd or CRI-O — creating runtime mismatch bugs. AI/ML workloads require manual GPU/VRAM management with no native container runtime support. Edge deployments are impractical due to runtime memory overhead.

FerroCrate solves all five problems with a single, AI-native runtime built in Rust.

---

## 2. User Personas

### Persona 1: "DevOps Dana" — Platform Engineer

- **Role:** Senior Platform Engineer at a 500-person SaaS company
- **Pain Points:** Manages Docker Desktop licenses ($15/user/month for 80 developers = $14,400/year). Spends 20% of time debugging container issues that repeat. Different runtime in dev vs prod causes "works on my machine" incidents monthly.
- **Goals:** Single runtime for dev and prod. Automated incident remediation. Reduced tooling costs.
- **Technical Level:** Expert with containers, comfortable with CLI, scripts, and configuration.

### Persona 2: "ML Marcus" — AI Infrastructure Lead

- **Role:** ML Platform Lead at an AI startup running 50+ GPU containers
- **Pain Points:** GPU containers waste 30-40% of allocated VRAM. No runtime understands model loading patterns. Container cold starts for LLM inference take 45-90 seconds due to model loading.
- **Goals:** Intelligent VRAM allocation. Model caching across container restarts. Sub-10-second LLM container startup.
- **Technical Level:** Expert with ML infrastructure, moderate with container internals.

### Persona 3: "Edge Elena" — IoT Platform Architect

- **Role:** Lead Architect for a fleet of 10,000 edge devices
- **Pain Points:** Docker is too heavy for ARM devices with 512MB-2GB RAM. Containers must operate autonomously when disconnected from cloud. OTA updates are fragile with current container tooling.
- **Goals:** Sub-20MB runtime footprint. Autonomous operation without cloud connectivity. Reliable OTA container updates.
- **Technical Level:** Expert with embedded systems, moderate with containers.

### Persona 4: "Startup Steve" — Full-Stack Developer

- **Role:** Solo developer / small team lead building SaaS products
- **Pain Points:** Docker Desktop consumes 2-4GB RAM on his MacBook. docker-compose up takes 30-60 seconds. Wants containers but hates the overhead.
- **Goals:** Fast, lightweight local development. Simple CLI. Works with existing Docker images and Dockerfiles.
- **Technical Level:** Competent with Docker basics, not a container expert.

### Persona 5: "Security Sarah" — CISO / Security Architect

- **Role:** Security lead at a financial services company
- **Pain Points:** Docker daemon runs as root — a container escape means full host compromise. Runtime is written in Go with garbage collector pauses and potential memory corruption in CGO code. No runtime provides meaningful security intelligence.
- **Goals:** Rootless by default. Memory-safe runtime. Automated vulnerability detection and response. Audit trail for all container operations.
- **Technical Level:** Expert with security, moderate with container operations.

---

## 3. Functional Requirements

### 3.1 Container Lifecycle Management

| ID | Requirement | Priority | Acceptance Criteria |
|----|------------|----------|-------------------|
| CLM-01 | Run OCI-compliant container images | P0 | All images from Docker Hub, GHCR, ECR, GCR run without modification |
| CLM-02 | Create, start, stop, restart, kill, remove containers | P0 | CLI commands complete within 2x of runc performance |
| CLM-03 | Container pause/unpause via cgroup freezer | P1 | Processes suspended/resumed without termination |
| CLM-04 | Container exec (run commands in running container) | P0 | Interactive and detached modes supported |
| CLM-05 | Container logs with stdout/stderr separation | P0 | Real-time streaming and historical log access |
| CLM-06 | Container inspect (JSON metadata output) | P0 | Docker-compatible JSON schema for tooling interoperability |
| CLM-07 | Health checks with configurable intervals | P0 | Dockerfile HEALTHCHECK directive supported |
| CLM-08 | Automatic restart policies (no, on-failure, always, unless-stopped) | P0 | Behavior matches Docker restart policy semantics |
| CLM-09 | Container resource limits (memory, CPU, PIDs) | P0 | cgroups v2 unified hierarchy enforcement |
| CLM-10 | Container environment variables, labels, annotations | P0 | Full Docker -e, --label, and OCI annotation support |

### 3.2 Image Management

| ID | Requirement | Priority | Acceptance Criteria |
|----|------------|----------|-------------------|
| IMG-01 | Pull images from OCI-compliant registries | P0 | Docker Hub, GHCR, ECR, GCR, Harbor, Quay.io tested |
| IMG-02 | Push images to OCI-compliant registries | P0 | Authentication via docker config.json and credential helpers |
| IMG-03 | Content-addressable store with Blake3 hashing | P0 | File-level deduplication across layers; 40%+ storage reduction vs Docker |
| IMG-04 | Zstd compression for layers | P1 | 2x+ compression speed vs gzip at comparable ratios |
| IMG-05 | Lazy image pulling (on-demand file fetch) | P1 | Container starts before full image download; manifest-only initial fetch |
| IMG-06 | Image build from Dockerfile | P0 | 95%+ Dockerfile directive compatibility (documented exceptions only) |
| IMG-07 | Image build from ferrofile.toml (declarative format) | P1 | Declarative build specification with static analysis capability |
| IMG-08 | Multi-stage build support | P0 | COPY --from= and named stages supported |
| IMG-09 | Build cache with file-level granularity | P1 | Single file change invalidates only that file, not entire COPY layer |
| IMG-10 | Image tagging, listing, removal, pruning | P0 | Standard image management operations |
| IMG-11 | Image scanning for known CVEs | P2 | Integration with vulnerability databases (NVD, OSV) |
| IMG-12 | ruvector-indexed layer deduplication | P2 | Vector embeddings identify similar (not identical) content for dedup |

### 3.3 Networking

| ID | Requirement | Priority | Acceptance Criteria |
|----|------------|----------|-------------------|
| NET-01 | Bridge networking (default) | P0 | Containers communicate via virtual bridge; port mapping to host |
| NET-02 | Host networking | P0 | Container shares host network namespace |
| NET-03 | None networking | P0 | Container has loopback only |
| NET-04 | Container-to-container DNS resolution | P0 | Containers resolve each other by name within a network |
| NET-05 | Custom network creation and management | P0 | Named networks with configurable subnets |
| NET-06 | eBPF-based packet forwarding with iptables/nftables fallback | P1 | eBPF primary; explicit `--network-backend=iptables` fallback available; no silent fallback |
| NET-07 | WireGuard encrypted overlay networking | P2 | Cross-host container communication with transparent encryption |
| NET-08 | Port mapping (host:container) | P0 | TCP and UDP port forwarding |
| NET-09 | IPv6 support | P1 | Dual-stack networking for containers |
| NET-10 | Network bandwidth limiting | P2 | Per-container egress/ingress rate limiting via eBPF |

### 3.4 Storage and Volumes

| ID | Requirement | Priority | Acceptance Criteria |
|----|------------|----------|-------------------|
| STR-01 | Named volumes | P0 | Persistent storage across container lifecycle |
| STR-02 | Bind mounts | P0 | Host directory mounted into container |
| STR-03 | tmpfs mounts | P0 | In-memory filesystem for sensitive or ephemeral data |
| STR-04 | Volume drivers (plugin system) | P2 | Extensible storage backend support |
| STR-05 | OverlayFS as default storage driver | P0 | Efficient copy-on-write layer management |
| STR-06 | Read-only root filesystem support | P0 | Immutable container filesystem with writable overlay |
| STR-07 | Volume backup and restore | P2 | CLI commands for volume data export/import |

### 3.5 Security

| ID | Requirement | Priority | Acceptance Criteria |
|----|------------|----------|-------------------|
| SEC-01 | Rootless operation by default | P0 | User namespace isolation without root privileges |
| SEC-02 | Seccomp profiles (default + custom) | P0 | Default profile blocks dangerous syscalls; custom profiles loadable |
| SEC-03 | AppArmor/SELinux integration | P1 | MAC enforcement for container processes |
| SEC-04 | Capability dropping (all dropped by default) | P0 | Only explicitly granted capabilities available to container |
| SEC-05 | Read-only rootfs by default for production mode | P1 | Configurable via flag; default differs for dev vs prod profiles |
| SEC-06 | No-new-privileges flag enforced | P0 | Processes cannot gain privileges via setuid/setgid |
| SEC-07 | Container image signature verification | P1 | Cosign/Sigstore signature verification before run |
| SEC-08 | Runtime security monitoring via eBPF | P2 | Real-time syscall auditing and anomaly detection |
| SEC-09 | Encrypted container-to-container communication | P2 | QuDAG-based quantum-resistant encryption option |
| SEC-10 | Audit logging for all container operations | P1 | Structured JSON logs for compliance requirements |

### 3.6 Compose / Multi-Container Orchestration

| ID | Requirement | Priority | Acceptance Criteria |
|----|------------|----------|-------------------|
| CMP-01 | docker-compose.yml compatibility | P0 | Version 3.x compose files parsed and executed |
| CMP-02 | Native compose subcommand (ferrocrate compose) | P0 | No separate tool installation required |
| CMP-03 | Service dependency ordering | P0 | depends_on with condition support |
| CMP-04 | Service scaling (replicas) | P1 | ferrocrate compose up --scale web=3 |
| CMP-05 | Environment file support (.env) | P0 | Variable substitution in compose files |
| CMP-06 | Profile support for selective service activation | P1 | Named profiles to enable/disable services |
| CMP-07 | Watch mode for development (file sync + rebuild) | P2 | Automatic container rebuild on source file changes |

### 3.7 AI/Intelligence Layer (ferro-mind)

| ID | Requirement | Priority | Acceptance Criteria |
|----|------------|----------|-------------------|
| AI-01 | WASM-based neural inference for resource prediction (pluggable) | P1 | 1-5ms prediction latency; zero external API calls in WASM tier; optional feature |
| AI-02 | Predictive resource allocation | P1 | Memory/CPU pre-allocation based on learned usage patterns |
| AI-03 | Intelligent container restart (not just blind restart) | P1 | Diagnostic analysis before restart; configuration adjustment if pattern detected |
| AI-04 | Cost-tiered AI routing | P1 | WASM (free) → local LLM (cheap) → Claude API (complex) decision hierarchy |
| AI-05 | claude-flow agent orchestration integration | P2 | Multi-agent swarm for complex debugging and remediation |
| AI-06 | Container anomaly detection | P1 | Resource usage anomalies flagged with severity and recommendation |
| AI-07 | Build cache optimization via ruvector | P2 | Learned similarity for cache hit improvement beyond exact hash matching |
| AI-08 | Natural language container management | P2 | "ferrocrate ask 'why did my web server crash?'" with claude-flow analysis |
| AI-09 | Self-learning from operational patterns | P2 | ruvector stores and retrieves operational patterns; improves over time |
| AI-10 | AI feature opt-out | P0 | All AI features disable via single flag; runtime operates identically to static runtime |
| AI-11 | AI decision explainability | P1 | Every AI action logged with reasoning; "ferrocrate explain <decision-id>" command |
| AI-12 | GPU/VRAM-aware scheduling for AI workloads | P2 | Detect NVIDIA/AMD GPUs; intelligent VRAM allocation for LLM containers |

### 3.8 CLI and Developer Experience

| ID | Requirement | Priority | Acceptance Criteria |
|----|------------|----------|-------------------|
| CLI-01 | Docker-compatible CLI syntax | P0 | ferrocrate run, build, pull, push, ps, logs, exec match Docker behavior |
| CLI-02 | Docker socket compatibility mode | P1 | Emulate /var/run/docker.sock for tools expecting Docker API |
| CLI-03 | Shell completion (bash, zsh, fish) | P0 | Tab completion for commands, images, container names |
| CLI-04 | Colored, human-friendly output | P0 | Progress bars for pulls; table formatting for ps/images |
| CLI-05 | JSON output mode (--format json) | P0 | Machine-parseable output for scripting |
| CLI-06 | Migration tool (ferrocrate migrate) | P1 | Scan Docker installation; generate ferrocrate-equivalent configuration |
| CLI-07 | Interactive container management TUI | P2 | Terminal UI for browsing containers, logs, resources |

---

## 4. Non-Functional Requirements

### 4.1 Performance

| ID | Requirement | Target | Measurement |
|----|------------|--------|-------------|
| PERF-01 | Container startup time | <100ms (cold), <50ms (warm) | Time from API call to process running |
| PERF-02 | Image pull throughput | >500 MB/s on 1Gbps link | Sustained download rate for large images |
| PERF-03 | Idle memory consumption (no daemon) | 0 MB | RSS measurement with no containers running |
| PERF-04 | Idle memory consumption (with daemon) | <8 MB | RSS of ferro-mgr process |
| PERF-05 | Per-container memory overhead | <2 MB | Additional RSS per managed container |
| PERF-06 | Build performance | Within 15% of Docker BuildKit | Equivalent Dockerfile build time comparison |
| PERF-07 | CLI binary size | <15 MB (static, stripped) | Single statically-linked binary |
| PERF-08 | AI inference latency (WASM) | 1-5 ms per decision (realistic WASM performance) | ruv-FANN neural net evaluation time with 2-5x overhead vs native |

### 4.2 Compatibility

| ID | Requirement | Target |
|----|------------|--------|
| COMPAT-01 | OCI Image Spec v1.1 | Full compliance |
| COMPAT-02 | OCI Runtime Spec v1.2 | Full compliance |
| COMPAT-03 | OCI Distribution Spec v1.1 | Full compliance |
| COMPAT-04 | Docker API v1.45+ (optional layer) | OCI-first primary; Docker API as optional translation layer with 70-80% core endpoint coverage |
| COMPAT-05 | docker-compose v3.x files | 90%+ directive coverage |
| COMPAT-06 | Dockerfile syntax | 95%+ directive coverage |
| COMPAT-07 | Linux kernel 5.10+ | Minimum supported kernel |
| COMPAT-08 | Architectures: x86_64, aarch64, riscv64 | Cross-compilation targets |
| COMPAT-09 | Kubernetes CRI v1 | Phase 2 deliverable (elevated priority over Docker API) |

### 4.3 Reliability

| ID | Requirement | Target |
|----|------------|--------|
| REL-01 | Runtime crash does not kill containers | Container processes survive runtime restart |
| REL-02 | Graceful degradation without AI | All container operations function if AI layer fails |
| REL-03 | Data integrity for image store | Blake3 checksums verified on every read |
| REL-04 | Atomic operations | Image pulls, volume operations are atomic (no partial state) |
| REL-05 | Test coverage | >80% line coverage; 100% coverage for unsafe blocks |

### 4.4 Observability

| ID | Requirement | Priority |
|----|------------|----------|
| OBS-01 | Prometheus metrics endpoint | P1 |
| OBS-02 | OpenTelemetry trace export | P2 |
| OBS-03 | Structured JSON logging | P0 |
| OBS-04 | Container resource usage stats (CPU, memory, network, disk I/O) | P0 |
| OBS-05 | AI decision audit log | P1 |

---

## 5. User Stories

### Epic 1: Container Runtime Core

**US-1.1:** As a developer, I want to run any Docker Hub image with `ferrocrate run` so that I can use my existing container images without modification.

**US-1.2:** As a DevOps engineer, I want ferrocrate to consume zero memory when no containers are running so that it doesn't waste resources on my servers.

**US-1.3:** As a security engineer, I want containers to run rootless by default so that a container escape doesn't grant root access to the host.

**US-1.4:** As a developer, I want `ferrocrate build` to accept my existing Dockerfiles so that I don't have to rewrite my build configurations.

**US-1.5:** As a platform engineer, I want `ferrocrate compose` to parse my docker-compose.yml files so that I can migrate multi-service applications without changes.

### Epic 2: Performance and Efficiency

**US-2.1:** As an edge developer, I want the ferrocrate binary to be under 15MB so that it fits on resource-constrained devices.

**US-2.2:** As a developer, I want container startup under 100ms so that my development loop is fast.

**US-2.3:** As a DevOps engineer, I want file-level image deduplication so that storing 50 similar images doesn't consume 50x the disk space.

**US-2.4:** As an ML engineer, I want lazy image pulling so that my 15GB model containers start before the full image downloads.

### Epic 3: Intelligence Layer

**US-3.1:** As a DevOps engineer, I want ferrocrate to predict container memory needs based on historical patterns so that I don't over-allocate or face OOM kills.

**US-3.2:** As a developer, I want to ask ferrocrate "why did my container crash?" in natural language and get an intelligent analysis, not just "OOMKilled."

**US-3.3:** As a platform engineer, I want ferrocrate to automatically adjust container resource limits based on observed usage so that I don't have to manually tune every service.

**US-3.4:** As a security engineer, I want ferrocrate to detect anomalous container behavior (unexpected network connections, unusual syscalls) and alert me without requiring external tools.

**US-3.5:** As a developer, I want to disable all AI features with a single flag so that I can use ferrocrate as a pure, predictable container runtime when I want.

### Epic 4: Migration and Compatibility

**US-4.1:** As a DevOps engineer, I want `ferrocrate migrate` to scan my Docker installation and generate an equivalent ferrocrate configuration so that migration is automated.

**US-4.2:** As a developer, I want ferrocrate to emulate the Docker socket so that tools like VS Code Dev Containers, Testcontainers, and docker-compose work without modification.

**US-4.3:** As a CI/CD engineer, I want ferrocrate to work as a drop-in replacement in GitHub Actions workflows so that I don't have to rewrite my pipelines.

### Epic 5: Multi-Agent Orchestration

**US-5.1:** As a platform engineer, I want to deploy claude-flow agents that monitor container health across my fleet and coordinate remediation automatically.

**US-5.2:** As a developer, I want containers to negotiate their own resource allocation using DAA principles so that a spike in one service doesn't starve others.

**US-5.3:** As a security engineer, I want agentic security scanning that proactively identifies and patches vulnerabilities in running containers without manual intervention.

---

## 6. Out of Scope (v1.0)

The following are explicitly excluded from the initial release:

- **Full Kubernetes CRI implementation** — Planned for Phase 4 (ferro-cri)
- **Windows container support** — Linux containers only (Windows/macOS users run via lightweight VM, similar to Docker Desktop)
- **Docker Swarm compatibility** — Swarm usage is declining; compose covers multi-container orchestration
- **GUI/Desktop application** — CLI-first; desktop app planned for FerroCrate Pro
- **Built-in container registry** — Use existing registries (Docker Hub, GHCR, etc.)
- **cgroups v1 support** — v2 only; all major distros have shipped v2 as default since 2021-2022
- **Proprietary image formats** — OCI standard only

---

## 7. Dependencies

### External Dependencies

| Dependency | Type | Risk Level | Mitigation |
|-----------|------|-----------|------------|
| Linux kernel 5.10+ | Runtime | Low | Widely available; 5.10 is 5+ years old |
| OverlayFS | Kernel module | Very Low | Standard in all Linux distributions |
| eBPF (kernel 5.10+) | Kernel feature | Low | Primary path; explicit fallback to iptables/nftables available via `--network-backend` flag |
| OCI registries | Network service | Low | Standard protocol; multiple providers |
| Claude API | Cloud service | Medium | All features work without it; WASM inference as fallback |
| ruvnet ecosystem (MIT) | Open source | Low | All repos MIT licensed; fork if needed |

### Internal Dependencies

| Component | Depends On | Notes |
|-----------|-----------|-------|
| ferro-exec | Linux kernel namespaces, cgroups v2 | Core runtime — no other internal deps |
| ferro-store | ferro-exec (for running builds) | Image management |
| ferro-build | ferro-store (for layer caching) | Build system |
| ferro-net | eBPF (or iptables fallback) | Networking |
| ferro-mind | ruv-FANN (WASM), ruvector, optimizer, DAA (all Rust, native) | Intelligence layer — optional. claude-flow and agentic-flow (TypeScript) are upstream dependencies consumed via MCP subprocess, not compiled into the binary. |
| ferro-compose | ferro-exec, ferro-store, ferro-net | Multi-container orchestration |

---

## 8. Open Questions

| # | Question | Owner | Status | Target Resolution |
|---|----------|-------|--------|------------------|
| 1 | Should ferrocrate support Docker Volume Plugins for backwards compatibility, or introduce a new plugin format? | Lyle | Open | Phase 2 |
| 2 | What is the minimum viable claude-flow integration for Phase 1? | ruvnet | Open | Week 2 |
| 3 | Should the ferrofile.toml format support importing from Dockerfile, or are they completely separate? | Lyle | Open | Phase 2 |
| 4 | What kernel version should be the hard minimum? 5.10 covers eBPF basics but 5.15+ adds more features. | Engineering | Open | Phase 1 |
| 5 | How should AI feature telemetry work? Opt-in usage data improves models but raises privacy concerns. | Lyle | Open | Phase 2 |
| 6 | Should there be a "ferrocrate desktop" lightweight VM for macOS/Windows in Phase 1, or defer? | Lyle | Open | Phase 1 |
| 7 | What is the licensing model for community-contributed claude-flow agent configurations? | Lyle | Open | Phase 3 |
| 8 | Should ferrocrate implement Docker's Build Cloud equivalent, or partner with existing CI/CD services? | Lyle | Open | Phase 4 |
| 9 | Should claude-flow and agentic-flow be rewritten in Rust for single-language consistency? | Lyle | **Resolved: No** | — |

**Decision Record for Q9:** claude-flow (TypeScript, 13.8K stars) and agentic-flow (TypeScript) remain upstream TypeScript dependencies consumed via MCP protocol over stdio as subprocesses. Rationale: (1) Rewrite would take 3-6 months and fork from actively-maintained upstream, losing future improvements and 500K+ user community contributions. (2) Cold-path latency is dominated by LLM API calls at 2+ seconds — TypeScript runtime overhead is invisible. (3) Routing *algorithms* from agentic-flow are selectively ported to Rust in ferro-mind/router.rs; orchestration stays TypeScript. (4) Node.js is optional and lazy-loaded — only spawned for complex multi-agent diagnostics (~5% of operations). (5) Three binary tiers (Minimal/Standard/Full) allow users who don't want Node.js to avoid it entirely while still getting WASM-based AI.

---

## 9. Success Criteria for v1.0 Release

The v1.0 release is considered successful if:

1. **Functional parity (80% rule):** 80% of Docker CLI commands work identically, covering the 95% use case. Documented exceptions for the remaining 20%.
2. **Performance targets met:** All PERF-* requirements achieved and independently benchmarked.
3. **Zero critical security vulnerabilities:** No CVEs in the runtime itself at launch (tracked via cargo-audit and continuous fuzzing).
4. **Migration path validated:** 10+ real-world Docker projects successfully migrated using `ferrocrate migrate` with documented results.
5. **Community validation:** 100+ beta testers across all 5 persona types with >7/10 satisfaction score.
6. **AI layer adds measurable value:** Demonstrable resource savings or incident reduction in at least 3 beta environments with AI features enabled vs disabled.
