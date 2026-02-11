# FerroCrate User Stories

## Overview

This document captures all user stories organized by epic, with detailed acceptance criteria for each story. User stories represent end-user needs and guide development priorities.

---

## Epic 1: Container Runtime Core

**Epic Goal:** Deliver a production-ready container runtime that is OCI-compliant, memory-efficient, and secure by default.

### US-1.1: Run Any Docker Hub Image

**As a** developer,
**I want to** run any Docker Hub image with `ferrocrate run`,
**So that** I can use my existing container images without modification.

#### Acceptance Criteria
- [ ] `ferrocrate run nginx:latest` pulls and runs the official nginx image
- [ ] `ferrocrate run alpine:3.19 sh -c "echo hello"` outputs "hello"
- [ ] `ferrocrate run python:3.12-slim python -c "print(42)"` outputs "42"
- [ ] Multi-architecture images automatically select correct variant for host
- [ ] Private registry images work with configured credentials
- [ ] Container exit code is returned to caller
- [ ] Performance: container starts within 100ms for cached images

#### Technical Notes
- Must implement OCI Image Spec v1.1 parsing
- Must implement OCI Runtime Spec v1.2 execution
- Support manifest lists for multi-arch
- Handle authentication via docker config.json

---

### US-1.2: Zero Memory When Idle

**As a** DevOps engineer,
**I want** ferrocrate to consume zero memory when no containers are running,
**So that** it doesn't waste resources on my servers.

#### Acceptance Criteria
- [ ] No background daemon process required for container execution
- [ ] After `ferrocrate run --rm alpine echo done`, no ferrocrate processes remain
- [ ] RSS measurement shows 0 MB for ferrocrate components when idle
- [ ] Optional daemon (`ferro-mgr`) has <8 MB RSS when running with no containers
- [ ] Daemon is only started when user explicitly requests stateful features

#### Technical Notes
- Design as daemonless by default
- State stored in SQLite database on disk
- Container state directory at `/var/lib/ferrocrate/containers/`
- Daemon only needed for: restart policies, compose, AI features

---

### US-1.3: Rootless by Default

**As a** security engineer,
**I want** containers to run rootless by default,
**So that** a container escape doesn't grant root access to the host.

#### Acceptance Criteria
- [ ] `ferrocrate run alpine id` shows uid=0 (root inside container) but maps to unprivileged host uid
- [ ] No root privileges required to run containers as non-root user
- [ ] User namespace ID mapping from /etc/subuid and /etc/subgid
- [ ] `--privileged` flag requires explicit acknowledgment
- [ ] Container process cannot access host files outside mapped ranges
- [ ] All container operations work without `sudo`

#### Technical Notes
- User namespaces with ID mapping (default: 65536 UIDs)
- `/etc/subuid` format: `username:start:count`
- Fall back to rootful mode with `--rootful` flag only
- Document uid/gid mapping for troubleshooting

---

### US-1.4: Dockerfile Compatibility

**As a** developer,
**I want** `ferrocrate build` to accept my existing Dockerfiles,
**So that** I don't have to rewrite my build configurations.

#### Acceptance Criteria
- [ ] Parse and execute standard Dockerfile syntax
- [ ] Support directives: FROM, RUN, CMD, LABEL, MAINTAINER, EXPOSE, ENV, ADD, COPY, ENTRYPOINT, VOLUME, USER, WORKDIR, ARG, ONBUILD, STOPSIGNAL, HEALTHCHECK, SHELL
- [ ] Multi-stage builds with `COPY --from=stage` work correctly
- [ ] Build arguments (`ARG`) and environment variables (`ENV`) interpolate correctly
- [ ] `.dockerignore` file is respected
- [ ] Build output matches Docker BuildKit output layer-by-layer
- [ ] Document any directives with <100% compatibility (target: 95%+)

#### Technical Notes
- Dockerfile parser in Rust
- Layer cache with Blake3 hashing
- BuildKit-compatible output format
- Support heredoc syntax (Dockerfile 1.40+)

---

### US-1.5: docker-compose.yml Compatibility

**As a** platform engineer,
**I want** `ferrocrate compose` to parse my docker-compose.yml files,
**So that** I can migrate multi-service applications without changes.

#### Acceptance Criteria
- [ ] Parse docker-compose.yml version 3.x format
- [ ] `ferrocrate compose up` starts all services in dependency order
- [ ] `ferrocrate compose down` stops and removes all services
- [ ] Service-to-service DNS resolution works by service name
- [ ] Volume definitions create and mount persistent storage
- [ ] Network definitions create isolated networks
- [ ] Environment variable substitution from .env files
- [ ] Port mapping exposed correctly on host

#### Technical Notes
- YAML parser for compose format
- Dependency graph with topological sort
- Embedded DNS server for service discovery
- Support compose file includes and extensions

---

## Epic 2: Performance and Efficiency

**Epic Goal:** Achieve best-in-class performance with minimal resource overhead, enabling use cases from edge devices to large-scale deployments.

### US-2.1: Small Binary Size

**As an** edge developer,
**I want** the ferrocrate binary to be under 15MB,
**So that** it fits on resource-constrained devices.

#### Acceptance Criteria
- [ ] Release binary (x86_64, stripped) is <= 15 MB
- [ ] ARM64 binary is <= 15 MB
- [ ] RISC-V 64 binary is <= 15 MB
- [ ] Statically linked (no external dependencies)
- [ ] Optional: minimal build without AI features under 10 MB

#### Technical Notes
- Use `cargo bloat` to identify size contributors
- LTO (Link Time Optimization) enabled for release
- Strip debug symbols
- Consider `panic = "abort"` for smaller binary
- Feature flags for optional components

---

### US-2.2: Fast Container Startup

**As a** developer,
**I want** container startup under 100ms,
**So that** my development loop is fast.

#### Acceptance Criteria
- [ ] Cold start (image not cached): < 100ms after image pull
- [ ] Warm start (image cached): < 50ms
- [ ] Measured from API call to process running (ps output)
- [ ] Container with init system (tini) starts in < 75ms
- [ ] 100 container starts in under 10 seconds total
- [ ] Benchmark comparison vs runc and Docker

#### Technical Notes
- Optimize namespace creation path
- Pre-fork optimization for container processes
- Cache parsed OCI config
- Use io_uring for filesystem operations

---

### US-2.3: Image Deduplication

**As a** DevOps engineer,
**I want** file-level image deduplication,
**So that** storing 50 similar images doesn't consume 50x the disk space.

#### Acceptance Criteria
- [ ] Identical files across layers stored once
- [ ] Blake3 hash used for content addressing
- [ ] 40%+ storage reduction vs Docker for typical image sets
- [ ] Pull of similar image reuses existing layers
- [ ] Garbage collection removes unreferenced content
- [ ] Deduplication transparent to user (same UX)

#### Technical Notes
- Content-addressable storage in `/var/lib/ferrocrate/store/`
- Reference counting for each content blob
- Periodic GC or GC on image removal
- Report storage savings in `ferrocrate system df`

---

### US-2.4: Lazy Image Pulling

**As an** ML engineer,
**I want** lazy image pulling,
**So that** my 15GB model containers start before the full image downloads.

#### Acceptance Criteria
- [ ] Container starts after manifest fetch (not full layer download)
- [ ] File contents fetched on first access
- [ ] Background pull continues while container runs
- [ ] Fallback to full pull if lazy pull fails
- [ ] Configurable: `--pull=lazy|always|missing`
- [ ] Progress indicator shows lazy vs full pull status

#### Technical Notes
- FUSE filesystem for lazy loading
- Track which file ranges are fetched
- Estimate remaining download size
- Handle network interruption gracefully

---

## Epic 3: Intelligence Layer

**Epic Goal:** Provide AI-powered insights and automation that add measurable value without compromising reliability or privacy.

### US-3.1: Predictive Resource Allocation

**As a** DevOps engineer,
**I want** ferrocrate to predict container memory needs based on historical patterns,
**So that** I don't over-allocate or face OOM kills.

#### Acceptance Criteria
- [ ] Container metrics collected: CPU, memory, network, disk I/O
- [ ] WASM neural network predicts next-hour resource needs
- [ ] Prediction latency < 1ms (no external API calls)
- [ ] Recommendation shown in `ferrocrate inspect --predictions`
- [ ] Optional auto-tuning: `--auto-tune` adjusts limits based on predictions
- [ ] Accuracy metrics reported: >80% accuracy target for memory prediction

#### Technical Notes
- ruv-FANN WASM model for inference
- Training data from container metrics
- Feature: time of day, day of week, request rate
- Confidence interval for predictions

---

### US-3.2: Natural Language Crash Analysis

**As a** developer,
**I want to** ask ferrocrate "why did my container crash?" in natural language,
**So that** I get an intelligent analysis, not just "OOMKilled."

#### Acceptance Criteria
- [ ] `ferrocrate ask "why did my-container crash?"` returns detailed analysis
- [ ] Analysis includes: root cause, contributing factors, recommendations
- [ ] Context gathered from: logs, metrics, exit code, OOM events, config
- [ ] Response includes confidence level and evidence
- [ ] Option to route to Claude API for complex analysis
- [ ] AI opt-out flag disables this feature

#### Technical Notes
- Route to WASM model for simple cases
- Route to local LLM for moderate complexity
- Route to Claude API via claude-flow for complex cases
- Store analysis history for learning

---

### US-3.3: Automatic Resource Tuning

**As a** platform engineer,
**I want** ferrocrate to automatically adjust container resource limits based on observed usage,
**So that** I don't have to manually tune every service.

#### Acceptance Criteria
- [ ] `--auto-tune` flag enables automatic resource adjustment
- [ ] Memory limit adjusted within configured bounds
- [ ] CPU shares adjusted based on usage patterns
- [ ] Adjustments logged with reasoning
- [ ] Rollback if adjustment causes instability
- [ ] Configurable bounds: min/max memory, CPU

#### Technical Notes
- PID controller for smooth adjustments
- Hysteresis to prevent oscillation
- Learning rate configurable
- Persist adjustments across restarts

---

### US-3.4: Anomaly Detection

**As a** security engineer,
**I want** ferrocrate to detect anomalous container behavior,
**So that** I'm alerted without requiring external tools.

#### Acceptance Criteria
- [ ] Detect: unexpected network connections
- [ ] Detect: unusual syscall patterns
- [ ] Detect: abnormal resource usage spikes
- [ ] Alert severity: low, medium, high, critical
- [ ] Recommendation included with each alert
- [ ] Alerts viewable via `ferrocrate alerts list`
- [ ] Export to Prometheus alertmanager

#### Technical Notes
- Statistical anomaly detection (z-score)
- eBPF for syscall monitoring
- Baseline established during first N hours
- Configurable sensitivity

---

### US-3.5: AI Feature Opt-Out

**As a** developer,
**I want to** disable all AI features with a single flag,
**So that** I can use ferrocrate as a pure, predictable container runtime when I want.

#### Acceptance Criteria
- [ ] `--no-ai` flag disables all AI features for that command
- [ ] `ferrocrate config set ai.enabled=false` disables globally
- [ ] With AI disabled, runtime behavior is deterministic and auditable
- [ ] No AI-related code paths executed when disabled
- [ ] Performance identical to non-AI version
- [ ] Compile-time feature flag for minimal binary without AI code

#### Technical Notes
- Runtime flag check at AI feature entry points
- `#[cfg(feature = "ai")]` for compile-time exclusion
- Document behavior differences with/without AI

---

## Epic 4: Migration and Compatibility

**Epic Goal:** Make migration from Docker trivial with automated tooling and API compatibility.

### US-4.1: Automated Migration

**As a** DevOps engineer,
**I want** `ferrocrate migrate` to scan my Docker installation and generate equivalent ferrocrate configuration,
**So that** migration is automated.

#### Acceptance Criteria
- [ ] Scan Docker for: images, containers, volumes, networks, configs
- [ ] Generate migration report with recommendations
- [ ] Export images to ferrocrate format
- [ ] Generate docker-compose.yml equivalent ferro-compose.toml
- [ ] Preserve volume data
- [ ] Report incompatibilities and workarounds

#### Technical Notes
- Read from Docker's API and state directory
- Handle Docker-specific features gracefully
- Generate step-by-step migration guide

---

### US-4.2: Docker Socket Compatibility

**As a** developer,
**I want** ferrocrate to emulate the Docker socket,
**So that** tools like VS Code Dev Containers, Testcontainers, and docker-compose work without modification.

#### Acceptance Criteria
- [ ] `--docker-compat` flag starts Docker API server
- [ ] Socket at `/var/run/docker.sock` (or configurable)
- [ ] Tools using Docker SDK work unmodified
- [ ] VS Code Dev Containers extension works
- [ ] Testcontainers library works
- [ ] 95% API endpoint coverage (document gaps)

#### Technical Notes
- Implement Docker API v1.45+ endpoints
- JSON response format matches Docker exactly
- Handle edge cases in tool behavior

---

### US-4.3: CI/CD Drop-In Replacement

**As a** CI/CD engineer,
**I want** ferrocrate to work as a drop-in replacement in GitHub Actions workflows,
**So that** I don't have to rewrite my pipelines.

#### Acceptance Criteria
- [ ] Replace `docker` commands with `ferrocrate` aliases
- [ ] Container build steps work identically
- [ ] Container run steps work identically
- [ ] Service containers work in GitHub Actions
- [ ] Docker login action works with ferrocrate
- [ ] Multi-stage builds produce same artifacts

#### Technical Notes
- Create `docker` symlink to `ferrocrate`
- Document any GitHub Actions-specific quirks
- Provide GitHub Action wrapper for easy adoption

---

## Epic 5: Multi-Agent Orchestration

**Epic Goal:** Enable advanced autonomous operations through multi-agent coordination for complex scenarios.

### US-5.1: Fleet Health Monitoring

**As a** platform engineer,
**I want to** deploy claude-flow agents that monitor container health across my fleet,
**So that** remediation is coordinated automatically.

#### Acceptance Criteria
- [ ] Deploy monitoring agents via `ferrocrate fleet deploy`
- [ ] Agents collect health metrics from all containers
- [ ] Agents coordinate to avoid duplicate work
- [ ] Remediation actions logged with agent attribution
- [ ] Fleet status viewable via `ferrocrate fleet status`
- [ ] Agent communication encrypted

#### Technical Notes
- claude-flow MCP protocol for agent communication
- Distributed state via consensus
- Agent heartbeat and failure detection

---

### US-5.2: Self-Negotiated Resource Allocation

**As a** developer,
**I want** containers to negotiate their own resource allocation using DAA principles,
**So that** a spike in one service doesn't starve others.

#### Acceptance Criteria
- [ ] Containers publish resource needs and current usage
- [ ] Negotiation protocol determines fair allocation
- [ ] No single container can monopolize resources
- [ ] Negotiation completes in < 5 seconds
- [ ] Fallback to static limits if negotiation fails
- [ ] Negotiation history logged for auditing

#### Technical Notes
- DAA (Decentralized Autonomous Agents) principles
- Game-theoretic fair division algorithms
- Consensus for multi-container agreement

---

### US-5.3: Agentic Security Scanning

**As a** security engineer,
**I want** agentic security scanning that proactively identifies and patches vulnerabilities,
**So that** issues are resolved without manual intervention.

#### Acceptance Criteria
- [ ] Continuous scanning of running containers
- [ ] CVE database updated daily
- [ ] Critical vulnerabilities trigger alerts
- [ ] Automatic patch available via image rebuild
- [ ] Patching requires explicit approval (configurable)
- [ ] Audit trail of all security actions

#### Technical Notes
- Integration with NVD and OSV databases
- Agent coordinates with CI/CD for patching
- Rollback capability for failed patches
- Human-in-the-loop for critical systems

---

## Summary Statistics

| Epic | Stories | P0 Stories | P1 Stories | P2 Stories |
|------|---------|------------|------------|------------|
| 1: Runtime Core | 5 | 5 | 0 | 0 |
| 2: Performance | 4 | 2 | 2 | 0 |
| 3: Intelligence | 5 | 1 | 3 | 1 |
| 4: Migration | 3 | 1 | 2 | 0 |
| 5: Orchestration | 3 | 0 | 0 | 3 |
| **Total** | **20** | **9** | **7** | **4** |
