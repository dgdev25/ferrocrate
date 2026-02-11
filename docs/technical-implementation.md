# FerroCrate Technical Implementation Plan

## AI-Native Container Runtime — Engineering Specification

**Version:** 1.0 | **Date:** February 11, 2026 | **Status:** Draft
**Build Team:** Claude (AI Engineering) + ruvnet Ecosystem

---

## 1. Architecture Overview

### 1.1 System Architecture

```
                     ┌─────────────────────────────────────┐
                     │         ferrocrate CLI               │
                     │    (single static Rust binary)       │
                     │  run | build | compose | ask/mind    │
                     └──────────────┬────────────────────────┘
                                    │
        ┌───────────────┬───────────┼───────────┬──────────────┐
        ▼               ▼           ▼           ▼              │
╔═══════════════════════════════════════════════════════════╗   │
║            HOT PATH (Rust — every operation)              ║   │
║                                                           ║   │
║  ferro-exec    ferro-store    ferro-net    ferro-mind     ║   │
║  ───────────   ───────────    ─────────   (Rust core)    ║   │
║  Namespaces    Blake3 CAS     eBPF        WASM neural    ║   │
║  cgroups v2    Zstd layers    Bridge      inference       ║   │
║  seccomp       File dedup     DNS         ruvector        ║   │
║  pivot_root    Lazy pull      WireGuard   optimizer       ║   │
║  rootless      Registry                   DAA agents     ║   │
║                                                           ║   │
╚══════════════════════════════┬════════════════════════════╝   │
                               │                                │
                               ▼                                │
              ┌────────────────────────────────┐                │
              │     Linux Kernel (5.10+)       │     MCP protocol
              │  user_ns  cgroup2  overlayfs   │     (stdio JSON-RPC)
              │  eBPF  seccomp  io_uring       │     ~5% of operations
              └────────────────────────────────┘     lazy-loaded
                                                                │
                                                                ▼
                                              ┌──────────────────────────┐
                                              │  COLD PATH (TypeScript)  │
                                              │  Optional, subprocess    │
                                              │                          │
                                              │  claude-flow (upstream)  │
                                              │  Agent orchestration     │
                                              │  Multi-agent swarms      │
                                              │                          │
                                              │  agentic-flow (upstream) │
                                              │  LLM routing (algos      │
                                              │  ported to Rust; orch.   │
                                              │  stays TypeScript)       │
                                              │                          │
                                              │  Spawned on demand only  │
                                              │  Crash-isolated from     │
                                              │  container runtime       │
                                              └──────────────────────────┘
```

### 1.2 Design Principles

1. **Daemon-optional**: Core operations (run, exec, stop) work without any background process. A management daemon (ferro-mgr) is optional for features requiring persistent state.

2. **Library-first**: Each component is a Rust library crate with a thin CLI wrapper. This enables embedding ferrocrate in other systems and independent testing.

3. **Zero-copy where possible**: Cap'n Proto for IPC, memory-mapped files for image layers, zero-copy networking via eBPF.

4. **Fail-open for AI**: If ferro-mind fails, crashes, or is disabled, all container operations continue exactly as they would in a static runtime. AI is additive, never blocking.

5. **Single binary distribution**: The entire runtime compiles to one statically-linked binary using musl libc. No shared library dependencies.

6. **Polyglot by design, with a clear boundary**: The hot path (container lifecycle, image ops, WASM inference) is pure Rust. The cold path (agent orchestration, LLM API calls, prompt construction) stays in TypeScript via upstream claude-flow and agentic-flow. Communication is via MCP protocol over stdio. This keeps us on upstream ruvnet releases, avoids a 3-6 month rewrite, and optimizes languages to their strengths. LLM calls dominate cold-path latency at 2+ seconds — TypeScript's runtime overhead is invisible at that scale.

---

## 2. Crate Structure

```
ferrocrate/
├── Cargo.toml                    # Workspace root
├── crates/
│   ├── ferro-exec/               # Container runtime (OCI compliant)
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── namespace.rs      # Linux namespace setup
│   │   │   ├── cgroup.rs         # cgroups v2 management
│   │   │   ├── rootfs.rs         # pivot_root, overlay mount
│   │   │   ├── seccomp.rs        # Seccomp BPF profiles
│   │   │   ├── capabilities.rs   # Linux capabilities
│   │   │   ├── user_ns.rs        # User namespace / rootless
│   │   │   ├── process.rs        # Container process lifecycle
│   │   │   ├── spec.rs           # OCI runtime spec parsing
│   │   │   └── hooks.rs          # OCI lifecycle hooks
│   │   └── Cargo.toml
│   │
│   ├── ferro-store/              # Image and layer management
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── content.rs        # Content-addressable store (Blake3)
│   │   │   ├── layer.rs          # Layer manifest and management
│   │   │   ├── image.rs          # OCI image spec handling
│   │   │   ├── registry.rs       # Registry client (pull/push)
│   │   │   ├── lazy.rs           # FUSE-based lazy pulling
│   │   │   ├── compress.rs       # Zstd compression/decompression
│   │   │   └── gc.rs             # Garbage collection
│   │   └── Cargo.toml
│   │
│   ├── ferro-build/              # Image builder
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── dockerfile.rs     # Dockerfile parser
│   │   │   ├── ferrofile.rs      # ferrofile.toml parser
│   │   │   ├── builder.rs        # Build execution engine
│   │   │   ├── cache.rs          # Build cache (file-level)
│   │   │   └── context.rs        # Build context handling
│   │   └── Cargo.toml
│   │
│   ├── ferro-net/                # Container networking
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── bridge.rs         # Bridge network driver
│   │   │   ├── veth.rs           # Virtual ethernet pairs
│   │   │   ├── ebpf.rs           # eBPF program management
│   │   │   ├── dns.rs            # Embedded DNS resolver
│   │   │   ├── portmap.rs        # Port mapping
│   │   │   └── wireguard.rs      # WireGuard overlay
│   │   ├── bpf/                  # eBPF C programs
│   │   │   ├── container_fwd.c
│   │   │   └── policy.c
│   │   └── Cargo.toml
│   │
│   ├── ferro-mind/               # AI intelligence layer
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── wasm_inference.rs # ruv-FANN WASM runtime
│   │   │   ├── predictor.rs      # Resource prediction engine
│   │   │   ├── anomaly.rs        # Anomaly detection
│   │   │   ├── router.rs         # Cost-tiered AI routing
│   │   │   ├── memory.rs         # ruvector operational memory
│   │   │   ├── agents.rs         # claude-flow agent integration
│   │   │   ├── optimizer.rs      # Memory optimization (from ruvnet/optimizer)
│   │   │   └── explainer.rs      # AI decision explainability
│   │   ├── wasm/                 # Pre-compiled WASM modules
│   │   │   ├── resource_predictor.wasm
│   │   │   └── anomaly_detector.wasm
│   │   └── Cargo.toml
│   │
│   ├── ferro-compose/            # Multi-container orchestration
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── parser.rs         # docker-compose.yml parser
│   │   │   ├── graph.rs          # Service dependency graph
│   │   │   ├── lifecycle.rs      # Service lifecycle management
│   │   │   └── scale.rs          # Service scaling
│   │   └── Cargo.toml
│   │
│   ├── ferro-mgr/                # Optional management daemon
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── api.rs            # Cap'n Proto + HTTP/JSON API
│   │   │   ├── restart.rs        # Restart policy enforcement
│   │   │   ├── events.rs         # Container event stream
│   │   │   └── docker_compat.rs  # Docker socket emulation
│   │   └── Cargo.toml
│   │
│   └── ferro-cli/                # CLI binary (thin wrapper)
│       ├── src/
│       │   ├── main.rs
│       │   ├── commands/
│       │   │   ├── run.rs
│       │   │   ├── build.rs
│       │   │   ├── compose.rs
│       │   │   ├── images.rs
│       │   │   ├── network.rs
│       │   │   ├── volume.rs
│       │   │   ├── mind.rs       # AI commands
│       │   │   └── migrate.rs    # Docker migration tool
│       │   └── output.rs         # Formatting (table, JSON, color)
│       └── Cargo.toml
│
├── tests/                        # Integration tests
│   ├── oci_compliance/
│   ├── docker_compat/
│   ├── performance/
│   └── ai_integration/
│
└── docs/
    ├── architecture/
    ├── migration/
    └── api/
```

### 2.1 Key Rust Dependencies

```toml
[workspace.dependencies]
# System interfaces
nix = { version = "0.29", features = ["mount", "sched", "signal", "user"] }
libc = "0.2"
caps = "0.5"                    # Linux capabilities
seccompiler = "0.4"             # Seccomp BPF

# Async runtime
tokio = { version = "1", features = ["full"] }
tokio-uring = "0.5"             # io_uring for file operations

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"                    # ferrofile.toml
capnp = "0.20"                  # Cap'n Proto IPC

# Hashing and compression
blake3 = "1"
zstd = "0.13"

# Networking
aya = "0.13"                    # eBPF from Rust
rtnetlink = "0.14"              # Netlink for network config
hickory-dns = "0.25"            # DNS resolver

# OCI specs
oci-spec = "0.7"

# WASM runtime (for ferro-mind)
wasmtime = "27"
wasmtime-wasi = "27"

# CLI
clap = { version = "4", features = ["derive"] }
indicatif = "0.17"              # Progress bars
comfy-table = "7"               # Table formatting

# Storage
sled = "0.34"                   # Embedded database
fuser = "0.15"                  # FUSE for lazy pulling

# Observability
tracing = "0.1"
tracing-subscriber = "0.3"
prometheus-client = "0.23"

# Testing
proptest = "1"
criterion = "0.5"
```

### 2.2 Build Configuration

```toml
[profile.release]
lto = "fat"
codegen-units = 1
opt-level = 3
strip = true
panic = "abort"

# Build: RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target x86_64-unknown-linux-musl
```

---

## 3. Core Component Implementation

### 3.1 ferro-exec: Container Creation Flow

```
ferrocrate run alpine echo hello
        │
        ▼
┌──────────────────────┐
│ 1. Parse OCI spec    │  Convert CLI flags → OCI runtime config
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ 2. Prepare rootfs    │  Extract/mount image layers via ferro-store
│    (OverlayFS)       │  lower=layers, upper=writable, merged=rootfs
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ 3. Create cgroup     │  /sys/fs/cgroup/ferrocrate/<container-id>/
│    (cgroups v2)      │  Set memory.max, cpu.weight, pids.max
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ 4. clone3() with     │  CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET
│    namespace flags    │  CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWUSER
└──────────┬───────────┘
           ▼  (in child process)
┌──────────────────────┐
│ 5. pivot_root        │  Switch to new root, mount /proc, /sys, /dev
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ 6. Apply security    │  Drop caps, apply seccomp, set no_new_privs
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ 7. execve()          │  Execute container entrypoint
└──────────────────────┘
```

### 3.2 ferro-store: Content-Addressable Image Store

Key data structures:

```rust
/// A layer is a manifest of file hashes — not a tarball
#[derive(Serialize, Deserialize)]
pub struct LayerManifest {
    pub files: BTreeMap<PathBuf, FileEntry>,
    pub removals: Vec<PathBuf>,  // Whiteout files
}

#[derive(Serialize, Deserialize)]
pub struct FileEntry {
    pub content_hash: Blake3Hash,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub link_target: Option<PathBuf>,
}
```

Storage layout:
```
~/.ferrocrate/
├── store/
│   ├── objects/            # Content-addressed (Blake3)
│   │   ├── a3/b2/a3b2...  # Large files (≥4KB)
│   │   └── ...
│   ├── small.db            # Sled DB for small files (<4KB)
│   ├── manifests/          # Layer manifests (JSON)
│   └── images/             # Image configs and indexes
├── overlays/               # OverlayFS directories per container
│   └── <container-id>/
│       ├── lower/          # Symlinks to store objects
│       ├── upper/          # Writable layer
│       ├── work/           # OverlayFS work dir
│       └── merged/         # Union mount point
├── volumes/                # Named volumes
├── networks/               # Network configuration
└── mind/                   # ferro-mind state
    ├── ruvector.db         # Operational pattern memory
    ├── models/             # WASM neural net models
    └── decisions.log       # AI decision audit trail
```

### 3.3 ferro-mind: Cost-Tiered AI Router

```rust
pub enum DecisionComplexity {
    /// Resource allocation, restart → WASM neural net (free, <1ms)
    Routine,
    /// Log analysis, anomaly investigation → Local LLM (~100ms)
    Moderate,
    /// Multi-service debugging → Claude API (~2s)
    Complex,
}

impl AiRouter {
    pub async fn decide(&self, context: &DecisionContext) -> Result<AiDecision> {
        let complexity = self.classify(context);

        match complexity {
            Routine => self.wasm_engine.predict(&context.features()).await,
            Moderate => match &self.local_llm {
                Some(llm) => llm.analyze(context).await,
                None => self.wasm_engine.predict(&context.features()).await,
            },
            Complex => match &self.claude_api {
                Some(api) => api.analyze_incident(context).await,
                None => {
                    tracing::warn!("Complex analysis requested but Claude API not configured");
                    self.wasm_engine.predict(&context.features()).await
                }
            },
        }
    }
}
```

### 3.4 ferro-net: eBPF Networking

```
Container Network Setup (no iptables):

1. Create veth pair: host-side (veth<id>) ↔ container-side (eth0)
2. Move container-side into network namespace
3. Assign IPs via netlink
4. Attach eBPF TC program to host-side veth
   - Handles forwarding between containers
   - Handles port mapping (replaces DNAT/SNAT rules)
   - Enforces network policies
5. Register in embedded DNS resolver
```

---

## 4. Implementation Phases

### Phase 1: ferro-exec — OCI Runtime (Weeks 1-6)

**Goal:** Drop-in runc replacement that works with existing Docker/containerd.

| Week | Deliverable |
|------|------------|
| 1-2 | Project scaffolding, CI/CD, clone3() with namespace flags, user namespace for rootless |
| 2-3 | cgroups v2 management, OverlayFS mount, pivot_root |
| 3-4 | Process lifecycle (start/stop/kill), seccomp BPF filter, capabilities |
| 4-5 | OCI runtime spec compliance, lifecycle hooks, state management |
| 5-6 | OCI compliance test suite, performance benchmarks vs runc |

**Exit Criteria:** Passes OCI runtime-tools suite; startup <100ms; overhead <2MB per container; rootless works.

### Phase 2: ferro-store + ferro-cli (Weeks 7-14)

**Goal:** ferrocrate pull and ferrocrate run work end-to-end without Docker installed.

| Week | Deliverable |
|------|------------|
| 7-8 | Content-addressable store with Blake3, file-level dedup |
| 8-9 | Registry client (OCI Distribution spec, Docker Hub auth) |
| 9-10 | Image layer management, OverlayFS mount from store |
| 10-11 | Zstd compression, FUSE skeleton for lazy pulling |
| 11-12 | CLI: run, pull, push, images, ps, logs, exec, stop, rm |
| 12-14 | Docker compatibility testing (top 100 images) |

**Exit Criteria:** Top 50 Docker Hub images work; 40%+ storage savings; Docker-familiar CLI UX.

### Phase 3: ferro-build + ferro-compose (Weeks 15-20)

**Goal:** Build images and run multi-container apps.

| Week | Deliverable |
|------|------------|
| 15-16 | Dockerfile parser, build engine (95% directive coverage) |
| 16-17 | Multi-stage builds, file-level build cache |
| 17-18 | ferrofile.toml declarative format |
| 18-19 | Compose parser (docker-compose.yml v3), dependency graph |
| 19-20 | Integration testing with real-world compose projects |

**Exit Criteria:** 95% Dockerfile compat; compose files work without modification; build within 15% of BuildKit.

### Phase 4: ferro-net (Weeks 21-24)

**Goal:** Container networking without iptables.

| Week | Deliverable |
|------|------------|
| 21-22 | Bridge networking, veth pairs, embedded DNS resolver |
| 22-23 | eBPF TC programs for forwarding and port mapping |
| 23-24 | Custom networks, cross-container communication, isolation testing |

**Exit Criteria:** Networking works; zero iptables rules; DNS resolves container names.

### Phase 5: ferro-mind (Weeks 25-32)

**Goal:** Embedded AI intelligence layer.

| Week | Deliverable |
|------|------------|
| 25-26 | wasmtime integration, ruv-FANN model loading, resource prediction |
| 26-28 | Historical pattern learning, anomaly detection, confidence scoring |
| 28-29 | WASM → local LLM → Claude API routing logic |
| 29-30 | ruvector operational memory (pattern storage and retrieval) |
| 30-31 | claude-flow MCP bridge, diagnostic swarm spawning |
| 31-32 | Decision audit log, explain command, --no-ai flag |

**Exit Criteria:** WASM inference <1ms; measurable resource savings; clean AI disable; decisions logged.

### Phase 6: Hardening + Release (Weeks 33-36)

| Week | Deliverable |
|------|------------|
| 33-34 | Security audit, cargo-fuzz on all unsafe blocks, penetration testing |
| 34-35 | PGO optimization, benchmark suite, regression tests |
| 35-36 | Documentation, migration guide, binary releases, install scripts |

---

## 5. Testing Strategy

### 5.1 Test Pyramid

```
                    ┌───────────┐
                    │  E2E      │   Real-world Docker project migrations
                    │  (10%)    │   Full compose stack deployments
                   ┌┴───────────┴┐
                   │ Integration  │  OCI compliance suite
                   │ (30%)       │  Docker API compatibility
                  ┌┴─────────────┴┐
                  │  Unit Tests    │  Per-crate unit tests
                  │  (60%)        │  Property-based tests (proptest)
                  └───────────────┘
```

### 5.2 Critical Test Categories

1. **OCI Compliance** — Official runtime-tools validation suite
2. **Docker Compatibility** — Top 100 images, compose examples, API endpoints
3. **Security** — Escape attempts, fuzzing unsafe code, rootless verification
4. **Performance Regression** — Criterion benchmarks on every PR, baselines vs Docker/Podman/runc
5. **AI Layer** — WASM accuracy, graceful degradation, cost tier routing, explainability

### 5.3 CI Pipeline

```yaml
jobs:
  test:
    matrix: [x86_64-gnu, x86_64-musl, aarch64-gnu]
    steps: [fmt, clippy, test --all-features, test --no-default-features]

  security:
    steps: [cargo audit, cargo deny, cargo fuzz (5 min)]

  benchmark:
    steps: [cargo bench, regression detection]

  oci-compliance:
    steps: [build, run oci-runtime-tools]

  docker-compat:
    steps: [build, run top-100 images, run compose suite]
```

---

## 6. Distribution

### 6.1 Installation

```bash
curl -fsSL https://get.ferrocrate.com | sh
brew install ferrocrate          # macOS
apt install ferrocrate           # Debian/Ubuntu
cargo install ferrocrate         # From source
```

### 6.2 Binary Size Targets

| Variant | Language | Features | Size | AI Capability |
|---------|----------|----------|------|---------------|
| Minimal | Pure Rust | ferro-exec only | ~5 MB | None |
| Standard | Pure Rust | exec + store + build + compose + net | ~12 MB | None |
| Full | Pure Rust | Standard + ferro-mind (WASM + ruvector) | ~18 MB | WASM neural inference (free, <1ms) |
| Full + Agents | Rust + TypeScript (bundled) | Full + claude-flow + agentic-flow (MCP subprocess) | ~45 MB | WASM + multi-agent swarms + Claude API diagnostics |

Note: The first three tiers are 100% Rust with zero Node.js dependency. The "Full + Agents" tier bundles claude-flow as a self-contained subprocess (optionally compiled via Bun/pkg to eliminate visible Node.js runtime). TypeScript components are crash-isolated from the container runtime — if the subprocess fails, all container operations continue normally.

### 6.3 Release Cadence

- **Nightly:** Automated from main branch
- **Monthly:** Stable releases with changelog
- **LTS:** Every 6 months, 18-month support window
- **Security patches:** Within 24 hours for critical CVEs

---

## 7. Dependency Versioning & Upgrade Strategy

FerroCrate consumes ruvnet ecosystem components via two fundamentally different integration paths, each requiring its own upgrade strategy.

### 7.1 Rust Dependencies (Compiled Into Binary)

**Components:** ruvector, ruv-FANN, optimizer, DAA

These are standard Cargo crate dependencies compiled directly into the FerroCrate binary. Upgrade process:

**Version pinning:** All ruvnet Rust dependencies are pinned to exact versions in Cargo.toml (e.g., `ruvector = "=0.7.3"`), never ranges. Breaking changes require deliberate, tested version bumps.

**Automated PR workflow:**
1. Dependabot or RenovateBot monitors ruvnet crate releases
2. New version triggers an automated PR in the FerroCrate repo
3. CI runs the full gate: OCI compliance suite, Docker compat (top 100 images), performance benchmarks (Criterion regression check), AI accuracy tests
4. If CI passes → developer reviews changelog for API surface changes → merge
5. If CI fails → evaluate: adapt FerroCrate code, skip version, or open issue upstream

**Cadence:** Monthly for non-security updates. Immediate (< 24 hours) for security patches.

**Risk:** Low. Cargo enforces semantic versioning — breaking changes require major version bumps, and Cargo won't auto-upgrade across major versions. If ruvector 0.8.0 introduces a regression, FerroCrate stays on 0.7.x until it's resolved.

### 7.2 TypeScript Dependencies (MCP Subprocess)

**Components:** claude-flow, agentic-flow

These are not compiled into FerroCrate. They run as external subprocesses communicating via MCP protocol over stdio (JSON-RPC). The MCP protocol is the version firewall — as long as the subprocess speaks MCP correctly, FerroCrate doesn't care what version is running on the other side of the pipe.

**Three deployment models:**

**Model A — Bundled (default, recommended):** FerroCrate ships a specific, integration-tested version of claude-flow inside the "Full + Agents" binary tier. Each FerroCrate release certifies a specific claude-flow version. Users get a known-good, tested combination.

**Model B — Bring Your Own (power users):** Users install claude-flow globally or point FerroCrate at a custom installation via config:
```toml
# ~/.config/ferrocrate/config.toml
[mind.claude-flow]
path = "/usr/local/bin/claude-flow"    # Custom installation
version-check = true                   # Warn if untested version
```
Users can run bleeding-edge claude-flow without waiting for FerroCrate to bundle it. Compatibility is "community-tested" rather than "certified."

**Model C — Auto-update with rollback (Phase 3+):** FerroCrate checks for new claude-flow releases on a configurable schedule, downloads the update, runs the MCP contract smoke test, and promotes if passing. If the smoke test fails, it stays on the current version and logs a warning. Requires:
```toml
[mind.claude-flow]
auto-update = true
check-interval = "weekly"
rollback-on-failure = true
```

### 7.3 MCP Contract Test Suite

This is the critical gating mechanism for all TypeScript dependency upgrades. It defines the exact MCP tool calls FerroCrate makes and the expected response shapes:

```
Test: swarm_init
  Input:  { topology: "hierarchical", maxAgents: 5 }
  Expect: { id: string, status: "ready", agentCount: 5 }

Test: agent_spawn
  Input:  { type: "diagnostics", name: "oom-analyzer", task: "analyze OOM in container abc123" }
  Expect: { id: string, status: "running" }

Test: task_orchestrate
  Input:  { task: "diagnose high memory usage", context: { container_id: "abc123", metrics: {...} } }
  Expect: { result: string, confidence: number > 0.0, actions: array }

Test: memory_search
  Input:  { text: "container restart patterns", k: 3 }
  Expect: { results: array, length >= 1, each: { score: number > 0.0, content: string } }

Test: graceful_degradation
  Input:  Kill subprocess mid-request
  Expect: ferro-mind falls back to WASM inference, no container operations affected
```

Any version of claude-flow or agentic-flow that passes this contract suite is compatible with FerroCrate. This fully decouples FerroCrate's release cycle from ruvnet's.

### 7.4 Compatibility Matrix

Published at docs.ferrocrate.com/compatibility and updated with each release:

| FerroCrate | claude-flow | agentic-flow | ruvector | ruv-FANN | DAA | Status |
|-----------|-------------|-------------|----------|----------|-----|--------|
| 1.0.x | 3.1.x – 3.2.x | 1.0.x | 0.7.x | 0.5.x | 0.3.x | Certified |
| 1.0.x | 3.3.x | 1.1.x | 0.8.x | 0.5.x | 0.3.x | Community-tested |
| 1.1.x | 3.3.x+ | 1.1.x | 0.8.x | 0.6.x | 0.4.x | Certified |

**Certified** = Integration-tested by FerroCrate team, bundled in official release.
**Community-tested** = Reported working by community members, not officially bundled.

### 7.5 Ported Algorithm Versioning

The routing algorithms ported from agentic-flow to Rust (in `ferro-mind/src/router.rs`) become FerroCrate-owned code once ported. They no longer auto-update with upstream releases.

**Tracking convention:**
```rust
// ferro-mind/src/router.rs

/// Cost-tiered LLM routing algorithm
/// Ported from: agentic-flow v1.0.3 (src/routing/cost-tier.ts)
/// Port date: 2026-03-15
/// Upstream changes reviewed through: agentic-flow v1.2.0
///
/// Next review due: 2026-06-15 (quarterly)
pub fn route_by_cost_tier(context: &DecisionContext) -> RoutingTier {
    // ...
}
```

**Quarterly review:** Check agentic-flow changelog for routing algorithm changes. Port updates only when the algorithm genuinely improves — routing math stabilizes quickly and rarely changes fundamentally.

### 7.6 `ferrocrate doctor` Command

Built-in diagnostics command that checks dependency health:

```bash
$ ferrocrate doctor

FerroCrate v1.0.2
──────────────────────────────────

Rust components (compiled):
  ✓ ruvector      0.7.3   (certified)
  ✓ ruv-FANN      0.5.1   (certified)
  ✓ optimizer     0.2.0   (certified)
  ✓ DAA           0.3.4   (certified)

TypeScript components (subprocess):
  ✓ claude-flow   3.2.1   (certified, bundled)
  ⚠ agentic-flow  1.1.0   (community-tested, newer than bundled 1.0.3)

MCP contract:
  ✓ swarm_init         passed (12ms)
  ✓ agent_spawn        passed (8ms)
  ✓ task_orchestrate   passed (2,341ms)
  ✓ memory_search      passed (45ms)
  ✓ graceful_degradation  passed

Ported algorithms:
  ⚠ router.rs ported from agentic-flow v1.0.3
    Upstream is now v1.1.0 — review recommended

Kernel: 5.15.0-91-generic ✓
cgroups v2: enabled ✓
User namespaces: enabled ✓
eBPF: supported ✓

Status: Healthy (2 advisories)
```

### 7.7 Upgrade Policy Summary

| Dependency Type | Pin Strategy | Update Trigger | Gate | Cadence |
|----------------|-------------|----------------|------|---------|
| Rust crates (ruvector, ruv-FANN, etc.) | Exact version pin | Dependabot PR | Full CI suite | Monthly (security: immediate) |
| TypeScript (claude-flow, agentic-flow) | Bundled certified version | MCP contract test suite | Contract tests + integration tests | Per FerroCrate release |
| Ported algorithms (router.rs) | Annotated source version | Manual changelog review | Unit tests + accuracy benchmarks | Quarterly |

---

## 8. Observability

### 7.1 Prometheus Metrics

```
ferrocrate_containers_total{state="running|paused|stopped"}
ferrocrate_container_start_duration_seconds
ferrocrate_container_memory_bytes{container_id}
ferrocrate_container_cpu_usage_seconds_total{container_id}
ferrocrate_store_objects_total
ferrocrate_store_dedup_ratio
ferrocrate_image_pull_duration_seconds
ferrocrate_ai_decisions_total{tier="wasm|local_llm|claude_api"}
ferrocrate_ai_decision_duration_seconds{tier}
ferrocrate_ai_prediction_accuracy
ferrocrate_network_rx_bytes_total{container_id}
ferrocrate_network_tx_bytes_total{container_id}
```

---

## 9. Security Architecture

### 9.1 Defense in Depth

```
Layer 1: Rust Memory Safety
   │  No buffer overflows, use-after-free, data races
   ▼
Layer 2: Rootless by Default
   │  User namespaces — container root ≠ host root
   ▼
Layer 3: Capability Dropping
   │  All capabilities dropped; only requested caps granted
   ▼
Layer 4: Seccomp BPF
   │  Syscall whitelist — only permitted syscalls execute
   ▼
Layer 5: No-New-Privileges
   │  setuid/setgid binaries cannot escalate
   ▼
Layer 6: Read-Only Rootfs (optional, default in prod mode)
   ▼
Layer 7: eBPF Network Policy
   │  Packet-level enforcement without iptables
   ▼
Layer 8: AI Anomaly Detection (ferro-mind)
   │  Behavioral monitoring, automatic alerting
   ▼
Layer 9: Audit Logging
      Every operation recorded, immutable log
```

### 9.2 Unsafe Code Policy

All unsafe code blocks must:
1. Be isolated in dedicated modules with safe public APIs
2. Include a `// SAFETY:` comment explaining the invariant
3. Have dedicated fuzz tests targeting the unsafe boundary
4. Be reviewed by two engineers before merging
5. Be documented in the security audit manifest

Expected unsafe locations: namespace.rs, rootfs.rs, cgroup.rs, ebpf.rs, WASM host functions.

---

## 10. ruvnet Component Integration Map

| Repository | Language | Integration Type | What We Use | What We Skip | Rewrite to Rust? |
|-----------|----------|-----------------|-------------|--------------|-----------------|
| **claude-flow** (13.8K★) | TypeScript | Upstream as-is, MCP protocol bridge (subprocess) | Swarm init, agent spawning, hierarchical topology, stream-JSON chaining, SQLite memory | GitHub agents, SWE-bench, UI | **No** — stays TypeScript. LLM API calls dominate latency (2s+); TS overhead invisible. Rewrite would fork from 13.8K-star upstream, losing future updates and community contributions. |
| **agentic-flow** (256★) | TypeScript | Hybrid: algorithms ported to Rust, orchestration stays TypeScript upstream | Cost-tiered LLM routing decision algorithm (ported to ferro-mind router.rs), SONA learning patterns (ported to Rust) | Orchestration layer, prompt management (stays TypeScript) | **Partial** — routing algorithm math ported to Rust for ferro-mind's cost-tier router. Orchestration stays TypeScript upstream. |
| **ruvector** (271★) | Rust | Native crate dependency | HNSW index, Raft consensus (Phase 4), GNN attention, SONA learning | PostgreSQL extension, Cypher queries | N/A — already Rust |
| **ruv-FANN** (297★) | Rust | WASM module (compiled from Rust) | Neural net creation/inference, WASM target, SIMD distance calc | Python compatibility layer | N/A — already Rust |
| **optimizer** (15★) | Rust | Algorithm extraction (Rust code) | PageRank process scoring, leak detection, AI workload detection, Docker monitoring | Windows-specific features, tray UI | N/A — already Rust |
| **DAA** (205★) | Rust | Selective crate dependency | Agent lifecycle, rule-based decisions, audit trails, P2P comms | Token economy, blockchain, darknet | N/A — already Rust |
| **midstream** (37★) | Architecture reference | Real-time streaming analysis patterns | Direct integration (Phase 4+) |
| **QuDAG** (124★) | Crypto primitives only | ML-KEM-768, BLAKE3, quantum-resistant key exchange | Full DAG consensus, darknet routing |
| **agentic-security** (18★) | Reference + adapted algorithms | Security scanning patterns, vulnerability detection | Python implementation |
| **code-mesh** (32★) | Phase 4+ consideration | Distributed execution for remote builds | Not in initial phases |

Pre-trained WASM models shipped with ferrocrate:
- `resource_predictor.wasm` — Predicts memory/CPU from usage history
- `anomaly_detector.wasm` — Detects abnormal resource patterns
- `restart_advisor.wasm` — Recommends restart strategy from failure patterns

---

## 11. Technical Decisions

| # | Decision | Choice | Rationale |
|---|----------|--------|-----------|
| TD-1 | Async runtime | tokio | Ecosystem breadth, io_uring support via tokio-uring |
| TD-2 | IPC protocol | Cap'n Proto | Zero-copy deserialization, no codegen runtime dependency |
| TD-3 | Embedded DB | sled | Pure Rust, embedded, no FFI, concurrent-safe |
| TD-4 | eBPF library | aya | Pure Rust, best maintained, active community |
| TD-5 | WASM runtime | wasmtime | Bytecode Alliance backing, WASI support, SIMD |
| TD-6 | Start from youki? | Clean-room | Avoid inherited architectural debt; use as reference only |
| TD-7 | CLI framework | clap | Feature-rich, derive macros, shell completion |
| TD-8 | Lazy pull mechanism | FUSE | More flexible than eStargz, works with any registry |
| TD-9 | Log storage | File + optional sled index | Open — needs benchmarking |
| TD-10 | Docker API scope | 80% coverage | Document gaps transparently |
| TD-11 | macOS/Windows | Lightweight VM (deferred) | Like Lima; Phase 4+ |
| TD-12 | Plugin system | WASM plugins | Sandboxed, portable, no dynamic linking |

---

## 12. Risk Register

| Risk | Prob | Impact | Mitigation |
|------|------|--------|------------|
| Namespace edge cases | High | Medium | OCI compliance suite; reference youki/crun for known issues |
| eBPF rejected by older kernels | Medium | Medium | Graceful iptables fallback; detect kernel version |
| WASM inference accuracy insufficient | Medium | Low | Advisory-only with confidence thresholds; low-confidence → safe defaults |
| Blake3 store causes corruption | Low | Critical | Checksums on every read; atomic writes; validation tool |
| claude-flow Node.js adds bloat | Medium | Low | Optional (Phase 5 only); core is pure Rust |
| Unsafe code vulnerabilities | Medium | Critical | Fuzz testing, minimal surface, two-reviewer policy |
| Docker API gaps frustrate users | High | Medium | Transparent errors; compatibility dashboard |
| Performance regression over time | Medium | Medium | Criterion in CI; performance budgets; auto regression detection |

---

## 13. Development Infrastructure

### Required Tools

```bash
rustup default stable
rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-gnu wasm32-wasi
cargo install cargo-fuzz cargo-audit cargo-deny cargo-criterion bpf-linker wasm-pack
sudo apt install clang llvm libelf-dev   # For eBPF
```

### Documentation Stack

- **mdBook** — User docs at docs.ferrocrate.com
- **cargo doc** — API documentation
- **ADRs** — Architecture Decision Records in /docs/architecture/
- **Runbooks** — Operational guides in /docs/operations/

---

## 14. Glossary

| Term | Definition |
|------|-----------|
| **OCI** | Open Container Initiative — standards body for container image and runtime specifications |
| **CRI** | Container Runtime Interface — Kubernetes API for container runtimes |
| **cgroups v2** | Linux unified control group hierarchy for resource management |
| **eBPF** | Extended Berkeley Packet Filter — programmable kernel-level packet processing and tracing |
| **WASM** | WebAssembly — portable binary instruction format for sandboxed execution |
| **Blake3** | Cryptographic hash function, 5-14x faster than SHA-256 |
| **Zstd** | Zstandard compression algorithm, 2-3x faster than gzip |
| **Cap'n Proto** | Zero-copy serialization protocol |
| **MCP** | Model Context Protocol — standardized interface for AI tool integration |
| **DAA** | Decentralized Autonomous Application — self-managing AI agent framework |
| **HNSW** | Hierarchical Navigable Small World — approximate nearest neighbor index |
| **SONA** | Self-Optimizing Neural Architecture — adaptive learning from ruvector |
| **PGO** | Profile-Guided Optimization — compiler optimization using runtime profiling data |
| **musl** | Lightweight C standard library used for static linking on Linux |
