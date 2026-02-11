# FerroCrate Architecture

**SPARC Phase:** Architecture
**Version:** 1.0
**Date:** February 11, 2026
**Status:** Draft

---

## 1. System Overview

FerroCrate is a modular container runtime composed of eight primary components, each implemented as a separate Rust crate for independent testing and potential reuse.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           FerroCrate Runtime                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                         ferro-compose                                │    │
│  │            (Multi-container orchestration, docker-compose)           │    │
│  └──────────────────────────────┬──────────────────────────────────────┘    │
│                                 │                                           │
│  ┌──────────────────────────────┼──────────────────────────────────────┐    │
│  │                              │             ferro-mind                │    │
│  │                    (AI layer - optional, zero-cost when disabled)   │    │
│  └──────────────────────────────┼──────────────────────────────────────┘    │
│                                 │                                           │
│         ┌───────────────────────┼───────────────────────┐                  │
│         │                       │                       │                   │
│         ▼                       ▼                       ▼                   │
│  ┌─────────────┐         ┌─────────────┐         ┌─────────────┐          │
│  │  ferro-exec │◄───────►│ ferro-store │◄───────►│  ferro-net  │          │
│  │ (Container  │         │   (Image    │         │ (Networking │          │
│  │  Runtime)   │         │  Management)│         │  & eBPF)    │          │
│  └──────┬──────┘         └──────┬──────┘         └──────┬──────┘          │
│         │                       │                       │                   │
│         └───────────────────────┼───────────────────────┘                  │
│                                 │                                           │
│  ┌──────────────────────────────┴──────────────────────────────────────┐    │
│  │                          ferro-build                                 │    │
│  │                    (Image building from Dockerfile)                  │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │   Linux Kernel APIs    │
                    │  ─────────────────────  │
                    │ • namespaces           │
                    │ • cgroups v2           │
                    │ • OverlayFS            │
                    │ • eBPF / TC            │
                    │ • seccomp              │
                    │ • netfilter (fallback) │
                    └────────────────────────┘
```

---

## 2. Component Details

### 2.1 ferro-exec (Container Runtime Core)

**Responsibility:** Low-level container lifecycle management

**Crate Structure:**
```
ferro-exec/
├── Cargo.toml
├── src/
│   ├── lib.rs              # Public API
│   ├── container/
│   │   ├── mod.rs
│   │   ├── create.rs       # Container creation
│   │   ├── start.rs        # Process execution
│   │   ├── stop.rs         # Graceful/forced termination
│   │   ├── state.rs        # State machine implementation
│   │   └── exec.rs         # Exec into running container
│   ├── namespace/
│   │   ├── mod.rs
│   │   ├── user.rs         # User namespaces (rootless)
│   │   ├── pid.rs          # PID namespaces
│   │   ├── net.rs          # Network namespaces
│   │   ├── mnt.rs          # Mount namespaces
│   │   ├── uts.rs          # UTS namespaces
│   │   └── ipc.rs          # IPC namespaces
│   ├── cgroup/
│   │   ├── mod.rs
│   │   ├── v2.rs           # cgroups v2 implementation
│   │   ├── memory.rs       # Memory controller
│   │   ├── cpu.rs          # CPU controller
│   │   ├── pids.rs         # PID controller
│   │   └── io.rs           # IO controller
│   ├── rootfs/
│   │   ├── mod.rs
│   │   ├── overlay.rs      # OverlayFS management
│   │   └── pivot.rs        # pivot_root implementation
│   ├── security/
│   │   ├── mod.rs
│   │   ├── seccomp.rs      # Seccomp filter loading
│   │   ├── capabilities.rs # Capability management
│   │   ├── apparmor.rs     # AppArmor profile loading
│   │   └── selinux.rs      # SELinux context setting
│   └── process/
│       ├── mod.rs
│       ├── init.rs         # Container init process
│       ├── reaper.rs       # Zombie process reaping
│       └── signal.rs       # Signal handling
```

**Key Traits:**
```rust
/// Container runtime interface
pub trait ContainerRuntime: Send + Sync {
    /// Create a new container from an image
    fn create(&self, config: ContainerConfig) -> Result<ContainerId>;

    /// Start a created container
    fn start(&self, id: &ContainerId) -> Result<Pid>;

    /// Stop a running container
    fn stop(&self, id: &ContainerId, timeout: Duration) -> Result<()>;

    /// Execute a command in a running container
    fn exec(&self, id: &ContainerId, cmd: ExecConfig) -> Result<ExecStream>;

    /// Get container state
    fn inspect(&self, id: &ContainerId) -> Result<ContainerState>;

    /// Remove a container
    fn remove(&self, id: &ContainerId, force: bool) -> Result<()>;
}

/// Namespace manager interface
pub trait NamespaceManager: Send + Sync {
    /// Create all namespaces for a container
    fn create_namespaces(&self, config: &NamespaceConfig) -> Result<NamespaceSet>;

    /// Enter an existing namespace
    fn enter(&self, ns_type: NamespaceType, fd: RawFd) -> Result<()>;

    /// Get namespace file descriptors
    fn get_fds(&self, pid: Pid) -> Result<HashMap<NamespaceType, RawFd>>;
}
```

**Dependencies:**
- `nix` - Unix API bindings
- `libc` - Low-level system calls
- `caps` - Capability manipulation
- `syscallz` - Seccomp BPF generation

---

### 2.2 ferro-store (Image Management)

**Responsibility:** Image storage, pulling, pushing, and content-addressable storage

**Crate Structure:**
```
ferro-store/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── storage/
│   │   ├── mod.rs
│   │   ├── cas.rs          # Content-addressable storage (Blake3)
│   │   ├── layer.rs        # Layer management
│   │   ├── manifest.rs     # OCI manifest handling
│   │   └── gc.rs           # Garbage collection
│   ├── registry/
│   │   ├── mod.rs
│   │   ├── client.rs       # OCI distribution client
│   │   ├── auth.rs         # Registry authentication
│   │   ├── pull.rs         # Image pull logic
│   │   └── push.rs         # Image push logic
│   ├── cache/
│   │   ├── mod.rs
│   │   ├── lru.rs          # LRU cache for blobs
│   │   └── lazy.rs         # Lazy loading implementation
│   └── dedup/
│       ├── mod.rs
│       ├── blake3.rs       # Blake3 hashing
│       ├── vector.rs       # ruvector similarity (optional)
│       └── stats.rs        # Deduplication statistics
```

**Key Traits:**
```rust
/// Image store interface
pub trait ImageStore: Send + Sync {
    /// Pull an image from a registry
    fn pull(&self, reference: &ImageReference, options: PullOptions) -> Result<ImageId>;

    /// Push an image to a registry
    fn push(&self, reference: &ImageReference, options: PushOptions) -> Result<()>;

    /// Get image manifest
    fn get_manifest(&self, id: &ImageId) -> Result<OciManifest>;

    /// List local images
    fn list(&self, filter: ImageFilter) -> Result<Vec<ImageSummary>>;

    /// Remove an image
    fn remove(&self, id: &ImageId, force: bool) -> Result<()>;

    /// Prune unused images/layers
    fn prune(&self, options: PruneOptions) -> Result<PruneResult>;
}

/// Content-addressable storage interface
pub trait ContentStore: Send + Sync {
    /// Store content and return its hash
    fn store(&self, content: &[u8]) -> Result<Blake3Hash>;

    /// Retrieve content by hash
    fn retrieve(&self, hash: &Blake3Hash) -> Result<Vec<u8>>;

    /// Check if content exists
    fn exists(&self, hash: &Blake3Hash) -> bool;

    /// Get storage statistics
    fn stats(&self) -> StorageStats;
}
```

**Dependencies:**
- `blake3` - Fast cryptographic hashing
- `oci-spec` - OCI specification types
- `reqwest` - HTTP client for registries
- `tokio` - Async runtime
- `zstd` - Compression

---

### 2.3 ferro-build (Image Building)

**Responsibility:** Build images from Dockerfile and ferrofile.toml

**Crate Structure:**
```
ferro-build/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── parser/
│   │   ├── mod.rs
│   │   ├── dockerfile.rs   # Dockerfile parser
│   │   └── ferrofile.rs    # ferrofile.toml parser
│   ├── builder/
│   │   ├── mod.rs
│   │   ├── context.rs      # Build context handling
│   │   ├── stage.rs        # Multi-stage build
│   │   ├── cache.rs        # Build cache
│   │   └── executor.rs     # Instruction execution
│   ├── instructions/
│   │   ├── mod.rs
│   │   ├── from.rs         # FROM instruction
│   │   ├── run.rs          # RUN instruction
│   │   ├── copy.rs         # COPY instruction
│   │   ├── env.rs          # ENV instruction
│   │   ├── workdir.rs      # WORKDIR instruction
│   │   └── healthcheck.rs  # HEALTHCHECK instruction
│   └── snapshot/
│       ├── mod.rs
│       └── diff.rs         # Filesystem diff for layer creation
```

**Key Traits:**
```rust
/// Builder interface
pub trait ImageBuilder: Send + Sync {
    /// Build from a Dockerfile
    fn build_dockerfile(&self, context: &Path, options: BuildOptions) -> Result<ImageId>;

    /// Build from a ferrofile.toml
    fn build_ferrofile(&self, path: &Path, options: BuildOptions) -> Result<ImageId>;

    /// Get build cache stats
    fn cache_stats(&self) -> CacheStats;

    /// Prune build cache
    fn prune_cache(&self, options: PruneOptions) -> Result<PruneResult>;
}

/// Build instruction executor
pub trait InstructionExecutor: Send + Sync {
    /// Execute a single build instruction
    fn execute(&self, instruction: &Instruction, context: &mut BuildContext) -> Result<()>;
}
```

**Dependencies:**
- `ferro-exec` - Container execution
- `ferro-store` - Image storage
- `dockerfile-parser` - Dockerfile parsing (custom or existing crate)
- `toml` - ferrofile.toml parsing

---

### 2.4 ferro-net (Networking)

**Responsibility:** Container networking, eBPF-based packet forwarding, DNS

**Crate Structure:**
```
ferro-net/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── bridge/
│   │   ├── mod.rs
│   │   ├── create.rs       # Bridge creation
│   │   └── manage.rs       # Bridge management
│   ├── veth/
│   │   ├── mod.rs
│   │   └── pair.rs         # veth pair creation
│   ├── bpf/
│   │   ├── mod.rs
│   │   ├── loader.rs       # BPF program loader
│   │   ├── port_map.rs     # Port forwarding BPF map
│   │   └── programs/
│   │       ├── tc_ingress.c  # TC ingress program
│   │       └── xdp.c         # XDP program (future)
│   ├── iptables/           # Fallback when eBPF unavailable
│   │   ├── mod.rs
│   │   └── rules.rs
│   ├── dns/
│   │   ├── mod.rs
│   │   ├── server.rs       # Embedded DNS server
│   │   └── resolver.rs     # Container DNS resolver
│   ├── network/
│   │   ├── mod.rs
│   │   ├── bridge.rs       # Bridge network driver
│   │   ├── host.rs         # Host network driver
│   │   ├── none.rs         # None network driver
│   │   └── custom.rs       # Custom network driver
│   └── ipam/
│       ├── mod.rs
│       └── allocator.rs    # IP address management
```

**Key Traits:**
```rust
/// Network manager interface
pub trait NetworkManager: Send + Sync {
    /// Create a network
    fn create_network(&self, config: NetworkConfig) -> Result<NetworkId>;

    /// Delete a network
    fn delete_network(&self, id: &NetworkId) -> Result<()>;

    /// Connect a container to a network
    fn connect(&self, container_id: &ContainerId, network_id: &NetworkId) -> Result<NetworkInfo>;

    /// Disconnect a container from a network
    fn disconnect(&self, container_id: &ContainerId, network_id: &NetworkId) -> Result<()>;

    /// List networks
    fn list(&self) -> Result<Vec<NetworkSummary>>;
}

/// Packet forwarding interface
pub trait PacketForwarder: Send + Sync {
    /// Set up port forwarding
    fn setup_port_forward(&self, config: PortForwardConfig) -> Result<()>;

    /// Remove port forwarding
    fn remove_port_forward(&self, host_port: u16) -> Result<()>;

    /// Check if eBPF is available
    fn is_ebpf_available(&self) -> bool;
}
```

**Dependencies:**
- `aya` - eBPF library for Rust
- `nix` - Network namespace operations
- `trust-dns-server` - Embedded DNS server
- `ipnetwork` - IP network types

---

### 2.5 ferro-mind (AI Intelligence Layer)

**Responsibility:** Resource prediction, intelligent restart, anomaly detection

**Crate Structure:**
```
ferro-mind/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── predictor/
│   │   ├── mod.rs
│   │   ├── wasm.rs         # WASM neural inference
│   │   ├── features.rs     # Feature extraction
│   │   └── history.rs      # Historical data management
│   ├── diagnosis/
│   │   ├── mod.rs
│   │   ├── oom.rs          # OOM diagnosis
│   │   ├── crash.rs        # Crash diagnosis
│   │   └── pattern.rs      # Pattern matching
│   ├── anomaly/
│   │   ├── mod.rs
│   │   ├── detector.rs     # Anomaly detection
│   │   └── alert.rs        # Alert generation
│   ├── routing/
│   │   ├── mod.rs
│   │   └── tier.rs         # Cost-tiered AI routing
│   └── wasm/
│       ├── mod.rs
│       ├── runtime.rs      # WASM runtime (wasmtime)
│       └── modules/
│           ├── resource_predictor.wasm
│           ├── oom_classifier.wasm
│           └── anomaly_detector.wasm
```

**Key Traits:**
```rust
/// AI inference interface
pub trait AiInference: Send + Sync {
    /// Predict container resource requirements
    fn predict_resources(&self, spec: &ContainerSpec) -> Result<ResourcePrediction>;

    /// Diagnose container failure
    fn diagnose_failure(&self, context: &FailureContext) -> Result<Diagnosis>;

    /// Detect anomalies in container behavior
    fn detect_anomaly(&self, metrics: &ContainerMetrics) -> Result<Option<Anomaly>>;
}

/// AI tier router
pub trait AiTierRouter: Send + Sync {
    /// Route request to appropriate AI tier
    fn route(&self, request: AiRequest) -> Result<AiResponse>;

    /// Check which tiers are available
    fn available_tiers(&self) -> Vec<AiTier>;
}

/// AI tiers (cost-ordered)
pub enum AiTier {
    /// Free, local WASM inference (1-5ms, pluggable with native fallback)
    Wasm,
    /// Cheap, local LLM (if available)
    LocalLlm,
    /// Expensive, Claude API (complex cases)
    ClaudeApi,
}
```

**Dependencies:**
- `wasmtime` - WASM runtime
- `ruv-fann` - Neural network (compiled to WASM)
- `serde` - Serialization for features/predictions
- `tokio` - Async for API calls (optional)

**Integration with claude-flow:**
```rust
/// Claude-flow MCP integration (optional, lazy-loaded)
pub struct ClaudeFlowIntegration {
    process: Option<ChildProcess>,
    socket: Option<PathBuf>,
}

impl ClaudeFlowIntegration {
    /// Spawn claude-flow process if not running
    pub async fn ensure_running(&mut self) -> Result<()> {
        if self.process.is_none() {
            // Lazy load: only spawn when needed for complex diagnostics
            self.process = Some(
                Command::new("npx")
                    .args(["claude-flow@alpha", "mcp", "start"])
                    .spawn()?
            );
        }
        Ok(())
    }

    /// Send diagnostic request via MCP
    pub async fn diagnose(&mut self, context: FailureContext) -> Result<Diagnosis> {
        self.ensure_running().await?;
        // MCP protocol communication over stdio
        // ...
    }
}
```

---

### 2.6 ferro-compose (Multi-Container Orchestration)

**Responsibility:** docker-compose.yml parsing and multi-container management

**Crate Structure:**
```
ferro-compose/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── parser/
│   │   ├── mod.rs
│   │   ├── compose.rs      # docker-compose.yml parser
│   │   └── validate.rs     # Schema validation
│   ├── project/
│   │   ├── mod.rs
│   │   ├── service.rs      # Service definition
│   │   ├── network.rs      # Project networks
│   │   └── volume.rs       # Project volumes
│   ├── commands/
│   │   ├── mod.rs
│   │   ├── up.rs           # docker compose up
│   │   ├── down.rs         # docker compose down
│   │   ├── ps.rs           # docker compose ps
│   │   ├── logs.rs         # docker compose logs
│   │   └── scale.rs        # docker compose scale
│   ├── dependency/
│   │   ├── mod.rs
│   │   └── graph.rs        # Service dependency graph
│   └── watch/
│       ├── mod.rs
│       └── reloader.rs     # File watch and rebuild
```

**Key Traits:**
```rust
/// Compose project interface
pub trait ComposeProject: Send + Sync {
    /// Load project from docker-compose.yml
    fn load(&self, path: &Path) -> Result<Project>;

    /// Start all services
    fn up(&self, options: UpOptions) -> Result<()>;

    /// Stop all services
    fn down(&self, options: DownOptions) -> Result<()>;

    /// Get service status
    fn ps(&self) -> Result<Vec<ServiceStatus>>;

    /// Scale a service
    fn scale(&self, service: &str, replicas: u32) -> Result<()>;
}
```

**Dependencies:**
- `ferro-exec` - Container execution
- `ferro-store` - Image management
- `ferro-net` - Networking
- `serde_yaml` - YAML parsing
- `notify` - File watching

---

## 3. Data Flow Diagrams

### 3.1 Container Creation Flow

```
┌─────────┐    ferrocrate run alpine     ┌──────────────┐
│   CLI   │ ───────────────────────────► │ ferro-compose │
└─────────┘                              └───────┬──────┘
                                                 │
                                                 ▼
                                         ┌──────────────┐
                                         │  ferro-store │
                                         │              │
                                         │ 1. Resolve   │
                                         │    image ref │
                                         │ 2. Pull if   │
                                         │    needed    │
                                         └───────┬──────┘
                                                 │
                                                 ▼
                                         ┌──────────────┐
                                         │  ferro-exec  │
                                         │              │
                                         │ 3. Prepare   │
                                         │    rootfs    │
                                         │ 4. Setup     │
                                         │    cgroups   │
                                         └───────┬──────┘
                                                 │
                                                 ▼
                                         ┌──────────────┐
                                         │  ferro-net   │
                                         │              │
                                         │ 5. Create    │
                                         │    veth pair │
                                         │ 6. Setup     │
                                         │    bridge    │
                                         │ 7. Configure │
                                         │    DNS       │
                                         └───────┬──────┘
                                                 │
                                                 ▼
                                         ┌──────────────┐
                                         │  ferro-mind  │
                                         │  (optional)  │
                                         │              │
                                         │ 8. Predict   │
                                         │    resources │
                                         │ 9. Adjust    │
                                         │    cgroups   │
                                         └───────┬──────┘
                                                 │
                                                 ▼
                                         ┌──────────────┐
                                         │  Container   │
                                         │  RUNNING     │
                                         └──────────────┘
```

### 3.2 Image Pull Flow

```
┌─────────────┐    ferrocrate pull myimage:latest    ┌──────────────┐
│     CLI     │ ──────────────────────────────────► │ ferro-store  │
└─────────────┘                                       └──────┬───────┘
                                                             │
                         ┌───────────────────────────────────┤
                         │                                   │
                         ▼                                   ▼
                  ┌─────────────┐                    ┌──────────────┐
                  │   Registry  │                    │  Local CAS   │
                  │   Client    │                    │  (Blake3)    │
                  └──────┬──────┘                    └──────────────┘
                         │
                         │ 1. GET /v2/myimage/manifests/latest
                         ▼
                  ┌─────────────┐
                  │   OCI       │
                  │   Registry  │
                  │  (remote)   │
                  └──────┬──────┘
                         │
                         │ 2. Manifest JSON
                         ▼
                  ┌─────────────┐
                  │   Layer     │
                  │   Resolution│
                  └──────┬──────┘
                         │
           ┌─────────────┼─────────────┐
           │             │             │
           ▼             ▼             ▼
      ┌─────────┐  ┌─────────┐  ┌─────────┐
      │ Layer 1 │  │ Layer 2 │  │ Layer N │
      │ (local) │  │ (fetch) │  │ (fetch) │
      └────┬────┘  └────┬────┘  └────┬────┘
           │            │            │
           │ skip       │ download   │ download
           │            │            │
           │            ▼            ▼
           │      ┌─────────────────────────┐
           │      │   Decompress (zstd)     │
           │      └───────────┬─────────────┘
           │                  │
           │                  ▼
           │      ┌─────────────────────────┐
           │      │   Extract to temp       │
           │      └───────────┬─────────────┘
           │                  │
           │                  ▼
           │      ┌─────────────────────────┐
           │      │   Hash each file (Blake3)│
           │      └───────────┬─────────────┘
           │                  │
           │                  ▼
           │      ┌─────────────────────────┐
           │      │   Store in CAS (dedup)  │
           │      └───────────┬─────────────┘
           │                  │
           └──────────────────┤
                              │
                              ▼
                      ┌──────────────┐
                      │   Manifest   │
                      │   stored     │
                      └──────────────┘
```

### 3.3 Intelligent Restart Flow

```
                    Container Exit Detected
                            │
                            ▼
                  ┌──────────────────┐
                  │   Collect Exit   │
                  │   Context        │
                  │  - exit_code     │
                  │  - oom_killed    │
                  │  - duration      │
                  │  - resource_peak │
                  └────────┬─────────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │   Check Restart  │
                  │   Policy         │
                  └────────┬─────────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
              ▼            ▼            ▼
        ┌──────────┐ ┌──────────┐ ┌──────────┐
        │   "no"   │ │"on-failure│ │ "always" │
        │          │ │  & 0"     │ │          │
        └────┬─────┘ └────┬──────┘ └────┬─────┘
             │            │             │
             ▼            ▼             │
        ┌──────────┐ ┌──────────┐       │
        │  Don't   │ │  Don't   │       │
        │  restart │ │  restart │       │
        └──────────┘ └──────────┘       │
                                        │
              ┌─────────────────────────┘
              │
              ▼
      ┌──────────────────┐
      │   AI Enabled?    │
      └────────┬─────────┘
               │
       ┌───────┴───────┐
       │               │
       ▼               ▼
   ┌───────┐     ┌───────────────┐
   │  No   │     │     Yes       │
   └───┬───┘     └───────┬───────┘
       │                 │
       │                 ▼
       │         ┌───────────────────┐
       │         │   ferro-mind      │
       │         │                   │
       │         │ 1. Extract        │
       │         │    features       │
       │         │ 2. WASM inference │
       │         │ 3. Match pattern  │
       │         └───────┬───────────┘
       │                 │
       │         ┌───────┼───────┐
       │         │       │       │
       │         ▼       ▼       ▼
       │    ┌────────┐ ┌────────┐ ┌────────┐
       │    │Adjust &│ │ Alert &│ │Restart │
       │    │Restart │ │  Wait  │ │ Normal │
       │    └───┬────┘ └───┬────┘ └───┬────┘
       │        │          │          │
       │        ▼          ▼          │
       │   ┌─────────┐ ┌─────────┐    │
       │   │Modify   │ │Escalate │    │
       │   │cgroup   │ │to user  │    │
       │   │limits   │ │         │    │
       │   └────┬────┘ └─────────┘    │
       │        │                      │
       └────────┴──────────────────────┤
                                        │
                                        ▼
                              ┌──────────────────┐
                              │   Execute        │
                              │   Restart with   │
                              │   backoff        │
                              └──────────────────┘
```

---

## 4. Integration with claude-flow MCP

### 4.1 MCP Tool Integration

FerroCrate exposes its functionality through MCP tools for integration with claude-flow agents:

```json
{
  "tools": [
    {
      "name": "ferrocrate_run",
      "description": "Run a container with intelligent defaults",
      "parameters": {
        "image": "string",
        "command": "array<string>",
        "env": "object",
        "ai_enabled": "boolean"
      }
    },
    {
      "name": "ferrocrate_diagnose",
      "description": "Diagnose a container issue using AI analysis",
      "parameters": {
        "container_id": "string",
        "context": "string"
      }
    },
    {
      "name": "ferrocrate_predict",
      "description": "Predict resource requirements for a container",
      "parameters": {
        "image": "string",
        "env": "object"
      }
    },
    {
      "name": "ferrocrate_explain",
      "description": "Explain an AI decision made by ferro-mind",
      "parameters": {
        "decision_id": "string"
      }
    }
  ]
}
```

### 4.2 Agent Coordination Pattern

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          claude-flow Agent Swarm                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐       │
│  │   Monitor Agent │     │  Diagnose Agent │     │   Fix Agent     │       │
│  │                 │     │                 │     │                 │       │
│  │ Watches         │     │ Analyzes        │     │ Applies         │       │
│  │ container       │────►│ crash logs      │────►│ config changes  │       │
│  │ health          │     │ and metrics     │     │                 │       │
│  └─────────────────┘     └─────────────────┘     └─────────────────┘       │
│           │                      │                       │                  │
│           └──────────────────────┴───────────────────────┘                  │
│                                  │                                           │
│                                  ▼                                           │
│                    ┌─────────────────────────────┐                          │
│                    │      MCP Protocol           │                          │
│                    │  (JSON-RPC over stdio)      │                          │
│                    └──────────────┬──────────────┘                          │
│                                   │                                          │
└───────────────────────────────────┼──────────────────────────────────────────┘
                                    │
                                    ▼
                    ┌─────────────────────────────┐
                    │       FerroCrate            │
                    │                             │
                    │  ferro-mind exposes:        │
                    │  - ferrocrate_diagnose      │
                    │  - ferrocrate_predict       │
                    │  - ferrocrate_explain       │
                    │                             │
                    │  ferro-exec exposes:        │
                    │  - ferrocrate_run           │
                    │  - ferrocrate_stop          │
                    │  - ferrocrate_exec          │
                    └─────────────────────────────┘
```

### 4.3 Decision Flow for Complex Diagnostics

```rust
/// Route diagnostic request to appropriate handler
pub async fn route_diagnosis(&self, context: &FailureContext) -> Result<Diagnosis> {
    // Step 1: Check complexity
    let complexity = self.assess_complexity(context);

    match complexity {
        Complexity::Simple => {
            // Use WASM inference (fast, free)
            self.wasm_diagnose(context)
        }
        Complexity::Moderate => {
            // Use local LLM if available, else WASM
            if self.local_llm_available() {
                self.local_llm_diagnose(context).await
            } else {
                self.wasm_diagnose(context)
            }
        }
        Complexity::Complex => {
            // Check if Claude API is configured
            if self.claude_api_available() {
                // Spawn claude-flow agent for multi-step analysis
                self.spawn_diagnostic_agent(context).await
            } else {
                // Fallback to WASM with lower confidence
                self.wasm_diagnose(context)
            }
        }
    }
}
```

---

## 5. Binary Tiers

FerroCrate is released in three binary tiers to accommodate different user needs:

### 5.1 Tier Comparison

| Feature | Minimal | Standard | Full | Full + Agents |
|---------|---------|----------|------|---------------|
| Container runtime | Yes | Yes | Yes | Yes |
| Image management | Yes | Yes | Yes | Yes |
| Networking (eBPF) | Yes | Yes | Yes | Yes |
| Compose support | Yes | Yes | Yes | Yes |
| WASM AI inference | No | Yes | Yes | Yes |
| Local LLM support | No | Optional | Yes | Yes |
| Claude API integration | No | No | Yes | Yes |
| claude-flow/agentic-flow | No | No | No | Yes (subprocess) |
| Binary size | ~5 MB | ~12 MB | ~18 MB | ~45 MB |
| Node.js dependency | No | No | No | Bundled (lazy) |

### 5.2 Feature Flags (Cargo.toml)

```toml
[features]
default = ["standard"]

minimal = [
    "ferro-exec",
    "ferro-store",
    "ferro-net",
    "ferro-build",
    "ferro-compose"
]

standard = [
    "minimal",
    "ferro-mind-wasm"
]

full = [
    "standard",
    "ferro-mind-llm",
    "ferro-mind-claude"
]

full-agents = [
    "full",
    "claude-flow-bundled",
    "agentic-flow-bundled"
]

ferro-mind-wasm = ["ferro-mind", "wasmtime"]
ferro-mind-llm = ["ferro-mind", "llama-cpp"]
ferro-mind-claude = ["ferro-mind", "reqwest", "tokio"]
```

---

## 6. Entry/Exit Criteria

### Phase 3: Architecture (Current)

**Entry Criteria:**
- [x] Pseudocode approved
- [x] Algorithms validated
- [x] Edge cases documented

**Exit Criteria:**
- [x] Component diagram complete
- [x] Data flow documented
- [x] MCP integration defined
- [x] Binary tiers specified
- [ ] Architecture review completed
- [ ] Ready for TDD implementation

---

## Appendix A: Directory Structure

```
ferrocrate/
├── Cargo.toml                  # Workspace configuration
├── crates/
│   ├── ferro-exec/             # Container runtime (OCI compliant)
│   ├── ferro-store/            # Image management (Blake3 CAS)
│   ├── ferro-build/            # Image building (Dockerfile + ferrofile)
│   ├── ferro-net/              # Networking (eBPF-based)
│   ├── ferro-mind/             # AI intelligence layer (WASM + ruvector)
│   ├── ferro-compose/          # Multi-container orchestration
│   ├── ferro-mgr/              # Optional management daemon
│   └── ferro-cli/              # CLI binary (thin wrapper)
├── cli/
│   └── src/
│       ├── main.rs             # CLI entry point
│       └── commands/           # CLI command implementations
├── bpf/
│   └── programs/               # eBPF programs (C)
├── wasm/
│   └── modules/                # Pre-compiled WASM modules
├── tests/
│   ├── integration/            # Integration tests
│   └── e2e/                    # End-to-end tests
├── docs/
│   └── sparc/                  # SPARC documentation
└── examples/
    └── Dockerfile              # Example Dockerfiles for testing
```

---

## Appendix B: External Dependencies

| Dependency | Version | Purpose | License |
|------------|---------|---------|---------|
| `nix` | 0.27 | Unix API bindings | MIT |
| `tokio` | 1.35 | Async runtime | MIT |
| `aya` | 0.11 | eBPF library | MIT/Apache-2.0 |
| `wasmtime` | 19.0 | WASM runtime | Apache-2.0 |
| `blake3` | 1.5 | Hashing | CC0/Apache-2.0 |
| `oci-spec` | 0.6 | OCI types | Apache-2.0 |
| `serde` | 1.0 | Serialization | MIT/Apache-2.0 |
| `clap` | 4.4 | CLI parsing | MIT/Apache-2.0 |
| `trust-dns-server` | 0.23 | Embedded DNS | MIT/Apache-2.0 |
| `zstd` | 0.13 | Compression | BSD-3-Clause |
