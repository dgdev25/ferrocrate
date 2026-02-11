# M0: Foundation Milestone

**⚠️ LEGACY NOTICE:** This milestone structure has been superseded by the 6-phase implementation plan (Phase 1-6). Maintained for historical reference only. See `INDEX.md` for the current Phase 1-6 timeline.

**Duration:** Weeks 1-4 | **Story Points:** 41 | **Tasks:** 6

---

## 1. Objective

Establish the core container runtime with Linux namespace isolation, cgroups v2 resource management, and rootless container support. This milestone delivers a functional container execution engine that can run OCI-compliant containers without root privileges.

## 2. Scope

### In Scope
- ferro-exec crate implementation
- Linux namespace management (pid, net, mnt, ipc, uts, user)
- cgroups v2 unified hierarchy support
- User namespace mapping for rootless containers
- OCI Runtime Spec v1.2 compliance
- Basic container lifecycle operations (create, start, stop, kill, delete)
- Process signal handling and graceful shutdown
- State persistence for daemonless operation

### Out of Scope
- Image management (M1)
- Networking (M2)
- AI features (M3)
- Multi-container orchestration (M3)

## 3. Architecture

### Component Structure

```
ferro-exec/
+-- Cargo.toml
+-- src/
|   +-- lib.rs              # Crate entry point
|   +-- namespace/
|   |   +-- mod.rs          # Namespace management
|   |   +-- pid.rs          # PID namespace
|   |   +-- net.rs          # Network namespace
|   |   +-- mnt.rs          # Mount namespace
|   |   +-- ipc.rs          # IPC namespace
|   |   +-- uts.rs          # UTS namespace
|   |   +-- user.rs         # User namespace
|   |   +-- builder.rs      # Namespace configuration builder
|   +-- cgroup/
|   |   +-- mod.rs          # Cgroup management
|   |   +-- v2.rs           # cgroups v2 implementation
|   |   +-- cpu.rs          # CPU controller
|   |   +-- memory.rs       # Memory controller
|   |   +-- io.rs           # IO controller
|   |   +-- pids.rs         # PIDs controller
|   |   +-- freezer.rs      # Freezer controller
|   +-- process/
|   |   +-- mod.rs          # Process management
|   |   +-- exec.rs         # Process execution
|   |   +-- signal.rs       # Signal handling
|   |   +-- stdio.rs        # Stdin/stdout/stderr
|   +-- container/
|   |   +-- mod.rs          # Container abstraction
|   |   +-- lifecycle.rs    # Create/start/stop/delete
|   |   +-- state.rs        # Container state machine
|   |   +-- bundle.rs       # OCI bundle handling
|   +-- security/
|   |   +-- mod.rs          # Security features
|   |   +-- capabilities.rs # Linux capabilities
|   |   +-- seccomp.rs      # Seccomp profiles
|   |   +-- rootless.rs     # Rootless setup
|   +-- error.rs            # Error types
|   +-- config.rs           # Configuration types
```

### Key Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| nix | 0.27 | Syscall wrappers (clone, unshare, setns) |
| caps | 0.5 | Linux capability manipulation |
| cgroups-rs | 0.3 | cgroup v2 management |
| libc | 0.2 | Low-level FFI |
| serde | 1.0 | Configuration serialization |
| thiserror | 1.0 | Error derivation |
| tracing | 0.1 | Instrumentation |

## 4. Tasks

### TASK-001: Implement ferro-exec crate skeleton

**Effort:** 3 days | **Points:** 5 | **Priority:** P0 | **Depends On:** -

**Description:**
Create the core ferro-exec crate with module structure for namespaces, cgroups, and process management. Include error types and base traits.

**Acceptance Criteria:**
- [ ] Cargo.toml created with all dependencies
- [ ] Module structure: src/{lib.rs, namespace.rs, cgroup.rs, process.rs, error.rs}
- [ ] cargo build succeeds
- [ ] cargo test passes with placeholder tests

**Implementation Notes:**
```rust
// src/lib.rs
pub mod namespace;
pub mod cgroup;
pub mod process;
pub mod container;
pub mod security;
pub mod error;
pub mod config;

pub use container::Container;
pub use error::Error;
```

---

### TASK-002: Implement Linux namespace management

**Effort:** 5 days | **Points:** 8 | **Priority:** P0 | **Depends On:** TASK-001

**Description:**
Create, enter, and manage Linux namespaces (pid, net, mnt, ipc, uts, user) for container isolation. Support namespace cloning and setns operations.

**Acceptance Criteria:**
- [ ] Unit tests for each namespace type
- [ ] Integration test: create isolated process
- [ ] Benchmark: namespace creation <1ms
- [ ] Document unsafe block safety rationale

**Implementation Notes:**
```rust
// namespace/mod.rs
pub struct NamespaceSet {
    pid: Option<Namespace>,
    net: Option<Namespace>,
    mnt: Option<Namespace>,
    ipc: Option<Namespace>,
    uts: Option<Namespace>,
    user: Option<UserNamespace>,
}

impl NamespaceSet {
    pub fn builder() -> NamespaceSetBuilder { ... }
    pub fn apply(&self) -> Result<()> { ... }
    pub fn clone_into_child(&self) -> Result<()> { ... }
}
```

**Key Syscalls:**
- `clone(CLONE_NEWPID | CLONE_NEWNET | ...)` - Create new namespaces
- `unshare(CLONE_NEWNS)` - Unshare namespace
- `setns(fd, CLONE_NEWNET)` - Enter existing namespace

---

### TASK-003: Implement cgroups v2 resource management

**Effort:** 5 days | **Points:** 8 | **Priority:** P0 | **Depends On:** TASK-001

**Description:**
Implement unified cgroups v2 hierarchy for CPU, memory, IO, and PIDs limiting. Support cgroup creation, delegation, and cleanup.

**Acceptance Criteria:**
- [ ] CPU limit enforcement verified with stress test
- [ ] Memory limit triggers OOM kill at threshold
- [ ] PIDs limit prevents fork bombs
- [ ] cgroup cleanup on container removal

**Implementation Notes:**
```rust
// cgroup/v2.rs
pub struct CgroupV2 {
    path: PathBuf,
    controllers: Vec<Controller>,
}

pub struct Controller {
    name: String,
    path: PathBuf,
}

impl CgroupV2 {
    pub fn create(name: &str) -> Result<Self> { ... }
    pub fn set_cpu(&self, quota: i64, period: i64) -> Result<()> { ... }
    pub fn set_memory(&self, limit: u64) -> Result<()> { ... }
    pub fn set_pids(&self, max: i64) -> Result<()> { ... }
    pub fn add_process(&self, pid: i32) -> Result<()> { ... }
    pub fn freeze(&self) -> Result<()> { ... }
    pub fn thaw(&self) -> Result<()> { ... }
    pub fn delete(&self) -> Result<()> { ... }
}
```

**File Structure:**
```
/sys/fs/cgroup/ferrocrate/<container-id>/
+-- cgroup.controllers     # Available controllers
+-- cgroup.subtree_control # Enabled subcontrollers
+-- cpu.max                # CPU quota/period
+-- cpu.weight             # CPU weight (1-10000)
+-- memory.max             # Memory limit
+-- memory.current         # Current usage
+-- pids.max               # PIDs limit
+-- cgroup.procs           # PIDs in cgroup
+-- cgroup.freeze          # Freezer state
```

---

### TASK-004: Implement rootless container support

**Effort:** 4 days | **Points:** 6 | **Priority:** P0 | **Depends On:** TASK-002, TASK-003

**Description:**
Implement user namespace mapping with subordinate UID/GID ranges. Configure unprivileged cgroup delegation via systemd user session.

**Acceptance Criteria:**
- [ ] Container runs as non-root user
- [ ] UID mapping: container 0 -> host 100000
- [ ] cgroup delegation works without root
- [ ] Security: no privilege escalation possible

**Implementation Notes:**
```rust
// security/rootless.rs
pub struct RootlessConfig {
    uid_map: Vec<IdMap>,
    gid_map: Vec<IdMap>,
    newuidmap_path: PathBuf,
    newgidmap_path: PathBuf,
}

pub struct IdMap {
    container_id: u32,
    host_id: u32,
    range: u32,
}

impl RootlessConfig {
    pub fn from_subuid(subuid_path: &Path) -> Result<Self> { ... }
    pub fn apply(&self, pid: i32) -> Result<()> { ... }
}
```

**Subordinate ID Setup:**
```bash
# /etc/subuid
username:100000:65536

# /etc/subgid
username:100000:65536
```

**cgroup Delegation:**
```bash
# Via systemd user session
loginctl enable-linger $USER
# Creates: /sys/fs/cgroup/user.slice/user-$(id -u).slice/
```

---

### TASK-005: Implement OCI Runtime Spec compliance

**Effort:** 5 days | **Points:** 8 | **Priority:** P0 | **Depends On:** TASK-002, TASK-003, TASK-004

**Description:**
Parse OCI config.json and create containers according to Runtime Spec v1.2. Support process, root, linux, and hooks sections.

**Acceptance Criteria:**
- [ ] OCI runtime-validator passes
- [ ] runc-generated bundles execute correctly
- [ ] All OCI hooks supported
- [ ] Spec-compliant error messages

**Implementation Notes:**
```rust
// container/bundle.rs
#[derive(Deserialize)]
pub struct OciSpec {
    pub ociVersion: String,
    pub process: Process,
    pub root: Root,
    pub hostname: Option<String>,
    pub mounts: Vec<Mount>,
    pub hooks: Option<Hooks>,
    pub linux: Option<Linux>,
}

impl OciSpec {
    pub fn from_file(path: &Path) -> Result<Self> { ... }
    pub fn to_container(&self) -> Result<ContainerConfig> { ... }
}
```

**Bundle Structure:**
```
/bundle/
+-- config.json    # OCI runtime config
+-- rootfs/        # Container filesystem
```

---

### TASK-006: Implement container lifecycle operations

**Effort:** 4 days | **Points:** 6 | **Priority:** P0 | **Depends On:** TASK-005

**Description:**
Implement create, start, stop, kill, delete container operations. Handle process signals and graceful shutdown with timeout.

**Acceptance Criteria:**
- [ ] Container create/start <100ms cold
- [ ] Graceful stop with SIGTERM timeout
- [ ] Force kill with SIGKILL
- [ ] State persistence across CLI invocations

**Implementation Notes:**
```rust
// container/lifecycle.rs
pub enum ContainerState {
    Creating,
    Created,
    Running,
    Stopped,
    Paused,
}

impl Container {
    pub fn create(spec: OciSpec) -> Result<Self> { ... }
    pub fn start(&mut self) -> Result<()> { ... }
    pub fn stop(&mut self, timeout: Duration) -> Result<()> { ... }
    pub fn kill(&mut self, signal: Signal) -> Result<()> { ... }
    pub fn delete(&mut self) -> Result<()> { ... }
    pub fn state(&self) -> ContainerState { ... }
}
```

**State Persistence:**
```rust
// container/state.rs
pub struct ContainerStateFile {
    pub id: String,
    pub status: ContainerState,
    pub pid: Option<i32>,
    pub bundle: PathBuf,
    pub created: DateTime<Utc>,
    pub rootfs: PathBuf,
}

impl ContainerStateFile {
    pub fn save(&self, path: &Path) -> Result<()> { ... }
    pub fn load(path: &Path) -> Result<Self> { ... }
}
```

---

## 5. Quality Gate

### Step 1: Code Complete
- [ ] All 6 tasks marked complete
- [ ] No TODO comments in code
- [ ] All clippy warnings resolved
- [ ] Code formatted with rustfmt

### Step 2: Unit Tests
- [ ] >80% line coverage
- [ ] 100% unsafe block coverage
- [ ] All edge cases tested
- [ ] Error paths tested

```bash
cargo tarpaulin --out Html --output-dir coverage/
```

### Step 3: Integration Tests
- [ ] OCI runtime-validator passes
- [ ] Alpine container runs successfully
- [ ] Resource limits enforced
- [ ] Rootless container works

```bash
# Integration test suite
cargo test --test integration
```

### Step 4: Performance Tests
- [ ] Container startup <100ms (cold)
- [ ] Container startup <50ms (warm)
- [ ] Namespace creation <1ms
- [ ] cgroup operations <5ms

```bash
cargo bench --bench lifecycle
```

### Step 5: Security Audit
- [ ] cargo-audit clean
- [ ] No unsafe without safety comment
- [ ] Privilege escalation tests pass
- [ ] Container escape tests pass

```bash
cargo audit
cargo deny check
```

### Step 6: Documentation
- [ ] API documentation complete
- [ ] README with examples
- [ ] Architecture diagram
- [ ] Configuration reference

```bash
cargo doc --no-deps
```

### Step 7: Review Sign-off
- [ ] Code review complete
- [ ] Architecture review complete
- [ ] Performance review complete
- [ ] Security review complete

---

## 6. Dependencies

### Internal Dependencies
- None (ferro-exec is the foundation)

### External Dependencies
- Linux kernel 5.10+ with:
  - CONFIG_USER_NS=y
  - CONFIG_CGROUPS=y
  - CONFIG_CGROUP_V2=y
  - CONFIG_OVERLAY_FS=y

### System Requirements
- /etc/subuid and /etc/subgid configured
- systemd user session (for cgroup delegation)
- /sys/fs/cgroup mounted with cgroupv2

---

## 7. Risks and Mitigations

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Kernel version incompatibility | Low | High | Detect kernel version; fail with clear message |
| User namespace not available | Medium | High | Check /proc/sys/kernel/unprivileged_userns_clone |
| cgroup delegation failure | Medium | Medium | Fallback instructions for manual setup |
| Rootless OverlayFS | Medium | Low | FUSE fallback (defer to M1) |

---

## 8. Exit Criteria

Before proceeding to M1, the following must be demonstrated:

1. **Basic Container Execution:**
   ```bash
   # Create OCI bundle
   mkdir -p /tmp/bundle/rootfs
   curl -o rootfs.tar.gz https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/x86_64/alpine-minirootfs-3.19.0-x86_64.tar.gz
   tar -xzf rootfs.tar.gz -C /tmp/bundle/rootfs

   # Generate config.json
   ferrocrate spec --rootfs /tmp/bundle/rootfs > /tmp/bundle/config.json

   # Run container
   ferrocrate create -b /tmp/bundle alpine-test
   ferrocrate start alpine-test
   ferrocrate exec alpine-test echo "Hello, FerroCrate!"
   ferrocrate stop alpine-test
   ferrocrate delete alpine-test
   ```

2. **Rootless Verification:**
   ```bash
   # As non-root user
   id  # Verify non-root
   ferrocrate create -b /tmp/bundle test-rootless
   # Verify container runs without root
   ```

3. **Resource Limits:**
   ```bash
   # Memory limit
   ferrocrate create -b /tmp/bundle --memory 100M test-mem
   ferrocrate start test-mem
   # Run memory stress; verify OOM kill
   ```

4. **Performance Verification:**
   ```bash
   # Startup time
   time ferrocrate create -b /tmp/bundle perf-test
   time ferrocrate start perf-test
   # Both should complete in <100ms total
   ```

---

*Milestone Owner: TBD | Last Updated: 2026-02-11*
