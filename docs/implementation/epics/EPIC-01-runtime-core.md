# EPIC-01: Runtime Core

**Phase:** Phase 1 (Weeks 1-6) | **Tasks:** 6 | **Story Points:** 41

---

## 1. Overview

This epic delivers the fundamental container runtime capabilities of FerroCrate, including container lifecycle management, namespace isolation, cgroup resource management, and rootless container support.

### User Stories Covered
- US-1.1: Run any Docker Hub image with `ferrocrate run`
- US-1.2: Zero memory consumption when no containers running
- US-1.3: Rootless containers by default
- US-1.4: `ferrocrate build` accepts existing Dockerfiles
- US-1.5: `ferrocrate compose` parses docker-compose.yml

### PRD Requirements Covered
- CLM-01 through CLM-10 (Container Lifecycle Management)
- SEC-01, SEC-04, SEC-06 (Security)
- COMPAT-02, COMPAT-07 (Compatibility)
- PERF-01, PERF-03, PERF-05 (Performance)

---

## 2. Components

### ferro-exec Crate
The core container execution engine responsible for:
- Linux namespace management
- cgroups v2 resource management
- Process lifecycle and signal handling
- OCI Runtime Spec compliance
- Rootless container setup

### Architecture

```
+------------------------------------------------------------------+
|                        ferro-exec crate                           |
|                                                                   |
|  +-------------+  +-------------+  +-------------+  +-----------+ |
|  | namespace/  |  |   cgroup/   |  |  process/   |  | container/| |
|  |             |  |             |  |             |  |           | |
|  | - pid.rs    |  | - v2.rs     |  | - exec.rs   |  | - lifecycle| |
|  | - net.rs    |  | - cpu.rs    |  | - signal.rs |  | - state.rs | |
|  | - mnt.rs    |  | - memory.rs |  | - stdio.rs  |  | - bundle.rs| |
|  | - ipc.rs    |  | - io.rs     |  |             |  |           | |
|  | - uts.rs    |  | - pids.rs   |  |             |  |           | |
|  | - user.rs   |  | - freezer.rs|  |             |  |           | |
|  +-------------+  +-------------+  +-------------+  +-----------+ |
|                                                                   |
|  +-------------+  +-------------+                                 |
|  |  security/  |  |   config/   |                                 |
|  |             |  |             |                                 |
|  | - caps.rs   |  | - spec.rs   |                                 |
|  | - seccomp.rs|  | - types.rs  |                                 |
|  | - rootless  |  |             |                                 |
|  +-------------+  +-------------+                                 |
+------------------------------------------------------------------+
```

---

## 3. Tasks

| ID | Title | Points | Depends On | Status |
|----|-------|--------|------------|--------|
| TASK-001 | Implement ferro-exec crate skeleton | 5 | - | Not Started |
| TASK-002 | Implement Linux namespace management | 8 | TASK-001 | Not Started |
| TASK-003 | Implement cgroups v2 resource management | 8 | TASK-001 | Not Started |
| TASK-004 | Implement rootless container support | 6 | TASK-002, TASK-003 | Not Started |
| TASK-005 | Implement OCI Runtime Spec compliance | 8 | TASK-002, TASK-003, TASK-004 | Not Started |
| TASK-006 | Implement container lifecycle operations | 6 | TASK-005 | Not Started |

**Total Story Points:** 41

---

## 4. Key Interfaces

### Container Lifecycle

```rust
/// Core container trait
pub trait ContainerLifecycle {
    /// Create a new container from OCI spec
    fn create(spec: OciSpec) -> Result<Self> where Self: Sized;

    /// Start the container
    fn start(&mut self) -> Result<()>;

    /// Stop the container gracefully
    fn stop(&mut self, timeout: Duration) -> Result<()>;

    /// Force kill the container
    fn kill(&mut self, signal: Signal) -> Result<()>;

    /// Delete the container
    fn delete(self) -> Result<()>;

    /// Get container state
    fn state(&self) -> ContainerState;

    /// Get container PID (if running)
    fn pid(&self) -> Option<i32>;
}

/// Container state machine
pub enum ContainerState {
    Creating,
    Created,
    Running,
    Stopped,
    Paused,
    Deleted,
}
```

### Namespace Management

```rust
/// Namespace configuration
pub struct NamespaceConfig {
    pub pid: bool,
    pub net: bool,
    pub mnt: bool,
    pub ipc: bool,
    pub uts: bool,
    pub user: Option<UserNamespaceConfig>,
}

pub struct UserNamespaceConfig {
    pub uid_mappings: Vec<IdMapping>,
    pub gid_mappings: Vec<IdMapping>,
}

/// Namespace operations
pub trait NamespaceOps {
    /// Create new namespaces
    fn create(config: NamespaceConfig) -> Result<NamespaceSet>;

    /// Enter existing namespace
    fn enter(ns_type: NamespaceType, fd: RawFd) -> Result<()>;

    /// Get namespace file descriptor
    fn fd(&self, ns_type: NamespaceType) -> Result<RawFd>;
}
```

### Cgroup Management

```rust
/// Cgroup configuration
pub struct CgroupConfig {
    pub cpu: Option<CpuConfig>,
    pub memory: Option<MemoryConfig>,
    pub io: Option<IoConfig>,
    pub pids: Option<PidsConfig>,
}

pub struct CpuConfig {
    pub quota: Option<i64>,      // microseconds per period
    pub period: Option<i64>,     // microseconds
    pub weight: Option<u16>,     // 1-10000
}

pub struct MemoryConfig {
    pub max: Option<u64>,        // bytes
    pub high: Option<u64>,       // bytes (soft limit)
    pub swap_max: Option<u64>,   // bytes
}

/// Cgroup operations
pub trait CgroupOps {
    /// Create cgroup for container
    fn create(name: &str, config: CgroupConfig) -> Result<Self>;

    /// Add process to cgroup
    fn add_process(&self, pid: i32) -> Result<()>;

    /// Freeze cgroup (pause containers)
    fn freeze(&self) -> Result<()>;

    /// Thaw cgroup (resume containers)
    fn thaw(&self) -> Result<()>;

    /// Delete cgroup
    fn delete(self) -> Result<()>;
}
```

---

## 5. Sequence Diagrams

### Container Creation Flow

```
User                CLI               ferro-exec           Kernel
  |                  |                    |                  |
  |-- create ------->|                    |                  |
  |                  |-- OciSpec -------->|                  |
  |                  |                    |-- unshare() ---->|
  |                  |                    |<-- new ns -------|
  |                  |                    |                  |
  |                  |                    |-- clone() ------>|
  |                  |                    |<-- child pid ----|
  |                  |                    |                  |
  |                  |                    |-- cgroup.create->|
  |                  |                    |<-- cgroup path --|
  |                  |                    |                  |
  |                  |                    |-- cgroup.add(pid)>
  |                  |                    |                  |
  |                  |                    |-- exec in child->|
  |                  |                    |                  |
  |                  |<-- container_id ---|                  |
  |<-- created ------|                    |                  |
```

### Rootless Container Setup

```
User                ferro-exec           /etc/subuid        Kernel
  |                     |                    |                 |
  |-- create(rootless)->|                    |                 |
  |                     |-- read ------------>|                 |
  |                     |<-- 100000:65536 ----|                 |
  |                     |                    |                 |
  |                     |-- unshare(CLONE_NEWUSER) ----------->|
  |                     |<-- new user ns ----------------------|
  |                     |                    |                 |
  |                     |-- write /proc/pid/uid_map ---------->|
  |                     |   "0 100000 65536"                   |
  |                     |                    |                 |
  |                     |-- write /proc/pid/gid_map ---------->|
  |                     |   "0 100000 65536"                   |
  |                     |                    |                 |
  |                     |-- continue with mapped IDs --------->|
```

---

## 6. Testing Strategy

### Unit Tests
- Namespace creation/destruction
- Cgroup configuration parsing
- OCI spec validation
- User namespace ID mapping
- Signal handling

### Integration Tests
- Run Alpine container rootless
- Resource limit enforcement
- Container pause/resume
- Graceful shutdown
- Container exec

### Performance Tests
- Container startup time (<100ms)
- Namespace creation (<1ms)
- Cgroup operations (<5ms)

### Security Tests
- Privilege escalation attempts
- Namespace escape attempts
- Cgroup bypass attempts

---

## 7. Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| Kernel version incompatibility | High | Version detection, clear error messages |
| User namespace disabled | High | Check kernel config, provide setup instructions |
| cgroup delegation failure | Medium | Fallback instructions, systemd integration |
| Namespace leak | Medium | Resource tracking, cleanup on error |

---

## 8. Acceptance Criteria

This epic is complete when:

1. **Functional**
   - [ ] Containers can be created, started, stopped, and deleted
   - [ ] Rootless containers work without root privileges
   - [ ] Resource limits are enforced correctly
   - [ ] OCI bundles execute correctly

2. **Performance**
   - [ ] Container startup <100ms cold, <50ms warm
   - [ ] Zero idle memory consumption
   - [ ] Per-container overhead <2MB

3. **Security**
   - [ ] No privilege escalation possible
   - [ ] Container isolation verified
   - [ ] No unsafe code without safety documentation

4. **Compliance**
   - [ ] OCI Runtime Spec v1.2 compliant
   - [ ] Passes OCI runtime-validator

---

*Epic Owner: TBD | Last Updated: 2026-02-11*
