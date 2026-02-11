# FerroCrate Specification

**SPARC Phase:** Specification
**Version:** 1.0
**Date:** February 11, 2026
**Status:** Draft

---

## 1. Overview

FerroCrate is an AI-native container runtime built in Rust that addresses five critical problems with existing container runtimes:

1. **Resource Waste** - Docker consumes 120-180MB at idle
2. **Dumb Failure Handling** - Blind restart loops without diagnostics
3. **Dev/Prod Split** - Different runtimes cause "works on my machine" bugs
4. **No ML/AI Awareness** - Manual GPU/VRAM management
5. **Edge Impracticality** - Runtime overhead too high for constrained devices

### Design Philosophy

- **Zero-Cost Abstractions**: Rust ensures AI features add no overhead when disabled
- **Defense in Depth**: Rootless by default, memory-safe, capability-constrained
- **Intelligence Optional**: All AI features disable via single flag with identical behavior
- **Standards Compliant**: OCI Image, Runtime, and Distribution specs are law

---

## 2. Container Lifecycle State Machine

### 2.1 State Definitions

```
                    ┌─────────────────────────────────────────────────────────┐
                    │                                                         │
                    ▼                                                         │
              ┌──────────┐                                                    │
              │ CREATED  │ ◄─── ferrocrate create                            │
              └────┬─────┘                                                    │
                   │                                                          │
         ┌─────────┼─────────┐                                                │
         │         │         │                                                │
         ▼         ▼         ▼                                                │
    ┌─────────┐ ┌─────────┐ ┌─────────┐                                      │
    │ RUNNING │ │  PAUSED │ │ STOPPED │                                      │
    └────┬────┘ └────┬────┘ └────┬────┘                                      │
         │           │           │                                            │
         │           │           │                                            │
         ▼           ▼           ▼                                            │
    ┌─────────────────────────────────┐                                      │
    │          RESTARTING             │◄─── Intelligent Restart              │
    │  (AI-driven diagnostic cycle)   │                                      │
    └─────────────────────────────────┘                                      │
         │                                                                   │
         ▼                                                                   │
    ┌──────────┐                                                             │
    │ REMOVED  │────► [TERMINAL]                                             │
    └──────────┘                                                             │
```

### 2.2 State Transitions

| From State | To State | Trigger | Preconditions | Postconditions |
|------------|----------|---------|---------------|----------------|
| (none) | CREATED | `ferrocrate create` | Image exists in store | Container rootfs prepared, config loaded |
| CREATED | RUNNING | `ferrocrate start` | Resources available | Process spawned, namespaces created |
| CREATED | REMOVED | `ferrocrate rm` | Container not running | Rootfs deleted, metadata removed |
| RUNNING | STOPPED | `ferrocrate stop` | Process running | Process terminated (SIGTERM→SIGKILL) |
| RUNNING | PAUSED | `ferrocrate pause` | Process running | Cgroup freezer applied |
| RUNNING | RESTARTING | `ferrocrate restart` OR crash | Container has restart policy | Diagnostic cycle initiated |
| PAUSED | RUNNING | `ferrocrate unpause` | Cgroup frozen | Cgroup thawed |
| STOPPED | RUNNING | `ferrocrate start` | Container not removed | New process spawned |
| STOPPED | REMOVED | `ferrocrate rm` | Container stopped | Rootfs deleted |
| RESTARTING | RUNNING | Diagnostic complete | Fix applied (if any) | Process respawned with adjustments |

### 2.3 Exit Codes and Signals

| Exit Code | Meaning | Restart Policy Action |
|-----------|---------|----------------------|
| 0 | Clean exit | Restart if `always` or `unless-stopped` |
| 1-125 | Application error | Restart if `on-failure` or `always` |
| 126 | Command not executable | No restart (configuration error) |
| 127 | Command not found | No restart (configuration error) |
| 128+N | Signal N received | Restart if `on-failure` or `always` |
| 137 | SIGKILL (OOM) | Intelligent restart with memory adjustment |

### 2.4 Intelligent Restart Protocol

```
RESTARTING State Machine:

1. DETECT ──► Why did container exit?
   │
   ├─► OOM Kill ──► ANALYZE_MEMORY
   ├─► Segfault ──► ANALYZE_COREDUMP
   ├─► Signal ──► CHECK_SIGNAL_POLICY
   └─► Normal ──► CHECK_RESTART_POLICY
   │
   ▼
2. ANALYZE ──► AI diagnostic (WASM inference)
   │
   ├─► Predictable pattern ──► APPLY_FIX
   ├─► Unknown pattern ──► LOG_AND_RESTART
   └─► Configuration error ──► ALERT_USER
   │
   ▼
3. APPLY_FIX ──► Adjust container config
   │
   ├─► Increase memory limit (if OOM)
   ├─► Adjust CPU shares
   ├─► Modify environment
   └─► No fix needed ──► DIRECT_RESTART
   │
   ▼
4. RESTART ──► Spawn new process with adjustments
```

---

## 3. Image Management Workflows

### 3.1 Image Pull Workflow

```
ferrocrate pull registry.example.com/image:tag

┌─────────────────────────────────────────────────────────────────────────┐
│ 1. MANIFEST FETCH                                                       │
│    ┌─────────────┐     ┌─────────────┐     ┌─────────────┐             │
│    │ Authenticate│────►│ Fetch Index │────►│ Resolve Tag │             │
│    │ (if needed) │     │ (manifest)  │     │ → Manifest  │             │
│    └─────────────┘     └─────────────┘     └──────┬──────┘             │
│                                                   │                     │
│ 2. LAYER RESOLUTION                              ▼                     │
│    ┌─────────────────────────────────────────────────────────┐         │
│    │ For each layer digest in manifest:                      │         │
│    │   ┌────────────────┐     ┌────────────────┐             │         │
│    │   │ Check local    │────►│ Skip if exists │             │         │
│    │   │ Blake3 store   │     │ (dedup hit)    │             │         │
│    │   └───────┬────────┘     └────────────────┘             │         │
│    │           │ missing                                      │         │
│    │           ▼                                              │         │
│    │   ┌────────────────┐     ┌────────────────┐             │         │
│    │   │ Download blob  │────►│ Verify digest  │             │         │
│    │   │ (concurrent)   │     │ (SHA256)       │             │         │
│    │   └────────────────┘     └────────────────┘             │         │
│    └─────────────────────────────────────────────────────────┘         │
│                                                   │                     │
│ 3. STORAGE                                        ▼                     │
│    ┌─────────────────────────────────────────────────────────┐         │
│    │ For each new layer:                                     │         │
│    │   ┌────────────────┐     ┌────────────────┐             │         │
│    │   │ Decompress     │────►│ Extract files  │             │         │
│    │   │ (zstd/gzip)    │     │ to temp dir    │             │         │
│    │   └───────┬────────┘     └───────┬────────┘             │         │
│    │           │                      │                       │         │
│    │           ▼                      ▼                       │         │
│    │   ┌────────────────┐     ┌────────────────┐             │         │
│    │   │ Blake3 hash    │────►│ Store in CAS   │             │         │
│    │   │ each file      │     │ (content-addr) │             │         │
│    │   └────────────────┘     └────────────────┘             │         │
│    └─────────────────────────────────────────────────────────┘         │
│                                                   │                     │
│ 4. FINALIZE                                       ▼                     │
│    ┌────────────────┐     ┌────────────────┐     ┌────────────────┐    │
│    │ Update image   │────►│ Create image   │────►│ Update tag     │    │
│    │ metadata DB    │     │ manifest ref   │     │ index          │    │
│    └────────────────┘     └────────────────┘     └────────────────┘    │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Content-Addressable Storage

```
Storage Layout:
/data/ferrocrate/
├── blobs/
│   └── blake3/
│       ├── a/
│       │   └── abc123...def    # File content keyed by Blake3 hash
│       ├── b/
│       │   └── bcd234...efa
│       └── ...
├── layers/
│   └── sha256:layer-digest/
│       └── manifest.json       # Layer-to-file mapping
├── images/
│   └── sha256:image-digest/
│       ├── manifest.json       # OCI manifest
│       ├── config.json         # OCI config
│       └── tags                # Local tag references
└── repositories/
    └── registry.example.com/
        └── namespace/
            └── image/
                └── tags        # Tag → digest mapping
```

### 3.3 Layer Deduplication

```
Deduplication Algorithm:

INPUT: Layer tarball (compressed or uncompressed)
OUTPUT: Set of Blake3 file references

1. Extract tarball to temporary directory
2. For each regular file:
   a. Compute Blake3 hash of content
   b. Check /blobs/blake3/{hash_prefix}/{hash}
   c. If exists:
        - Increment refcount
        - Record hardlink path
      Else:
        - Store file in CAS
        - Set refcount = 1
3. Create layer manifest:
   {
     "version": "1.0",
     "files": [
       {"path": "/app/main", "blake3": "abc...", "mode": "0755"},
       {"path": "/app/config.yaml", "blake3": "def...", "mode": "0644"}
     ],
     "whiteouts": ["/etc/passwd"]  # OCI whiteout markers
   }
4. Delete temporary directory
5. Return layer manifest hash
```

### 3.4 Build Workflow

```
ferrocrate build -t myimage:latest .

┌─────────────────────────────────────────────────────────────────────────┐
│ 1. PARSE DOCKERFILE                                                     │
│    ┌─────────────────┐                                                  │
│    │ Read Dockerfile │────► Validate syntax                            │
│    └────────┬────────┘                                                  │
│             │                                                            │
│             ▼                                                            │
│    ┌─────────────────┐                                                  │
│    │ Convert to IR   │────► Internal representation                     │
│    │ (Instruction)   │                                                  │
│    └────────┬────────┘                                                  │
│             │                                                            │
│ 2. RESOLVE BASE IMAGE                                                   │
│    ┌─────────────────┐     ┌─────────────────┐                         │
│    │ Pull if needed  │────►│ Extract to      │                         │
│    │ (IMG-01)        │     │ build context   │                         │
│    └─────────────────┘     └─────────────────┘                         │
│                                                                          │
│ 3. EXECUTE INSTRUCTIONS (with caching)                                  │
│    For each instruction:                                                │
│    ┌─────────────────────────────────────────────────────────────┐     │
│    │ ┌───────────────┐     ┌───────────────┐                     │     │
│    │ │ Compute cache │────►│ Skip if hit   │                     │     │
│    │ │ key           │     │ (use cached)  │                     │     │
│    │ └───────┬───────┘     └───────────────┘                     │     │
│    │         │ miss                                               │     │
│    │         ▼                                                    │     │
│    │ ┌───────────────────────────────────────────────────────┐   │     │
│    │ │ Execute in container namespace:                        │   │     │
│    │ │   - RUN: Execute command, capture fs diff             │   │     │
│    │ │   - COPY: Copy files, compute hashes                   │   │     │
│    │ │   - ENV/ARG: Update environment                       │   │     │
│    │ │   - WORKDIR: Change directory                         │   │     │
│    │ │   - EXPOSE/PORT: Record metadata                      │   │     │
│    │ │   - HEALTHCHECK: Record health config                 │   │     │
│    │ └───────────────────────────────────────────────────────┘   │     │
│    │         │                                                    │     │
│    │         ▼                                                    │     │
│    │ ┌───────────────┐     ┌───────────────┐                     │     │
│    │ │ Snapshot diff │────►│ Create layer  │                     │     │
│    │ │ (OverlayFS)   │     │ (dedup store) │                     │     │
│    │ └───────────────┘     └───────────────┘                     │     │
│    └─────────────────────────────────────────────────────────────┘     │
│                                                                          │
│ 4. CREATE IMAGE                                                         │
│    ┌─────────────────┐     ┌─────────────────┐     ┌───────────────┐  │
│    │ Assemble layers │────►│ Create config   │────►│ Push to store │  │
│    │ into manifest   │     │ (OCI format)    │     │ with tag      │  │
│    └─────────────────┘     └─────────────────┘     └───────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Network Topology Constraints

### 4.1 Network Types

| Network Type | Isolation Level | DNS | Use Case |
|-------------|-----------------|-----|----------|
| `bridge` (default) | Container namespace + virtual bridge | Yes (internal) | Multi-container apps |
| `host` | Host network namespace | Host DNS | High-performance networking |
| `none` | Loopback only | None | Isolated workloads |
| `custom` | User-defined bridge | Yes (configurable) | Service isolation |

### 4.2 Bridge Network Architecture

```
                    Host Network Stack
                    ─────────────────────────────────────────
                    │
    ┌───────────────┼───────────────────┐
    │               │                   │
    ▼               ▼                   ▼
┌───────┐     ┌─────────┐         ┌───────┐
│ eth0  │     │ ferrob0 │         │ eth1  │
└───┬───┘     │(bridge) │         └───────┘
    │         └────┬────┘
    │              │
    │    ┌─────────┼─────────┐
    │    │         │         │
    │    ▼         ▼         ▼
    │ ┌─────┐  ┌─────┐  ┌─────┐
    │ │veth0│  │veth1│  │veth2│  (Host-side veth pairs)
    │ └──┬──┘  └──┬──┘  └──┬──┘
    │    │        │        │
    └────┼────────┼────────┼─────────────────────────────
         │        │        │    Container Network Stack
         │        │        │    ─────────────────────────
         ▼        ▼        ▼
      ┌────┐  ┌────┐  ┌────┐
      │eth0│  │eth0│  │eth0│  (Container-side interfaces)
      └────┘  └────┘  └────┘
        │        │        │
    ┌───┴───┐┌───┴───┐┌───┴───┐
    │Container││Container││Container│
    │   A    ││   B    ││   C    │
    └───────┘└───────┘└───────┘
```

### 4.3 eBPF Packet Forwarding (NET-06)

```
Traditional iptables path:
  Packet → PREROUTING → FORWARD → POSTROUTING → DNAT → SNAT → Interface
           (multiple table lookups, rule chains)

FerroCrate eBPF path:
  Packet → eBPF program (single pass) → Interface

eBPF Program Structure:

┌─────────────────────────────────────────────────────────────────┐
│ TC (Traffic Control) BPF Program attached to ferrob0           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. Parse Ethernet header                                       │
│  2. Parse IP header (IPv4/IPv6)                                │
│  3. Parse TCP/UDP header                                       │
│  4. Lookup port mapping table (BPF map)                        │
│     ┌─────────────────────────────────────────────┐            │
│     │ Key: host_port                              │            │
│     │ Value: { container_ip, container_port }     │            │
│     └─────────────────────────────────────────────┘            │
│  5. If match found:                                            │
│     - DNAT: Rewrite destination to container IP:port           │
│     - Redirect to container veth interface                     │
│  6. If no match:                                               │
│     - Pass through (normal host traffic)                       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 4.4 DNS Resolution

```
Container DNS Resolution:

┌─────────────────────────────────────────────────────────────────┐
│ Container requests DNS lookup for "db"                          │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│ /etc/resolv.conf in container:                                  │
│   nameserver 127.0.0.1    # FerroCrate embedded DNS            │
│   search ferrocrate.local                                       │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│ FerroCrate Embedded DNS (ferro-net-dns):                        │
│                                                                 │
│ 1. Check container name cache                                   │
│    ┌─────────────────────────────────────────────┐              │
│    │ Query: "db"                                 │              │
│    │ Network: "mynetwork"                        │              │
│    │ Result: 172.17.0.3 (container IP of "db")  │              │
│    └─────────────────────────────────────────────┘              │
│                                                                 │
│ 2. If not found in local network, forward to:                  │
│    - Host DNS servers (from /etc/resolv.conf)                  │
│    - User-configured upstream DNS                              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 5. Security Boundaries

### 5.1 Security Layers

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Layer 1: User Namespaces (Rootless)                                    │
│ ─────────────────────────────────────────────────────────────────────── │
│ • Container root (UID 0) → Unprivileged host UID (e.g., 100000)        │
│ • GID mapping for group permissions                                    │
│ • No actual root privileges on host                                    │
└─────────────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Layer 2: Capability Dropping (SEC-04)                                  │
│ ─────────────────────────────────────────────────────────────────────── │
│ Default: All capabilities dropped                                      │
│ Granted only via explicit --cap-add:                                   │
│   • CAP_NET_BIND_SERVICE (bind to ports < 1024)                       │
│   • CAP_SYS_ADMIN (required for some operations)                       │
│   • CAP_CHOWN, CAP_DAC_OVERRIDE, etc.                                  │
└─────────────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Layer 3: Seccomp Filtering (SEC-02)                                    │
│ ─────────────────────────────────────────────────────────────────────── │
│ Default profile blocks:                                                │
│   • kexec_load, kexec_file_load                                       │
│   • init_module, finit_module, delete_module                          │
│   • acct, swapon, swapoff                                             │
│   • perf_event_open, kcmp                                             │
│   • ptrace (unless --cap-add=SYS_PTRACE)                              │
│   • process_vm_readv, process_vm_writev                               │
│   • namespace syscalls (unshare, setns, etc.)                         │
└─────────────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Layer 4: AppArmor/SELinux (SEC-03)                                     │
│ ─────────────────────────────────────────────────────────────────────── │
│ FerroCrate default AppArmor profile:                                   │
│   • Deny access to /proc/*/mem, /proc/*/sys/*                         │
│   • Deny mount, umount                                                 │
│   • Deny ptrace                                                        │
│   • Deny network raw sockets                                           │
│   • Allow read/write to container rootfs                               │
│   • Allow network access within container network                      │
└─────────────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Layer 5: No-New-Privileges (SEC-06)                                    │
│ ─────────────────────────────────────────────────────────────────────── │
│ • prctl(PR_SET_NO_NEW_PRIVS, 1) set on container init                 │
│ • Prevents setuid/setgid elevation                                     │
│ • Prevents file capability execution                                   │
│ • ALWAYS enabled (not configurable)                                    │
└─────────────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Layer 6: Read-Only Rootfs (SEC-05)                                     │
│ ─────────────────────────────────────────────────────────────────────── │
│ Production mode (--profile=prod):                                      │
│   • Rootfs mounted read-only                                           │
│   • Writable overlay only for /tmp, /var, /run                        │
│   • Explicit --read-only=false to override                             │
│                                                                         │
│ Development mode (--profile=dev):                                      │
│   • Full writable overlay (Docker-compatible)                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 5.2 Security Decision Matrix

| Operation | Rootless | Capability Required | Seccomp Allowed | AppArmor Allowed |
|-----------|----------|---------------------|-----------------|------------------|
| Read file in container | Yes | None | Yes | Yes (rootfs) |
| Write file in container | Yes | None | Yes | Yes (rootfs) |
| Bind to port 80 | Yes | NET_BIND_SERVICE | Yes | Yes |
| Ping (ICMP) | Yes | NET_RAW | Yes | No (default) |
| strace another process | Yes | SYS_PTRACE | Conditional | No (default) |
| Mount filesystem | Yes | SYS_ADMIN | No (default) | No (default) |
| Load kernel module | **No** | SYS_MODULE | **No** | **No** |
| Access host /etc/passwd | **No** | None | Yes | **No** |

### 5.3 Rootless Execution Flow

```
ferrocrate run --rootless alpine

┌─────────────────────────────────────────────────────────────────────────┐
│ 1. CHECK PRIVILEGES                                                     │
│    ┌─────────────────────────────────────────────────────────┐          │
│    │ geteuid() == 0?                                         │          │
│    │   Yes → WARN: Running as root, --rootless ignored       │          │
│    │   No  → Continue with rootless setup                    │          │
│    └─────────────────────────────────────────────────────────┘          │
│                                                                         │
│ 2. SETUP USER NAMESPACE                                                 │
│    ┌─────────────────────────────────────────────────────────┐          │
│    │ /etc/subuid: lyle:100000:65536                          │          │
│    │ /etc/subgid: lyle:100000:65536                          │          │
│    │                                                         │          │
│    │ Map: container UID 0 → host UID 100000                  │          │
│    │ Map: container GID 0 → host GID 100000                  │          │
│    └─────────────────────────────────────────────────────────┘          │
│                                                                         │
│ 3. CREATE NAMESPACES                                                    │
│    ┌─────────────────────────────────────────────────────────┐          │
│    │ unshare(CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS |    │          │
│    │         CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS)     │          │
│    └─────────────────────────────────────────────────────────┘          │
│                                                                         │
│ 4. APPLY SECURITY PROFILES                                              │
│    ┌─────────────────────────────────────────────────────────┐          │
│    │ • Write seccomp BPF program                             │          │
│    │ • Load AppArmor profile                                 │          │
│    │ • prctl(PR_SET_NO_NEW_PRIVS, 1)                         │          │
│    │ • capset(drop all, add explicit)                        │          │
│    └─────────────────────────────────────────────────────────┘          │
│                                                                         │
│ 5. EXECUTE CONTAINER                                                    │
│    ┌─────────────────────────────────────────────────────────┐          │
│    │ execve("/entrypoint", args, env)                        │          │
│    └─────────────────────────────────────────────────────────┘          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Entry/Exit Criteria

### Phase 1: Specification (Current)

**Entry Criteria:**
- [x] PRD reviewed and approved
- [x] User personas defined
- [x] Functional requirements prioritized

**Exit Criteria:**
- [x] Container lifecycle state machine documented
- [x] Image management workflows specified
- [x] Network topology constraints defined
- [x] Security boundaries established
- [x] All CLM-*, IMG-*, NET-*, SEC-* requirements mapped to specs

### Phase 2: Pseudocode (Next)

**Entry Criteria:**
- [ ] Specification approved
- [ ] All state machines validated
- [ ] Workflow diagrams complete

**Exit Criteria:**
- [ ] Core algorithms in pseudocode
- [ ] Complexity analysis complete
- [ ] Edge cases identified

---

## Appendix A: Requirement Traceability

| Requirement ID | Section | Priority |
|---------------|---------|----------|
| CLM-01 to CLM-10 | Section 2: Container Lifecycle | P0-P1 |
| IMG-01 to IMG-12 | Section 3: Image Management | P0-P2 |
| NET-01 to NET-10 | Section 4: Network Topology | P0-P2 |
| SEC-01 to SEC-10 | Section 5: Security Boundaries | P0-P2 |

---

## Appendix B: Glossary

| Term | Definition |
|------|------------|
| CAS | Content-Addressable Storage - files stored by hash |
| OCI | Open Container Initiative - container standards body |
| Blake3 | Fast cryptographic hash function used for deduplication |
| eBPF | Extended Berkeley Packet Filter - in-kernel programmable packet processing |
| Rootless | Container execution without root privileges on host |
| OverlayFS | Union filesystem for copy-on-write layering |
