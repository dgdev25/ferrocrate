# FerroCrate Security Model

## Executive Summary

FerroCrate implements a defense-in-depth security architecture with secure defaults. The runtime is written in Rust for memory safety, runs rootless by default, and provides comprehensive audit logging. This document details the security requirements, implementation approach, and threat model.

---

## 1. Security Architecture Overview

### 1.1 Design Principles

1. **Secure by Default**: All security features enabled unless explicitly disabled
2. **Defense in Depth**: Multiple independent security layers
3. **Least Privilege**: Minimal permissions for all operations
4. **Fail Secure**: Security failures result in denied operations
5. **Transparency**: All security decisions logged and explainable

### 1.2 Security Layers

```
┌─────────────────────────────────────────────────────────────────┐
│                     Application Layer                           │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Container Process                           │   │
│  │  ┌─────────────────────────────────────────────────┐    │   │
│  │  │         User Application Code                    │    │   │
│  │  └─────────────────────────────────────────────────┘    │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Runtime Security                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐     │
│  │  Seccomp    │  │  Capabilities│  │  no_new_privs       │     │
│  │  Profile    │  │  Dropping   │  │  Flag               │     │
│  └─────────────┘  └─────────────┘  └─────────────────────┘     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Isolation Layer                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐     │
│  │   User      │  │   Network   │  │     Filesystem      │     │
│  │  Namespace  │  │  Namespace  │  │     Isolation       │     │
│  └─────────────┘  └─────────────┘  └─────────────────────┘     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Mandatory Access Control                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐     │
│  │  AppArmor   │  │  SELinux    │  │     Landlock        │     │
│  │  Profile    │  │  Context    │  │     Rules           │     │
│  └─────────────┘  └─────────────┘  └─────────────────────┘     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Resource Control                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐     │
│  │  cgroups v2 │  │  Resource   │  │     PID             │     │
│  │  Limits     │  │  Quotas     │  │     Limits          │     │
│  └─────────────┘  └─────────────┘  └─────────────────────┘     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Host Kernel                                │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Linux 5.10+ with security modules          │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Rootless Operation (SEC-01)

### 2.1 Requirement

**SEC-01**: Rootless operation by default with user namespace isolation without root privileges.

### 2.2 Implementation

FerroCrate runs entirely without root privileges using Linux user namespaces.

#### User Namespace ID Mapping

```
┌────────────────────────────────────────────────────────────────┐
│                    User Namespace Mapping                       │
├────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Container (Inside)          Host (Outside)                     │
│  ──────────────────          ──────────────                     │
│  UID 0 (root)       ──►      UID 100000                         │
│  UID 1              ──►      UID 100001                         │
│  UID 65534          ──►      UID 165534                         │
│                                                                 │
│  GID 0 (root)       ──►      GID 100000                         │
│  GID 1              ──►      GID 100001                         │
│  GID 65534          ──►      GID 165534                         │
│                                                                 │
└────────────────────────────────────────────────────────────────┘
```

#### Configuration Sources

1. **/etc/subuid**: User-specific subordinate UID ranges
   ```
   username:100000:65536
   ```

2. **/etc/subgid**: User-specific subordinate GID ranges
   ```
   username:100000:65536
   ```

3. **Default mapping** (when /etc/subuid unavailable):
   - Container UID 0 → Host UID of current user
   - Container GID 0 → Host GID of current user

#### Technical Implementation

```rust
// Pseudo-code for user namespace setup
fn setup_user_namespace(config: &UserNamespaceConfig) -> Result<()> {
    // 1. Clone with CLONE_NEWUSER flag
    let pid = clone(
        CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS,
        &mut stack,
    )?;

    // 2. Write UID mapping (in child before exec)
    let uid_map = format!("0 {} {}", config.host_uid, config.count);
    fs::write("/proc/self/uid_map", &uid_map)?;

    // 3. Disable setgroups for unprivileged mapping
    fs::write("/proc/self/setgroups", "deny")?;

    // 4. Write GID mapping
    let gid_map = format!("0 {} {}", config.host_gid, config.count);
    fs::write("/proc/self/gid_map", &gid_map)?;

    Ok(())
}
```

### 2.3 Verification

- [ ] Container runs as non-root host user
- [ ] No sudo required for any container operation
- [ ] Container processes visible in `ps` with mapped UIDs
- [ ] File access limited to user-accessible paths
- [ ] Privileged operations fail gracefully

---

## 3. Seccomp Profiles (SEC-02)

### 3.1 Requirement

**SEC-02**: Seccomp profiles with default blocking of dangerous syscalls and custom profile loading.

### 3.2 Default Profile

The default seccomp profile blocks syscalls that are:
- Known to be dangerous or rarely needed
- Commonly used in container escapes
- Hardware-specific or debugging-related

#### Blocked Syscalls (Default Profile)

| Syscall | Reason | Risk Level |
|---------|--------|------------|
| `kexec_load` | Load new kernel | Critical |
| `kexec_file_load` | Load new kernel | Critical |
| `init_module` | Load kernel modules | Critical |
| `finit_module` | Load kernel modules | Critical |
| `delete_module` | Remove kernel modules | Critical |
| `acct` | Enable process accounting | High |
| `swapon` | Enable swap | High |
| `swapoff` | Disable swap | High |
| `reboot` | Reboot system | Critical |
| `settimeofday` | Change system time | Medium |
| `stime` | Change system time | Medium |
| `clock_settime` | Change system time | Medium |
| `adjtimex` | Adjust system clock | Medium |
| `pivot_root` | Change root filesystem | High |
| `chroot` | Change root directory | Medium |
| `mount` | Mount filesystems | High |
| `umount` | Unmount filesystems | High |
| `umount2` | Unmount filesystems | High |
| `ptrace` | Process tracing | High |
| `process_vm_readv` | Read other process memory | High |
| `process_vm_writev` | Write other process memory | High |
| `bpf` | eBPF syscall | High |
| `perf_event_open` | Performance monitoring | Medium |
| `kcmp` | Compare processes | Low |
| `userfaultfd` | User-space page fault handling | Medium |
| `io_setup` | Async I/O setup | Low |
| `io_destroy` | Async I/O destroy | Low |
| `io_getevents` | Async I/O events | Low |
| `io_submit` | Async I/O submit | Low |
| `io_cancel` | Async I/O cancel | Low |
| `ioprio_set` | Set I/O priority | Low |
| `ioprio_get` | Get I/O priority | Low |
| `syslog` | Read kernel syslog | Low |
| `mknod` | Create device files | Medium |
| `mknodat` | Create device files | Medium |
| `acct` | Process accounting | Low |

#### Allowed Syscalls with Restrictions

| Syscall | Restriction |
|---------|-------------|
| `clone` | Flags filtered (no CLONE_NEW*) |
| `unshare` | Flags filtered |
| `setns` | Namespace restrictions |
| `ioctl` | Subcommand filtering |
| `prctl` | Subcommand filtering |

### 3.3 Custom Profile Format

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "defaultErrnoRet": 1,
  "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X32"],
  "syscalls": [
    {
      "names": ["read", "write", "open", "close"],
      "action": "SCMP_ACT_ALLOW"
    },
    {
      "names": ["clone"],
      "action": "SCMP_ACT_ALLOW",
      "args": [
        {
          "index": 0,
          "value": 2080505856,
          "valueTwo": 0,
          "op": "SCMP_CMP_MASKED_EQ"
        }
      ]
    }
  ]
}
```

### 3.4 Implementation Notes

- Use libseccomp Rust bindings (`seccomp` crate)
- Profile applied before container process execs
- Profile inherited by all child processes
- Audit logging for blocked syscalls

---

## 4. Capability Dropping (SEC-04)

### 4.1 Requirement

**SEC-04**: All Linux capabilities dropped by default; only explicitly granted capabilities available.

### 4.2 Capability Model

#### Default: All Dropped

```
Initial capabilities (after clone): NONE
Add capabilities only via: --cap-add=<CAP>
```

#### Available Capabilities (for --cap-add)

| Capability | Use Case | Risk |
|------------|----------|------|
| CAP_NET_BIND_SERVICE | Bind ports < 1024 | Low |
| CAP_NET_RAW | Raw sockets | Medium |
| CAP_NET_ADMIN | Network config | High |
| CAP_SYS_ADMIN | Various admin ops | Critical |
| CAP_SYS_PTRACE | Process debugging | High |
| CAP_SYS_CHROOT | Chroot | Medium |
| CAP_KILL | Signal any process | Medium |
| CAP_AUDIT_WRITE | Write audit records | Low |
| CAP_SETUID | Change UID | Medium |
| CAP_SETGID | Change GID | Medium |
| CAP_FOWNER | Bypass file owner checks | Medium |
| CAP_DAC_OVERRIDE | Bypass DAC | High |
| CAP_MKNOD | Create device nodes | High |

### 4.3 Implementation

```rust
fn apply_capabilities(requested: &[Capability]) -> Result<()> {
    use caps::{CapSet, Capability};

    // Drop all capabilities from all sets
    for capset in &[CapSet::Effective, CapSet::Permitted, CapSet::Inheritable] {
        caps::clear(None, *capset)?;
    }

    // Add only requested capabilities
    for cap in requested {
        caps::raise(None, CapSet::Effective, *cap)?;
        caps::raise(None, CapSet::Permitted, *cap)?;
        caps::raise(None, CapSet::Inheritable, *cap)?;
    }

    Ok(())
}
```

---

## 5. No-New-Privileges (SEC-06)

### 5.1 Requirement

**SEC-06**: Processes cannot gain privileges via setuid/setgid binaries.

### 5.2 Implementation

Always set PR_SET_NO_NEW_PRIVS before exec:

```rust
fn set_no_new_privs() -> Result<()> {
    const PR_SET_NO_NEW_PRIVS: i32 = 38;

    unsafe {
        let ret = libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        if ret < 0 {
            return Err(Error::from_errno());
        }
    }

    Ok(())
}
```

### 5.3 Effects

- setuid binaries run with caller's privileges
- setgid binaries run with caller's privileges
- File capability bits ignored
- Inherited across fork/clone/exec

---

## 6. AppArmor/SELinux Integration (SEC-03)

### 6.1 Requirement

**SEC-03**: MAC enforcement for container processes.

### 6.2 AppArmor Integration

#### Default Profile

```
#include <tunables/global>
profile ferrocrate-default flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  # Deny all by default
  deny /** wl,

  # Allow container rootfs
  /var/lib/ferrocrate/containers/** r,
  /**/upper/** rw,
  /**/work/** rw,

  # Allow standard paths
  /dev/null rw,
  /dev/zero rw,
  /dev/random r,
  /dev/urandom r,
  /dev/tty rw,
  /dev/pts/** rw,
  /proc/** r,
  /sys/** r,

  # Network
  network inet tcp,
  network inet udp,
  network inet6 tcp,
  network inet6 udp,
  network unix,

  # Signals
  signal (receive) peer=unconfined,
}
```

#### Profile Application

```bash
# Apply profile at container start
ferrocrate run --security-opt apparmor=ferrocrate-default image
```

### 6.3 SELinux Integration

#### Context Assignment

```bash
# Assign SELinux context
ferrocrate run --security-opt label=type:container_t image
```

#### Default Types

| Type | Purpose |
|------|---------|
| container_t | Standard container |
| container_net_t | Network operations |
| container_ro_t | Read-only container |

---

## 7. Read-Only Rootfs (SEC-05)

### 7.1 Requirement

**SEC-05**: Read-only root filesystem by default in production mode.

### 7.2 Implementation

```
OverlayFS Structure:
┌─────────────────────────────────────┐
│           Merged View               │  ← Container sees this
├─────────────────────────────────────┤
│         Upper Layer (rw)            │  ← Only for /var, /tmp
├─────────────────────────────────────┤
│         Lower Layers (ro)           │  ← Image layers
└─────────────────────────────────────┘
```

### 7.3 Writable Paths (with --read-only)

- /tmp (tmpfs)
- /var (tmpfs or named volume)
- /run (tmpfs)
- Any explicitly mounted volumes

### 7.4 Profile-Based Defaults

| Profile | Rootfs | Writable Paths |
|---------|--------|----------------|
| dev | read-write | all |
| prod | read-only | /tmp, /var, /run |
| secure | read-only | /tmp only (tmpfs) |

---

## 8. Image Signature Verification (SEC-07)

### 8.1 Requirement

**SEC-07**: Cosign/Sigstore signature verification before container execution.

### 8.2 Verification Flow

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Pull Image    │────►│  Fetch Signatures│────►│  Verify Signatures│
│   Manifest      │     │   from OCI       │     │   against Keys    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                        │
                                                        ▼
                        ┌─────────────────┐     ┌─────────────────┐
                        │   Allow/Deny    │◄────│  Check Policy    │
                        │   Execution     │     │   Configuration  │
                        └─────────────────┘     └─────────────────┘
```

### 8.3 Configuration

```toml
# /etc/ferrocrate/signing.toml

[policy]
default = "verify"  # verify, audit, ignore

[[keys]]
name = "company-key"
public_key = "/etc/ferrocrate/keys/company.pub"

[[policies]]
pattern = "registry.company.com/*"
required_signatures = 1
keys = ["company-key"]

[[policies]]
pattern = "*"
action = "warn"  # Allow unsigned but warn
```

### 8.4 CLI Usage

```bash
# Verify before run
ferrocrate run --verify-signature myapp:latest

# Explicit public key
ferrocrate run --verify-signature --public-key /path/to/key.pub myapp:latest

# Fulcio (Sigstore) verification
ferrocrate run --verify-signature --fulcio myapp:latest
```

---

## 9. Audit Logging (SEC-10)

### 9.1 Requirement

**SEC-10**: Structured JSON logs for compliance requirements covering all container operations.

### 9.2 Log Format

```json
{
  "timestamp": "2026-02-11T10:30:00.000Z",
  "event_id": "evt_abc123",
  "event_type": "container.create",
  "actor": {
    "type": "user",
    "id": "dana",
    "ip": "192.168.1.100"
  },
  "resource": {
    "type": "container",
    "id": "ctr_xyz789",
    "image": "nginx:latest",
    "name": "web-server"
  },
  "action": {
    "operation": "create",
    "parameters": {
      "memory": "512m",
      "cpu": "1.0",
      "rootless": true,
      "security_profile": "default"
    },
    "result": "success"
  },
  "security": {
    "seccomp": "default",
    "capabilities": [],
    "apparmor": "ferrocrate-default",
    "rootless": true,
    "read_only_rootfs": true
  },
  "metadata": {
    "hostname": "server01",
    "ferrocrate_version": "1.0.0",
    "kernel_version": "6.1.0"
  }
}
```

### 9.3 Audited Events

| Event Type | Description |
|------------|-------------|
| container.create | Container creation |
| container.start | Container start |
| container.stop | Container stop |
| container.kill | Container kill signal |
| container.remove | Container deletion |
| container.exec | Command execution in container |
| image.pull | Image download |
| image.push | Image upload |
| image.build | Image build |
| image.remove | Image deletion |
| network.create | Network creation |
| volume.create | Volume creation |
| auth.login | Authentication event |
| security.violation | Security policy violation |
| ai.decision | AI-powered decision |

### 9.4 Log Retention

```toml
# /etc/ferrocrate/audit.toml

[retention]
max_size_mb = 1000
max_days = 90
compress_after_days = 7

[output]
path = "/var/log/ferrocrate/audit.json"
format = "json"
flush_interval_secs = 5
```

---

## 10. eBPF Security Monitoring (SEC-08)

### 10.1 Requirement

**SEC-08**: Real-time syscall auditing and anomaly detection via eBPF.

### 10.2 Monitored Events

| Event Type | Description | Alert Condition |
|------------|-------------|-----------------|
| execve | Process execution | Unknown binary |
| connect | Network connection | Unexpected destination |
| open | File open | Sensitive file access |
| ptrace | Process tracing | Any use |
| mount | Filesystem mount | Any use |
| unshare | Namespace unshare | Unexpected namespace |

### 10.3 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      User Space                              │
│  ┌─────────────────┐     ┌─────────────────────────────┐   │
│  │  FerroCrate     │     │     ferro-mind              │   │
│  │  Runtime        │◄────│     AI Analysis             │   │
│  └─────────────────┘     └─────────────────────────────┘   │
│          ▲                              ▲                   │
│          │ Events (via perf buffer)     │ Alerts            │
│          │                              │                   │
├──────────┼──────────────────────────────┼───────────────────┤
│          │                              │                   │
│  ┌───────▼──────────────────────────────▼───────────────┐   │
│  │                    Kernel Space                       │   │
│  │  ┌───────────────────────────────────────────────┐   │   │
│  │  │               eBPF Programs                    │   │   │
│  │  │  ┌─────────────┐  ┌─────────────┐             │   │   │
│  │  │  │ tracepoint/ │  │ tracepoint/ │   ...       │   │   │
│  │  │  │ syscalls/   │  │ syscalls/   │             │   │   │
│  │  │  │ sys_enter_  │  │ sys_enter_  │             │   │   │
│  │  │  │ execve      │  │ connect     │             │   │   │
│  │  │  └─────────────┘  └─────────────┘             │   │   │
│  │  └───────────────────────────────────────────────┘   │   │
│  └───────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## 11. Threat Model

### 11.1 Threat Categories

| Threat | Mitigation | Residual Risk |
|--------|------------|---------------|
| Container escape via kernel exploit | User namespaces, seccomp | Low |
| Privilege escalation | no_new_privs, capability dropping | Very Low |
| Resource exhaustion | cgroups limits | Low |
| Network eavesdropping | Encrypted overlay (P2) | Medium (P1 without) |
| Malicious image | Signature verification, CVE scanning | Low |
| Data exfiltration | Network policies, audit logging | Medium |
| Runtime compromise | Rust memory safety, minimal privileges | Very Low |

### 11.2 Attack Surfaces

```
┌─────────────────────────────────────────────────────────────┐
│                      Attack Surfaces                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. CLI Input                                                │
│     └── Mitigated by: Input validation, privilege separation │
│                                                              │
│  2. Image Content                                            │
│     └── Mitigated by: Signature verification, sandboxing     │
│                                                              │
│  3. Network Input                                            │
│     └── Mitigated by: Network namespaces, eBPF filtering     │
│                                                              │
│  4. Container Process Output                                 │
│     └── Mitigated by: Seccomp, capability dropping           │
│                                                              │
│  5. Configuration Files                                      │
│     └── Mitigated by: File permissions, validation           │
│                                                              │
│  6. Kernel Interfaces                                        │
│     └── Mitigated by: User namespaces, minimal syscalls      │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 12. Compliance Considerations

### 12.1 Supported Frameworks

| Framework | Relevant Controls | FerroCrate Support |
|-----------|-------------------|-------------------|
| SOC 2 | Access control, audit logging | Full |
| PCI DSS | Network isolation, audit trails | Full |
| HIPAA | Access controls, audit logging | Full |
| NIST 800-53 | AC, AU, SC controls | Full |
| CIS Docker Benchmark | Container security | Full compliance |

### 12.2 Audit Trail Requirements

| Requirement | Implementation |
|-------------|----------------|
| Event recording | All operations logged to audit.json |
| Timestamp precision | Millisecond accuracy |
| Actor identification | User ID, source IP |
| Data integrity | Append-only log files |
| Retention | Configurable, default 90 days |
| Export | JSON format, SIEM compatible |

---

## 13. Security Configuration Summary

```toml
# /etc/ferrocrate/security.toml

[default]
rootless = true
seccomp_profile = "default"
apparmor_profile = "ferrocrate-default"
capabilities = []  # None by default
no_new_privileges = true
read_only_rootfs = true

[network]
default_bridge = "ferro0"
iptables = false  # Use eBPF instead
encrypted_overlay = false  # P2 feature

[audit]
enabled = true
path = "/var/log/ferrocrate/audit.json"
format = "json"

[monitoring]
ebpf_tracing = true
anomaly_detection = true
alert_webhook = ""  # Optional webhook for alerts

[signing]
verify_by_default = false  # Explicit --verify-signature needed
policy_file = "/etc/ferrocrate/signing.toml"
```

---

## Document Information

| Field | Value |
|-------|-------|
| Version | 1.0 |
| Last Updated | 2026-02-11 |
| Author | FerroCrate Security Team |
| Review Status | Draft |
| Classification | Internal |

---

*This document is approximately 450 lines and provides comprehensive coverage of the FerroCrate security model.*
