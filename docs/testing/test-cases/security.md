# Security Test Cases

**Component:** All | **Priority:** P0 | **Last Updated:** 2026-02-11

---

## Overview

Security tests are critical for a container runtime. These tests verify isolation, privilege controls, input validation, and attack resistance. All tests in this category are P0 unless otherwise noted.

---

## Attack Surface Model

```
┌─────────────────────────────────────────────────────────────────┐
│                      ATTACK VECTORS                             │
├─────────────────────────────────────────────────────────────────┤
│  1. Untrusted Images        - Malicious tarballs, path traversal │
│  2. Malicious Dockerfiles   - Command injection, resource abuse  │
│  3. Privilege Escalation    - Namespace escape, setuid abuse     │
│  4. Registry Attacks        - MITM, certificate spoofing         │
│  5. Input Validation        - Malformed JSON, injection attacks  │
│  6. Resource Exhaustion     - Memory bombs, fork bombs           │
│  7. Network Attacks         - Port scanning, ARP spoofing        │
│  8. Container Escape        - Kernel exploits, syscall abuse     │
└─────────────────────────────────────────────────────────────────┘
```

---

## Test Categories

### 1. Rootless Operation (SEC-01)

#### TC-SEC-001: Rootless container execution

| Attribute | Value |
|-----------|-------|
| **ID** | TC-SEC-001 |
| **Priority** | P0 |
| **Type** | Security |
| **Automated** | Yes |

**Preconditions:**
- User not root
- Rootless mode enabled

**Steps:**
1. Execute `ferrocrate run alpine id`
2. Verify UID in output

**Expected Result:**
- Container runs as non-root user
- UID mapping configured

---

#### TC-SEC-002: User namespace isolation

| Attribute | Value |
|-----------|-------|
| **ID** | TC-SEC-002 |
| **Priority** | P0 |
| **Type** | Security |
| **Automated** | Yes |

**Steps:**
1. Run container: `ferrocrate run alpine cat /proc/self/uid_map`
2. Verify UID mapping

**Expected Result:**
- UID map shows user namespace mapping
- Root in container maps to unprivileged host UID

---

#### TC-SEC-003: Rootless with explicit user

| Attribute | Value |
|-----------|-------|
| **ID** | TC-SEC-003 |
| **Priority** | P0 |
| **Type** | Security |
| **Automated** | Yes |

**Steps:**
1. Execute `ferrocrate run --user 1000:1000 alpine id`

**Expected Result:**
- Output: uid=1000 gid=1000

---

#### TC-SEC-004: No root on host

| Attribute | Value |
|-----------|-------|
| **ID** | TC-SEC-004 |
| **Priority** | P0 |
| **Type** | Security |
| **Automated** | Yes |

**Preconditions:**
- Monitor host processes

**Steps:**
1. Run container with root-like operations
2. Verify no root process on host

**Expected Result:**
- No process with UID 0 on host
- All container processes mapped to unprivileged UIDs

---

### 2. Seccomp Profiles (SEC-02)

#### TC-SEC-010: Default seccomp enforcement

| Attribute | Value |
|-----------|-------|
| **ID** | TC-SEC-010 |
| **Priority** | P0 |
| **Type** | Security |
| **Automated** | Yes |

**Steps:**
1. Run container with blocked syscall attempt
2. Execute: `ferrocrate run alpine unshare --user echo test`

**Expected Result:**
- Syscall blocked
- EPERM returned

---

#### TC-SEC-011: Custom seccomp profile

| Attribute | Value |
|-----------|-------|
| **ID** | TC-SEC-011 |
| **Priority** | P0 |
| **Type** | Security |
| **Automated** | Yes |

**Preconditions:**
- Custom seccomp profile file

```json
{
  "defaultAction": "SCMP_ACT_ALLOW",
  "syscalls": [
    {
      "names": ["mkdir"],
      "action": "SCMP_ACT_ERRNO"
    }
  ]
}
```

**Steps:**
1. Execute `ferrocrate run --security-opt seccomp=profile.json alpine mkdir /test`

**Expected Result:**
- mkdir syscall blocked
- Operation fails

---

#### TC-SEC-012: Seccomp with all syscalls blocked

| Attribute | Value |
|-----------|-------|
| **ID** | TC-SEC-012 |
| **Priority** | P0 |
| **Type** | Security |
| **Automated** | Yes |

**Preconditions:**
- Profile blocking all syscalls

**Steps:**
1. Run container with restrictive profile

**Expected Result:**
- Container fails to start (essential syscalls blocked)

---

#### TC-SEC-013: Seccomp bypass attempt

| Attribute | Value |
|-----------|-------|
| **ID** | TC-SEC-013 |
| **Priority** | P0 |
| **Type** | Security |
| **Automated** | Yes |

**Steps:**
1. Try various syscall obfuscation techniques
2. Attempt 32-bit compat syscalls

**Expected Result:**
- All bypass attempts fail
- Seccomp applied uniformly

---

### 3. Capability Management (SEC-04)

#### TC-SEC-020: All capabilities dropped by default

| Attribute | Value |
|-----------|-------|
| **ID** | TC-SEC-020 |
| **Priority** | P0 |
| **Type** | Security |
| **Automated** | Yes |

**Steps:**
1. Execute `ferrocrate run alpine capsh --print`
2. Check capabilities list

**Expected Result:**
- Minimal/no capabilities
- All dangerous capabilities dropped

---

#### TC-SEC-021: Add specific capability

| Attribute | Value |
|-----------|-------|
| **ID** | TC-SEC-021 |
| **Priority** | P0 |
| **Type** | Security |
| **Automated** | Yes |

**Steps:**
1. Execute `ferrocrate run --cap-add NET_ADMIN alpine capsh --print`

**Expected Result:**
- CAP_NET_ADMIN in list
- Only specified capability added

---

#### TC-SEC-022: Drop specific capability

| Attribute | Value |
|-----------|-------|
| **ID** | TC-SEC-022 |
| **Priority** | P0 |
| **Type** | Security |
| **Automated** | Yes |

**Preconditions:**
- Image with default capabilities

**Steps:**
1. Execute `ferrocrate run --cap-drop ALL --cap-add CHOWN alpine capsh --print`

**Expected Result:**
- Only CAP_CHOWN present

---

#### TC-SEC-023: Privileged mode warning

| Attribute | Value |
|-----------|-------|
| **ID** | TC-SEC-023 |
| **Priority** | P0 |
| **Type** | Security |
| **Automated** | Yes |

**Steps:**
1. Execute `ferrocrate run --privileged alpine id`

**Expected Result:**
- Warning displayed about privileged mode
- All capabilities granted (user explicitly opted in)

---

### 4. No-New-Privileges (SEC-06)

#### TC-SEC-030: no-new-privileges enforcement

| Attribute | Value |
|-----------|-------|
| **ID** | TC-SEC-030 |
| **Priority** | P0 |
| **Type** | Security |
| **Automated** | Yes |

**Preconditions:**
- setuid binary in image

**Steps:**
1. Run container: `ferrocrate run --security-opt no-new-privileges setuid-test /usr/bin/su -`

**Expected Result:**
- setuid escalation blocked
- EPERM or operation fails

---

#### TC-SEC-031: sudo escalation blocked

| Attribute | Value |
|-----------|-------|
| **ID** | TC-SEC-031 |
| **Priority** | P0 |
| **Type** | Security |
| **Automated** | Yes |

**Preconditions:**
- sudo installed in container
- no-new-privileges enabled

**Steps:**
1. Attempt `sudo` inside container

**Expected Result:**
- sudo fails
- No privilege escalation

---

### 5. Read-Only Rootfs (SEC-05)

#### TC-SEC-040: Read-only root filesystem

| Attribute | Value |
|-----------|-------|
| **ID** | TC-SEC-040 |
| **Priority** | P0 |
| **Type** | Security |
| **Automated** | Yes |

**Steps:**
1. Execute `ferrocrate run --read-only alpine touch /test`
2. Verify write failure

**Expected Result:**
- EROFS error
- Write blocked

---

#### TC-SEC-041: Read-only with tmpfs exception

| Attribute | Value |
|-----------|-------|
| **ID** | TC-SEC-041 |
| **Priority** | P0 |
| **Type** | Security |
| **Automated** | Yes |

**Steps:**
1. Execute `ferrocrate run --read-only --tmpfs /tmp alpine touch /test`
2. Execute `ferrocrate run --read-only --tmpfs /tmp alpine touch /tmp/test`

**Expected Result:**
- Root write blocked
- /tmp write succeeds

---

### 6. Image Security (SEC-07)

#### TC-SEC-050: Path traversal in image

| Attribute | Value |
|-----------|-------|
| **ID** | TC-SEC-050 |
| **Priority** | P0 |
| **Type** | Security |
| **Automated** | Yes |

**Preconditions:**
- Malicious image with path traversal

```
tarball contains:
../../../etc/passwd
../../../../root/.ssh/authorized_keys
```

**Steps:**
1. Pull/extract malicious image
2. Verify file paths normalized

**Expected Result:**
- Path traversal blocked
- Files extracted to safe location or rejected

---

#### TC-SEC-051: Setuid binary in image

| Attribute | Value |
|-----------|-------|
| **ID** | TC-SEC-051 |
| **Priority** | P0 |
| **Type** | Security |
| **Automated** | Yes |

**Preconditions:**
- Image with setuid binary

**Steps:**
1. Pull image with setuid binary
2. Verify setuid bit stripped or warned

**Expected Result:**
- setuid bits removed (configurable)
- Warning logged

---

#### TC-SEC-052: Device files in image

| Attribute | Value |
|-----------|-------|
| **ID** | TC-SEC-052 |
| **Priority** | P0 |
| **Type** | Security |
| **Automated** | Yes |

**Preconditions:**
- Image with device files

**Steps:**
1. Pull image with /dev entries
2. Verify devices not created

**Expected Result:**
- Device files ignored or rejected
- No device nodes on host

---

#### TC-SEC-053: Symlink escape in image

| Attribute | Value |
|-----------|-------|
| **ID** | TC-SEC-053 |
| **Priority** | P0 |
| **Type** | Security |
| **Automated** | Yes |

**Preconditions:**
- Image with symlink pointing outside rootfs

**Steps:**
1. Pull image with escaping symlink
2. Verify symlink contained

**Expected Result:**
- Symlink target contained within rootfs
- No host access via symlink

---

#### TC-SEC-054: Image signature verification

| Attribute | Value |
|-----------|-------|
| **ID** | TC-SEC-054 |
| **Priority** | P1 |
| **Type** | Security |
| **Automated** | Yes |

**Preconditions:**
- Signature verification enabled
- Image signed with cosign

**Steps:**
1. Pull signed image
2. Verify signature checked

**Expected Result:**
- Signature verified before running
- Unsigned image rejected

---

### 7. Registry Security

#### TC-SEC-060: TLS certificate validation

| Attribute | Value |
|-----------|-------|
| **ID** | TC-SEC-060 |
| **Priority** | P0 |
| **Type** | Security |
| **Automated** | Yes |

**Preconditions:**
- Registry with self-signed cert

**Steps:**
1. Pull from registry with invalid cert

**Expected Result:**
- Connection rejected
- Certificate validation enforced

---

#### TC-SEC-061: MITM protection

| Attribute | Value |
|-----------|-------|
| **ID** | TC-SEC-061 |
| **Priority** | P0 |
| **Type** | Security |
| **Automated** | Yes |

**Preconditions:**
- MITM proxy intercepting traffic

**Steps:**
1. Pull image through MITM
2. Verify hash validation

**Expected Result:**
- Tampered content detected
- Blake3 hash mismatch error

---

#### TC-SEC-062: Credential handling

| Attribute | Value |
|-----------|-------|
| **ID** | TC-SEC-062 |
| **Priority** | P0 |
| **Type** | Security |
| **Automated** | Yes |

**Steps:**
1. Configure credentials
2. Check process list for credentials
3. Check log files for credentials

**Expected Result:**
- No credentials in process args
- No credentials in logs
- Credentials securely stored

---

### 8. Namespace Isolation

#### TC-SEC-070: PID namespace isolation

| Attribute | Value |
|-----------|-------|
| **ID** | TC-SEC-070 |
| **Priority** | P0 |
| **Type** | Security |
| **Automated** | Yes |

**Steps:**
1. Run container: `ferrocrate run alpine ps aux`
2. Compare with host processes

**Expected Result:**
- Only container processes visible
- Host processes hidden

---

#### TC-SEC-071: Mount namespace isolation

| Attribute | Value |
|-----------|-------|
| **ID** | TC-SEC-071 |
| **Priority** | P0 |
| **Type** | Security |
| **Automated** | Yes |

**Steps:**
1. Run container: `ferrocrate run alpine mount`
2. Verify no host mounts visible

**Expected Result:**
- Only container mounts visible
- Host filesystem not exposed

---

#### TC-SEC-072: Network namespace isolation

| Attribute | Value |
|-----------|-------|
| **ID** | TC-SEC-072 |
| **Priority** | P0 |
| **Type** | Security |
| **Automated** | Yes |

**Preconditions:**
- Host has sensitive network services

**Steps:**
1. Run container in bridge network
2. Attempt to access host services

**Expected Result:**
- Host network namespace isolated
- Container cannot access host localhost services

---

#### TC-SEC-073: IPC namespace isolation

| Attribute | Value |
|-----------|-------|
| **ID** | TC-SEC-073 |
| **Priority** | P0 |
| **Type** | Security |
| **Automated** | Yes |

**Steps:**
1. Create IPC object on host
2. Run container and try to access IPC

**Expected Result:**
- Host IPC objects not visible
- Container has isolated IPC namespace

---

#### TC-SEC-074: UTS namespace isolation

| Attribute | Value |
|-----------|-------|
| **ID** | TC-SEC-074 |
| **Priority** | P0 |
| **Type** | Security |
| **Automated** | Yes |

**Steps:**
1. Run container: `ferrocrate run --hostname isolated alpine hostname`
2. Verify hostname isolated

**Expected Result:**
- Container has separate hostname
- Host hostname unchanged

---

### 9. Cgroup Isolation

#### TC-SEC-080: Memory limit enforcement

| Attribute | Value |
|-----------|-------|
| **ID** | TC-SEC-080 |
| **Priority** | P0 |
| **Type** | Security |
| **Automated** | Yes |

**Steps:**
1. Run container with memory limit: `ferrocrate run --memory 50m alpine`
2. Attempt to allocate more memory

```sh
# In container
dd if=/dev/zero of=/dev/null bs=1M count=100
```

**Expected Result:**
- OOM kill triggered
- Container memory contained

---

#### TC-SEC-081: CPU limit enforcement

| Attribute | Value |
|-----------|-------|
| **ID** | TC-SEC-081 |
| **Priority** | P0 |
| **Type** | Security |
| **Automated** | Yes |

**Steps:**
1. Run container with CPU limit: `ferrocrate run --cpus 0.5 alpine`
2. Run CPU-intensive task
3. Monitor host CPU usage

**Expected Result:**
- Container CPU usage limited
- Host not affected

---

#### TC-SEC-082: PID limit enforcement

| Attribute | Value |
|-----------|-------|
| **ID** | TC-SEC-082 |
| **Priority** | P0 |
| **Type** | Security |
| **Automated** | Yes |

**Steps:**
1. Run container with PID limit: `ferrocrate run --pids-limit 10 alpine`
2. Attempt fork bomb

```sh
# In container
:(){ :|:& };:
```

**Expected Result:**
- Fork limited
- Container PID limit enforced

---

### 10. Input Validation

#### TC-SEC-090: Malformed JSON input

| Attribute | Value |
|-----------|-------|
| **ID** | TC-SEC-090 |
| **Priority** | P0 |
| **Type** | Security |
| **Automated** | Yes |

**Steps:**
1. Send malformed JSON to API
2. Verify graceful handling

**Expected Result:**
- Parse error returned
- No crash
- No memory leak

---

#### TC-SEC-091: Command injection prevention

| Attribute | Value |
|-----------|-------|
| **ID** | TC-SEC-091 |
| **Priority** | P0 |
| **Type** | Security |
| **Automated** | Yes |

**Steps:**
1. Execute `ferrocrate run alpine echo "$(cat /etc/passwd)"`
2. Verify proper escaping

**Expected Result:**
- Command properly escaped
- No injection possible

---

#### TC-SEC-092: Environment variable injection

| Attribute | Value |
|-----------|-------|
| **ID** | TC-SEC-092 |
| **Priority** | P0 |
| **Type** | Security |
| **Automated** | Yes |

**Steps:**
1. Pass malicious env var: `-e 'LD_PRELOAD=/malicious.so'`

**Expected Result:**
- Dangerous env vars filtered or warned
- Container behavior documented

---

### 11. Container Escape Tests

#### TC-SEC-100: Known escape technique: CVE-2019-5736

| Attribute | Value |
|-----------|-------|
| **ID** | TC-SEC-100 |
| **Priority** | P0 |
| **Type** | Security |
| **Automated** | Yes |

**Steps:**
1. Run container attempting runc exploit
2. Verify no host access

**Expected Result:**
- Exploit mitigated
- No host file access

---

#### TC-SEC-101: Known escape technique: symbolic link race

| Attribute | Value |
|-----------|-------|
| **ID** | TC-SEC-101 |
| **Priority** | P0 |
| **Type** | Security |
| **Automated** | Yes |

**Steps:**
1. Attempt TOCTOU race with symlinks
2. Verify atomic operations

**Expected Result:**
- Race condition prevented
- Atomic path resolution

---

### 12. Audit Logging (SEC-10)

#### TC-SEC-110: Container operation logging

| Attribute | Value |
|-----------|-------|
| **ID** | TC-SEC-110 |
| **Priority** | P1 |
| **Type** | Security |
| **Automated** | Yes |

**Steps:**
1. Perform container operations
2. Check audit log

**Expected Result:**
- All operations logged
- Timestamp, user, action recorded

---

#### TC-SEC-111: Security event logging

| Attribute | Value |
|-----------|-------|
| **ID** | TC-SEC-111 |
| **Priority** | P1 |
| **Type** | Security |
| **Automated** | Yes |

**Steps:**
1. Trigger security violation (blocked syscall)
2. Check security log

**Expected Result:**
- Security violation logged
- Sufficient detail for forensics

---

## Fuzzing Test Cases

### Fuzz-01: Image Layer Extraction

```rust
// fuzz/fuzz_layer_extraction.rs
fuzz_target!(|data: &[u8]| {
    let _ = ferro_store::layer::extract_layer(data);
});
```

**Focus Areas:**
- Malformed tar headers
- Path traversal attempts
- Integer overflow in size fields
- Corrupt compression streams

### Fuzz-02: Manifest Parsing

```rust
// fuzz/fuzz_manifest.rs
fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<oci_spec::ImageManifest>(data);
});
```

### Fuzz-03: Dockerfile Parsing

```rust
// fuzz/fuzz_dockerfile.rs
fuzz_target!(|data: &[u8]| {
    let _ = ferro_build::dockerfile::parse(std::str::from_utf8(data).unwrap_or(""));
});
```

---

## Test Execution Matrix

| Test ID | Priority | Smoke | Regression | Fuzz | CI |
|---------|----------|-------|------------|------|-----|
| TC-SEC-001 | P0 | X | X | - | X |
| TC-SEC-010 | P0 | X | X | - | X |
| TC-SEC-020 | P0 | X | X | - | X |
| TC-SEC-030 | P0 | - | X | - | X |
| TC-SEC-040 | P0 | - | X | - | X |
| TC-SEC-050 | P0 | X | X | X | X |
| TC-SEC-060 | P0 | - | X | - | X |
| TC-SEC-070 | P0 | X | X | - | X |
| TC-SEC-080 | P0 | - | X | - | X |
| TC-SEC-090 | P0 | - | X | X | X |
| TC-SEC-100 | P0 | - | X | - | X |

---

## Continuous Security Testing

| Activity | Frequency | Tool |
|----------|-----------|------|
| Dependency CVE scan | Daily | cargo-audit |
| Fuzzing campaigns | Daily | cargo-fuzz |
| Security regression | Weekly | Custom harness |
| Penetration test | Per-release | Third-party |
| Static analysis | Per-commit | cargo-clippy |
