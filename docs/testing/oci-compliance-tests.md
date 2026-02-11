# OCI Compliance Tests

**Version:** 1.0 | **Date:** February 11, 2026 | **Compliance Target:** OCI v1.1

---

## Overview

FerroCrate must fully comply with the Open Container Initiative (OCI) specifications to ensure interoperability with the container ecosystem. This document defines the test plan for validating compliance with all three OCI specifications.

---

## OCI Specifications

| Specification | Version | Description | PRD Reference |
|--------------|---------|-------------|---------------|
| OCI Image Spec | v1.1 | Image format and content descriptors | COMPAT-01 |
| OCI Runtime Spec | v1.2 | Container configuration and lifecycle | COMPAT-02 |
| OCI Distribution Spec | v1.1 | Registry API and content distribution | COMPAT-03 |

---

## 1. OCI Image Specification Tests

### 1.1 Image Manifest

#### TC-OCI-IMG-001: Valid manifest structure

| Attribute | Value |
|-----------|-------|
| **ID** | TC-OCI-IMG-001 |
| **Spec Reference** | image-spec.md#image-manifest |
| **Priority** | P0 |

**Steps:**
1. Pull image from OCI-compliant registry
2. Parse manifest
3. Validate against JSON schema

**Expected Result:**
- Manifest parses successfully
- Required fields present: `schemaVersion`, `mediaType`, `config`, `layers`
- Valid digest references

---

#### TC-OCI-IMG-002: Manifest list (index)

| Attribute | Value |
|-----------|-------|
| **ID** | TC-OCI-IMG-002 |
| **Spec Reference** | image-spec.md#image-index |
| **Priority** | P0 |

**Steps:**
1. Pull multi-arch image (e.g., `nginx:latest`)
2. Parse manifest list
3. Verify platform selection

**Expected Result:**
- Manifest list parsed
- Correct platform variant selected
- `manifests` array contains valid descriptors

---

#### TC-OCI-IMG-003: Content descriptor

| Attribute | Value |
|-----------|-------|
| **ID** | TC-OCI-IMG-003 |
| **Spec Reference** | descriptor.md |
| **Priority** | P0 |

**Steps:**
1. Verify descriptor format for all references
2. Check digest algorithm support (sha256, sha512)
3. Validate size field accuracy

**Expected Result:**
- All descriptors have `mediaType`, `digest`, `size`
- Digest matches content
- Size matches actual size

---

### 1.2 Image Configuration

#### TC-OCI-IMG-010: Config blob format

| Attribute | Value |
|-----------|-------|
| **ID** | TC-OCI-IMG-010 |
| **Spec Reference** | config.md |
| **Priority** | P0 |

**Steps:**
1. Extract config blob
2. Validate JSON structure

**Expected Result:**
```json
{
  "architecture": "amd64",
  "os": "linux",
  "config": {
    "Env": [...],
    "Entrypoint": [...],
    "Cmd": [...],
    ...
  },
  "rootfs": {
    "type": "layers",
    "diff_ids": [...]
  }
}
```

---

#### TC-OCI-IMG-011: Architecture and OS

| Attribute | Value |
|-----------|-------|
| **ID** | TC-OCI-IMG-011 |
| **Spec Reference** | config.md#properties |
| **Priority** | P0 |

**Test Matrix:**

| Architecture | OS | Expected |
|--------------|-----|----------|
| amd64 | linux | Supported |
| arm64 | linux | Supported |
| riscv64 | linux | Supported |
| amd64 | windows | Not supported (v1.0) |

---

#### TC-OCI-IMG-012: RootFS type

| Attribute | Value |
|-----------|-------|
| **ID** | TC-OCI-IMG-012 |
| **Spec Reference** | config.md#rootfs |
| **Priority** | P0 |

**Steps:**
1. Verify `rootfs.type` is "layers"
2. Verify `diff_ids` matches layer uncompressed hashes

**Expected Result:**
- Type is "layers"
- Diff IDs are valid SHA256 sums

---

### 1.3 Layer Format

#### TC-OCI-IMG-020: Layer tar format

| Attribute | Value |
|-----------|-------|
| **ID** | TC-OCI-IMG-020 |
| **Spec Reference** | layer.md |
| **Priority** | P0 |

**Steps:**
1. Extract layer tarball
2. Validate format
3. Check file entries

**Expected Result:**
- Valid tar format (POSIX or GNU)
- No absolute paths
- No path traversal (../)

---

#### TC-OCI-IMG-021: Layer compression

| Attribute | Value |
|-----------|-------|
| **ID** | TC-OCI-IMG-021 |
| **Spec Reference** | layer.md#compression |
| **Priority** | P0 |

**Test Matrix:**

| Media Type | Compression | Supported |
|------------|-------------|-----------|
| application/vnd.oci.image.layer.v1.tar | None | Yes |
| application/vnd.oci.image.layer.v1.tar+gzip | gzip | Yes |
| application/vnd.oci.image.layer.v1.tar+zstd | zstd | Yes |

---

#### TC-OCI-IMG-022: Whiteout files

| Attribute | Value |
|-----------|-------|
| **ID** | TC-OCI-IMG-022 |
| **Spec Reference** | layer.md#whiteouts |
| **Priority** | P0 |

**Steps:**
1. Create image with deleted file
2. Verify whiteout file created
3. Verify deletion on extraction

**Expected Result:**
- `.wh.filename` creates whiteout
- `.wh..wh..opq` creates opaque whiteout
- Files correctly removed

---

### 1.4 Media Types

#### TC-OCI-IMG-030: Supported media types

| Media Type | Purpose | Required |
|------------|---------|----------|
| application/vnd.oci.image.manifest.v1+json | Manifest | Yes |
| application/vnd.oci.image.index.v1+json | Index | Yes |
| application/vnd.oci.image.config.v1+json | Config | Yes |
| application/vnd.oci.image.layer.v1.tar | Layer (uncompressed) | Yes |
| application/vnd.oci.image.layer.v1.tar+gzip | Layer (gzip) | Yes |
| application/vnd.oci.image.layer.v1.tar+zstd | Layer (zstd) | Yes |

---

## 2. OCI Runtime Specification Tests

### 2.1 Runtime Bundle

#### TC-OCI-RUN-001: Bundle structure

| Attribute | Value |
|-----------|-------|
| **ID** | TC-OCI-RUN-001 |
| **Spec Reference** | runtime.md#runtime-model |
| **Priority** | P0 |

**Steps:**
1. Create OCI bundle
2. Verify required files

**Expected Result:**
```
bundle/
├── config.json    # Required
├── rootfs/        # Required
│   └── ...
```

---

#### TC-OCI-RUN-002: config.json format

| Attribute | Value |
|-----------|-------|
| **ID** | TC-OCI-RUN-002 |
| **Spec Reference** | config.md |
| **Priority** | P0 |

**Steps:**
1. Parse config.json
2. Validate schema

**Expected Result:**
```json
{
  "ociVersion": "1.0.0",
  "process": { ... },
  "root": { ... },
  "hostname": "...",
  "mounts": [ ... ],
  "linux": { ... }
}
```

---

### 2.2 Container Process

#### TC-OCI-RUN-010: Process configuration

| Attribute | Value |
|-----------|-------|
| **ID** | TC-OCI-RUN-010 |
| **Spec Reference** | runtime.md#process |
| **Priority** | P0 |

**Test Matrix:**

| Property | Test |
|----------|------|
| `terminal` | True/false produces correct TTY behavior |
| `user.uid` | Process runs with specified UID |
| `user.gid` | Process runs with specified GID |
| `user.additionalGids` | Supplementary groups set |
| `args` | Command-line arguments passed |
| `env` | Environment variables set |
| `cwd` | Working directory set |

---

#### TC-OCI-RUN-011: Process capabilities

| Attribute | Value |
|-----------|-------|
| **ID** | TC-OCI-RUN-011 |
| **Spec Reference** | config.md#linux-process |
| **Priority** | P0 |

**Steps:**
1. Configure capabilities
2. Start container
3. Verify capability set

**Expected Result:**
- `capabilities.bounding` applied
- `capabilities.effective` applied
- `capabilities.inheritable` applied
- `capabilities.permitted` applied
- `capabilities.ambient` applied

---

### 2.3 Linux Namespace Configuration

#### TC-OCI-RUN-020: Namespace types

| Attribute | Value |
|-----------|-------|
| **ID** | TC-OCI-RUN-020 |
| **Spec Reference** | runtime.md#linux-namespaces |
| **Priority** | P0 |

**Test Matrix:**

| Namespace Type | Test |
|---------------|------|
| `pid` | Isolated PID namespace |
| `network` | Isolated network namespace |
| `ipc` | Isolated IPC namespace |
| `uts` | Isolated UTS namespace |
| `mount` | Isolated mount namespace |
| `user` | User namespace with mappings |
| `cgroup` | Isolated cgroup namespace |

---

#### TC-OCI-RUN-021: User namespace mappings

| Attribute | Value |
|-----------|-------|
| **ID** | TC-OCI-RUN-021 |
| **Spec Reference** | config.md#user-namespace-mappings |
| **Priority** | P0 |

**Steps:**
1. Configure uidMappings and gidMappings
2. Start container
3. Verify /proc/self/uid_map

**Expected Result:**
- Mappings applied correctly
- Container UID 0 maps to unprivileged host UID

---

### 2.4 Linux Security

#### TC-OCI-RUN-030: Seccomp

| Attribute | Value |
|-----------|-------|
| **ID** | TC-OCI-RUN-030 |
| **Spec Reference** | runtime.md#seccomp |
| **Priority** | P0 |

**Steps:**
1. Configure seccomp profile
2. Test blocked syscalls
3. Test allowed syscalls

**Expected Result:**
- `defaultAction` applied
- Per-syscall `action` applied
- `args` filtering works

---

#### TC-OCI-RUN-031: AppArmor

| Attribute | Value |
|-----------|-------|
| **ID** | TC-OCI-RUN-031 |
| **Spec Reference** | runtime.md#apparmor |
| **Priority** | P1 |

**Steps:**
1. Specify AppArmor profile
2. Verify profile loaded

**Expected Result:**
- Profile applied to container processes
- `/proc/self/attr/current` shows profile

---

#### TC-OCI-RUN-032: SELinux

| Attribute | Value |
|-----------|-------|
| **ID** | TC-OCI-RUN-032 |
| **Spec Reference** | runtime.md#selinux |
| **Priority** | P1 |

**Steps:**
1. Configure SELinux context
2. Verify context applied

**Expected Result:**
- Process runs with specified context

---

### 2.5 Cgroups

#### TC-OCI-RUN-040: Cgroup v2 resources

| Attribute | Value |
|-----------|-------|
| **ID** | TC-OCI-RUN-040 |
| **Spec Reference** | config.md#cgroups |
| **Priority** | P0 |

**Test Matrix:**

| Resource | Property | Test |
|----------|----------|------|
| Memory | `memory.limit` | OOM at limit |
| Memory | `memory.swap` | Swap limit enforced |
| CPU | `cpu.shares` | Shares applied |
| CPU | `cpu.quota` | Quota enforced |
| PIDs | `pids.limit` | Fork limit |
| IO | `blockIO` | IO limits |

---

### 2.6 Lifecycle

#### TC-OCI-RUN-050: State transitions

| Attribute | Value |
|-----------|-------|
| **ID** | TC-OCI-RUN-050 |
| **Spec Reference** | runtime.md#lifecycle |
| **Priority** | P0 |

**Test Matrix:**

| Transition | Command | Expected State |
|------------|---------|----------------|
| create | `ferrocrate create` | created |
| start | `ferrocrate start` | running |
| kill | `ferrocrate kill` | stopped |
| delete | `ferrocrate rm` | (removed) |

---

#### TC-OCI-RUN-051: Hooks

| Attribute | Value |
|-----------|-------|
| **ID** | TC-OCI-RUN-051 |
| **Spec Reference** | runtime.md#hooks |
| **Priority** | P1 |

**Test Matrix:**

| Hook | When Executed |
|------|---------------|
| prestart | Before container start |
| createRuntime | After container created |
| createContainer | Before user process |
| startContainer | Before user process starts |
| poststart | After container started |
| poststop | After container stopped |

---

## 3. OCI Distribution Specification Tests

### 3.1 Registry API

#### TC-OCI-DIST-001: Content discovery

| Attribute | Value |
|-----------|-------|
| **ID** | TC-OCI-DIST-001 |
| **Spec Reference** | spec.md#content-discovery |
| **Priority** | P0 |

**Steps:**
1. List repositories
2. List tags for repository

**Expected Result:**
- Valid JSON response
- Pagination supported

---

#### TC-OCI-DIST-002: Pull manifest

| Attribute | Value |
|-----------|-------|
| **ID** | TC-OCI-DIST-002 |
| **Spec Reference** | spec.md#pulling-manifests |
| **Priority** | P0 |

**Steps:**
1. GET `/v2/<name>/manifests/<reference>`
2. Verify response

**Expected Result:**
- Correct Content-Type
- Valid manifest body
- Docker-Content-Digest header

---

#### TC-OCI-DIST-003: Push manifest

| Attribute | Value |
|-----------|-------|
| **ID** | TC-OCI-DIST-003 |
| **Spec Reference** | spec.md#pushing-manifests |
| **Priority** | P0 |

**Steps:**
1. PUT `/v2/<name>/manifests/<reference>`
2. Push all referenced blobs first

**Expected Result:**
- 201 Created response
- Location header set

---

### 3.2 Blob Operations

#### TC-OCI-DIST-010: Pull blob

| Attribute | Value |
|-----------|-------|
| **ID** | TC-OCI-DIST-010 |
| **Spec Reference** | spec.md#pulling-blobs |
| **Priority** | P0 |

**Steps:**
1. GET `/v2/<name>/blobs/<digest>`
2. Verify content

**Expected Result:**
- Correct blob content
- Digest matches
- Range requests supported

---

#### TC-OCI-DIST-011: Push blob (monolithic)

| Attribute | Value |
|-----------|-------|
| **ID** | TC-OCI-DIST-011 |
| **Spec Reference** | spec.md#pushing-blobs |
| **Priority** | P0 |

**Steps:**
1. POST `/v2/<name>/blobs/uploads/`
2. PUT with digest

**Expected Result:**
- Blob stored
- Digest verified

---

#### TC-OCI-DIST-012: Push blob (chunked)

| Attribute | Value |
|-----------|-------|
| **ID** | TC-OCI-DIST-012 |
| **Spec Reference** | spec.md#pushing-blobs-in-chunks |
| **Priority** | P0 |

**Steps:**
1. Start upload session
2. PATCH chunks
3. Complete with PUT

**Expected Result:**
- Chunks assembled correctly
- Final blob valid

---

### 3.3 Authentication

#### TC-OCI-DIST-020: Bearer token auth

| Attribute | Value |
|-----------|-------|
| **ID** | TC-OCI-DIST-020 |
| **Spec Reference** | spec.md#authentication |
| **Priority** | P0 |

**Steps:**
1. Request protected resource
2. Handle 401 with WWW-Authenticate
3. Obtain token
4. Retry with token

**Expected Result:**
- Token obtained
- Access granted with token

---

#### TC-OCI-DIST-021: Basic auth

| Attribute | Value |
|-----------|-------|
| **ID** | TC-OCI-DIST-021 |
| **Spec Reference** | spec.md#authentication |
| **Priority** | P0 |

**Steps:**
1. Connect to registry with basic auth
2. Verify authentication

**Expected Result:**
- Basic auth accepted
- Operations succeed

---

### 3.4 Error Handling

#### TC-OCI-DIST-030: Error response format

| Attribute | Value |
|-----------|-------|
| **ID** | TC-OCI-DIST-030 |
| **Spec Reference** | spec.md#errors |
| **Priority** | P0 |

**Steps:**
1. Trigger various error conditions
2. Verify error response

**Expected Result:**
```json
{
  "errors": [{
    "code": "MANIFEST_UNKNOWN",
    "message": "...",
    "detail": {...}
  }]
}
```

---

## 4. Official OCI Compliance Tools

### oci-runtime-tool

```bash
# Install
go install github.com/opencontainers/runtime-tools/cmd/oci-runtime-tool@latest

# Validate config.json
oci-runtime-tool validate --path /bundle

# Run compliance tests
oci-runtime-tool run --path /bundle
```

### oci-image-tool

```bash
# Install
go install github.com/opencontainers/image-tools/cmd/oci-image-tool@latest

# Validate image
oci-image-tool validate --image myimage:tag

# Unpack image to bundle
oci-image-tool unpack --ref myimage:tag myimage.tar bundle/
```

---

## 5. Compliance Test Matrix

### OCI Image Spec v1.1

| Section | Tests | Required | Status |
|---------|-------|----------|--------|
| Manifest | 5 | Yes | Pending |
| Index | 3 | Yes | Pending |
| Config | 4 | Yes | Pending |
| Layer | 6 | Yes | Pending |
| Descriptor | 3 | Yes | Pending |
| Media Types | 10 | Yes | Pending |

### OCI Runtime Spec v1.2

| Section | Tests | Required | Status |
|---------|-------|----------|--------|
| Bundle | 2 | Yes | Pending |
| Process | 5 | Yes | Pending |
| Namespaces | 8 | Yes | Pending |
| Security | 6 | Yes | Pending |
| Cgroups | 6 | Yes | Pending |
| Lifecycle | 5 | Yes | Pending |
| Hooks | 6 | Yes | Pending |

### OCI Distribution Spec v1.1

| Section | Tests | Required | Status |
|---------|-------|----------|--------|
| Manifest Operations | 4 | Yes | Pending |
| Blob Operations | 5 | Yes | Pending |
| Authentication | 3 | Yes | Pending |
| Errors | 3 | Yes | Pending |
| Pagination | 2 | Yes | Pending |

---

## 6. CI Integration

```yaml
# .github/workflows/oci-compliance.yml
name: OCI Compliance

on: [push, pull_request]

jobs:
  runtime-spec:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build ferrocrate
        run: cargo build --release
      - name: Install oci-runtime-tool
        run: go install github.com/opencontainers/runtime-tools/cmd/oci-runtime-tool@latest
      - name: Run runtime compliance
        run: |
          ./scripts/oci-runtime-tests.sh

  image-spec:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install oci-image-tool
        run: go install github.com/opencontainers/image-tools/cmd/oci-image-tool@latest
      - name: Run image compliance
        run: |
          ./scripts/oci-image-tests.sh

  distribution-spec:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Start test registry
        run: docker run -d -p 5000:5000 --name registry registry:2
      - name: Run distribution compliance
        run: |
          ./scripts/oci-distribution-tests.sh
```

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-02-11 | Test Team | Initial version |
