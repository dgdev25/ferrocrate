# Image Operations Test Cases

**Component:** ferro-store, ferro-build | **Priority:** P0 | **Last Updated:** 2026-02-11

---

## Overview

Image operation tests verify all functionality related to container image management, including pulling, pushing, building, tagging, and storage operations.

---

## Test Categories

### 1. Image Pull (IMG-01)

#### TC-IMG-001: Pull image from Docker Hub

| Attribute | Value |
|-----------|-------|
| **ID** | TC-IMG-001 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Network connectivity to Docker Hub
- No local copy of target image

**Steps:**
1. Execute `ferrocrate pull alpine:latest`
2. Verify progress output
3. Verify image in `ferrocrate images`

**Expected Result:**
- Image downloaded successfully
- All layers present in store
- Blake3 checksums verified

---

#### TC-IMG-002: Pull image from GHCR

| Attribute | Value |
|-----------|-------|
| **ID** | TC-IMG-002 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Steps:**
1. Execute `ferrocrate pull ghcr.io/owner/image:tag`

**Expected Result:**
- Image pulled from GitHub Container Registry
- Authentication handled via credential helpers

---

#### TC-IMG-003: Pull image from ECR

| Attribute | Value |
|-----------|-------|
| **ID** | TC-IMG-003 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- AWS credentials configured

**Steps:**
1. Execute `ferrocrate pull 123456789.dkr.ecr.us-east-1.amazonaws.com/myapp:latest`

**Expected Result:**
- ECR authentication successful
- Image pulled

---

#### TC-IMG-004: Pull with authentication

| Attribute | Value |
|-----------|-------|
| **ID** | TC-IMG-004 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Private registry with authentication

**Steps:**
1. Configure credentials in `~/.docker/config.json`
2. Execute `ferrocrate pull registry.example.com/private:latest`

**Expected Result:**
- Authentication successful
- Private image pulled

---

#### TC-IMG-005: Pull non-existent image

| Attribute | Value |
|-----------|-------|
| **ID** | TC-IMG-005 |
| **Priority** | P0 |
| **Type** | Negative |
| **Automated** | Yes |

**Steps:**
1. Execute `ferrocrate pull nonexistent/image:v1`

**Expected Result:**
- Error: "image not found"
- Exit code non-zero

---

#### TC-IMG-006: Pull with manifest list (multi-arch)

| Attribute | Value |
|-----------|-------|
| **ID** | TC-IMG-006 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Steps:**
1. Execute `ferrocrate pull nginx:latest` (multi-arch image)
2. Verify correct architecture selected

**Expected Result:**
- Platform-appropriate variant pulled
- Manifest list resolved correctly

---

#### TC-IMG-007: Pull with specific platform

| Attribute | Value |
|-----------|-------|
| **ID** | TC-IMG-007 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Steps:**
1. Execute `ferrocrate pull --platform linux/arm64 nginx:latest`

**Expected Result:**
- ARM64 variant pulled regardless of host arch

---

### 2. Image Push (IMG-02)

#### TC-IMG-010: Push image to registry

| Attribute | Value |
|-----------|-------|
| **ID** | TC-IMG-010 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Image exists locally
- Push access to registry

**Steps:**
1. Tag image for target registry
2. Execute `ferrocrate push registry.example.com/myapp:v1`

**Expected Result:**
- Image pushed successfully
- All layers uploaded
- Manifest uploaded

---

#### TC-IMG-011: Push with layer deduplication

| Attribute | Value |
|-----------|-------|
| **ID** | TC-IMG-011 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Registry already has some layers

**Steps:**
1. Push image with shared layers
2. Verify only new layers uploaded

**Expected Result:**
- Existing layers skipped
- Upload size reduced

---

#### TC-IMG-012: Push with authentication

| Attribute | Value |
|-----------|-------|
| **ID** | TC-IMG-012 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Steps:**
1. Push to private registry with credentials

**Expected Result:**
- Authentication successful
- Push completed

---

### 3. Content-Addressable Store (IMG-03)

#### TC-IMG-020: Layer deduplication

| Attribute | Value |
|-----------|-------|
| **ID** | TC-IMG-020 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Two images with identical layer

**Steps:**
1. Pull image A with layer X
2. Pull image B with same layer X
3. Verify storage usage

**Expected Result:**
- Layer X stored once
- Storage reflects single copy

---

#### TC-IMG-021: Blake3 checksum verification

| Attribute | Value |
|-----------|-------|
| **ID** | TC-IMG-021 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Steps:**
1. Pull image
2. Manually corrupt a layer file
3. Attempt to run container from image

**Expected Result:**
- Checksum mismatch detected
- Error reported
- Image marked as corrupted

---

#### TC-IMG-022: Layer sharing across images

| Attribute | Value |
|-----------|-------|
| **ID** | TC-IMG-022 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Base image pulled
- Derived image to pull

**Steps:**
1. Pull `alpine:latest`
2. Pull `nginx:alpine` (shares alpine layers)
3. Check storage

**Expected Result:**
- Shared layers not re-downloaded
- Storage reflects deduplication

---

### 4. Zstd Compression (IMG-04)

#### TC-IMG-030: Pull zstd-compressed layer

| Attribute | Value |
|-----------|-------|
| **ID** | TC-IMG-030 |
| **Priority** | P1 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Registry serves zstd-compressed layers

**Steps:**
1. Pull image with zstd layers

**Expected Result:**
- Layer decompressed correctly
- Faster than gzip equivalent

---

#### TC-IMG-031: Push with zstd compression

| Attribute | Value |
|-----------|-------|
| **ID** | TC-IMG-031 |
| **Priority** | P1 |
| **Type** | Positive |
| **Automated** | Yes |

**Steps:**
1. Build image
2. Push with zstd compression

**Expected Result:**
- Layers compressed with zstd
- Compression ratio acceptable

---

### 5. Lazy Image Pulling (IMG-05)

#### TC-IMG-040: Lazy pull on container start

| Attribute | Value |
|-----------|-------|
| **ID** | TC-IMG-040 |
| **Priority** | P1 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Large image not present locally
- Lazy pulling enabled

**Steps:**
1. Execute `ferrocrate run --lazy large-image:latest echo test`
2. Verify container starts before full download
3. Verify on-demand file fetching

**Expected Result:**
- Container starts within 2 seconds
- Files fetched on access
- Background download continues

---

#### TC-IMG-041: Lazy pull with file access

| Attribute | Value |
|-----------|-------|
| **ID** | TC-IMG-041 |
| **Priority** | P1 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Container started with lazy pull
- File not yet fetched

**Steps:**
1. Access file in container
2. Verify fetch-on-demand

**Expected Result:**
- File fetched when accessed
- Subsequent accesses instant

---

### 6. Dockerfile Build (IMG-06)

#### TC-IMG-050: Build from simple Dockerfile

| Attribute | Value |
|-----------|-------|
| **ID** | TC-IMG-050 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Dockerfile in current directory

```dockerfile
FROM alpine:latest
RUN echo "hello" > /test.txt
```

**Steps:**
1. Execute `ferrocrate build -t test-image .`

**Expected Result:**
- Image built successfully
- Image tagged as test-image:latest

---

#### TC-IMG-051: Build with ARG

| Attribute | Value |
|-----------|-------|
| **ID** | TC-IMG-051 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

```dockerfile
ARG VERSION=latest
FROM alpine:${VERSION}
```

**Steps:**
1. Execute `ferrocrate build --build-arg VERSION=3.18 -t test .`

**Expected Result:**
- ARG substituted correctly
- Alpine 3.18 used

---

#### TC-IMG-052: Build with COPY

| Attribute | Value |
|-----------|-------|
| **ID** | TC-IMG-052 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- File `app.txt` in build context

```dockerfile
FROM alpine
COPY app.txt /app/
```

**Steps:**
1. Execute `ferrocrate build -t test .`
2. Run container and verify file

**Expected Result:**
- File copied correctly
- Content preserved

---

#### TC-IMG-053: Multi-stage build (IMG-08)

| Attribute | Value |
|-----------|-------|
| **ID** | TC-IMG-053 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

```dockerfile
FROM golang:1.21 AS builder
WORKDIR /app
COPY . .
RUN go build -o myapp

FROM alpine:latest
COPY --from=builder /app/myapp /usr/local/bin/
CMD ["myapp"]
```

**Steps:**
1. Execute `ferrocrate build -t multi-stage .`
2. Verify final image size

**Expected Result:**
- Builder stage artifacts not in final image
- Only copied binary present

---

#### TC-IMG-054: Build with RUN

| Attribute | Value |
|-----------|-------|
| **ID** | TC-IMG-054 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

```dockerfile
FROM alpine
RUN apk add --no-cache curl
```

**Steps:**
1. Build image
2. Verify curl installed

**Expected Result:**
- Package installed
- Layer cached

---

#### TC-IMG-055: Build with WORKDIR

| Attribute | Value |
|-----------|-------|
| **ID** | TC-IMG-055 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

```dockerfile
FROM alpine
WORKDIR /app
RUN pwd > /app/location.txt
```

**Steps:**
1. Build and run
2. Check /app/location.txt

**Expected Result:**
- Content: "/app"

---

#### TC-IMG-056: Build with ENV

| Attribute | Value |
|-----------|-------|
| **ID** | TC-IMG-056 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

```dockerfile
FROM alpine
ENV APP_ENV=production
RUN echo $APP_ENV > /env.txt
```

**Expected Result:**
- ENV available in RUN commands
- Persisted in final image

---

#### TC-IMG-057: Build with EXPOSE

| Attribute | Value |
|-----------|-------|
| **ID** | TC-IMG-057 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

```dockerfile
FROM alpine
EXPOSE 8080
```

**Expected Result:**
- Port documented in image metadata

---

#### TC-IMG-058: Build with CMD

| Attribute | Value |
|-----------|-------|
| **ID** | TC-IMG-058 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

```dockerfile
FROM alpine
CMD ["echo", "hello"]
```

**Steps:**
1. Build and run without command

**Expected Result:**
- Output: "hello"

---

#### TC-IMG-059: Build with ENTRYPOINT

| Attribute | Value |
|-----------|-------|
| **ID** | TC-IMG-059 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

```dockerfile
FROM alpine
ENTRYPOINT ["echo"]
CMD ["default"]
```

**Steps:**
1. Run without args
2. Run with args

**Expected Result:**
- No args: "default"
- With args "custom": "custom"

---

#### TC-IMG-060: Build with VOLUME

| Attribute | Value |
|-----------|-------|
| **ID** | TC-IMG-060 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

```dockerfile
FROM alpine
VOLUME /data
```

**Steps:**
1. Build and run
2. Write to /data
3. Check volume creation

**Expected Result:**
- Anonymous volume created
- Data persisted

---

### 7. Build Cache (IMG-09)

#### TC-IMG-070: Cache hit on unchanged file

| Attribute | Value |
|-----------|-------|
| **ID** | TC-IMG-070 |
| **Priority** | P1 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Image previously built

**Steps:**
1. Build same Dockerfile again
2. Verify cache used

**Expected Result:**
- "CACHED" markers for unchanged layers
- Build time significantly reduced

---

#### TC-IMG-071: Cache invalidation on file change

| Attribute | Value |
|-----------|-------|
| **ID** | TC-IMG-071 |
| **Priority** | P1 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Image previously built

**Steps:**
1. Modify one file in COPY context
2. Rebuild
3. Verify cache invalidation from changed layer

**Expected Result:**
- Changed file invalidates its layer
- Subsequent layers rebuilt
- Previous layers cached

---

#### TC-IMG-072: File-level cache granularity

| Attribute | Value |
|-----------|-------|
| **ID** | TC-IMG-072 |
| **Priority** | P1 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- COPY with multiple files

```dockerfile
COPY file1.txt file2.txt file3.txt /app/
```

**Steps:**
1. Build initial
2. Modify only file2.txt
3. Rebuild

**Expected Result:**
- Only file2.txt change detected
- Minimal layer invalidation

---

### 8. Image Management (IMG-10)

#### TC-IMG-080: Tag image

| Attribute | Value |
|-----------|-------|
| **ID** | TC-IMG-080 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Steps:**
1. Execute `ferrocrate tag alpine:latest my-alpine:v1`
2. Verify both tags point to same image

**Expected Result:**
- Image ID identical for both tags

---

#### TC-IMG-081: List images

| Attribute | Value |
|-----------|-------|
| **ID** | TC-IMG-081 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Steps:**
1. Execute `ferrocrate images`
2. Verify output format

**Expected Result:**
- Table with Repository, Tag, Image ID, Created, Size
- All images listed

---

#### TC-IMG-082: Remove image

| Attribute | Value |
|-----------|-------|
| **ID** | TC-IMG-082 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Image not used by any container

**Steps:**
1. Execute `ferrocrate rmi test-image:v1`
2. Verify removal

**Expected Result:**
- Image removed from store
- Layers cleaned (if unreferenced)

---

#### TC-IMG-083: Remove image with containers

| Attribute | Value |
|-----------|-------|
| **ID** | TC-IMG-083 |
| **Priority** | P0 |
| **Type** | Negative |
| **Automated** | Yes |

**Preconditions:**
- Container using image exists

**Steps:**
1. Execute `ferrocrate rmi used-image:v1`

**Expected Result:**
- Error: "image is in use by container X"
- Use --force to override

---

#### TC-IMG-084: Prune unused images

| Attribute | Value |
|-----------|-------|
| **ID** | TC-IMG-084 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Dangling images exist

**Steps:**
1. Execute `ferrocrate image prune`
2. Verify dangling images removed

**Expected Result:**
- Untagged images removed
- Space reclaimed

---

### 9. Image Scanning (IMG-11)

#### TC-IMG-090: Scan for vulnerabilities

| Attribute | Value |
|-----------|-------|
| **ID** | TC-IMG-090 |
| **Priority** | P2 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Vulnerability database updated

**Steps:**
1. Execute `ferrocrate scan vulnerable-image:latest`

**Expected Result:**
- CVE list output
- Severity ratings
- Remediation suggestions

---

### 10. ruvector Deduplication (IMG-12)

#### TC-IMG-100: Similar content deduplication

| Attribute | Value |
|-----------|-------|
| **ID** | TC-IMG-100 |
| **Priority** | P2 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- ruvector enabled
- Similar but not identical files

**Steps:**
1. Pull images with similar content
2. Verify vector-based dedup

**Expected Result:**
- Similar content identified
- Storage reduced beyond exact dedup

---

## Test Execution Matrix

| Test ID | Priority | Smoke | Regression | CI |
|---------|----------|-------|------------|-----|
| TC-IMG-001 | P0 | X | X | X |
| TC-IMG-010 | P0 | - | X | X |
| TC-IMG-020 | P0 | - | X | X |
| TC-IMG-050 | P0 | X | X | X |
| TC-IMG-053 | P0 | - | X | X |
| TC-IMG-070 | P1 | - | X | X |
| TC-IMG-080 | P0 | X | X | X |
| TC-IMG-082 | P0 | X | X | X |
