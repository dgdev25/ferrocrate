# ADR-008: OCI Compliance

## Status

**Accepted** (Amended February 11, 2026 - Added OCI conformance testing suite and elevated Kubernetes CRI integration priority per AI consensus)

## Context

The Open Container Initiative (OCI) defines standards for container ecosystems:

1. **OCI Image Spec**: Format for container images (manifest, config, layers)
2. **OCI Runtime Spec**: How to run a container (config.json, bundle format)
3. **OCI Distribution Spec**: API for pushing/pulling images (registries)

**Ecosystem Reality:**
- Docker created the de facto standards
- OCI standardized them with improvements
- All major runtimes (containerd, CRI-O, Podman) implement OCI specs
- All major registries (Docker Hub, GHCR, ECR, GCR) support OCI

**Compatibility Matrix:**

| Feature | Docker Format | OCI Spec | FerroCrate Target |
|---------|--------------|----------|-------------------|
| Image manifest | v2.2 | v1.1 | OCI v1.1 |
| Layer format | tar+gzip | tar+zstd/gzip | OCI v1.1 |
| Runtime config | config.v2.json | config.json | OCI v1.2 |
| Bundle format | Docker-specific | OCI bundle | OCI v1.2 |
| Registry API | Docker v2 | OCI v1.1 | OCI v1.1 |

## Decision

**Full compliance with OCI Image Spec v1.1, OCI Runtime Spec v1.2, and OCI Distribution Spec v1.1.**

No proprietary extensions to image formats or runtime configuration.

Implementation:
1. **Image format**: OCI v1.1 manifest and config exactly as specified
2. **Runtime**: OCI v1.2 bundle with config.json
3. **Distribution**: OCI v1.1 API with Docker v2 fallback for legacy registries
4. **No proprietary layers**: All image content readable by other OCI runtimes

**Docker Compatibility via OCI:**
- Docker images ARE OCI images (since Docker 1.10+)
- Docker registries support OCI media types
- FerroCrate reads Docker images as OCI images

## Consequences

### Positive

- **Portability**: Images built by FerroCrate run on containerd, CRI-O, Podman
- **Interoperability**: Images from Docker Hub, GHCR, ECR all work without modification
- **No vendor lock-in**: Standard formats protect users
- **Ecosystem benefit**: Contributes to container standardization
- **Kubernetes ready**: CRI runtimes expect OCI bundles (CRI/K8s integration elevated to Phase 2 priority per ADR-015)

### Negative

- **No optimization shortcuts**: Cannot use proprietary optimizations
- **Legacy edge cases**: Some very old Docker images may need translation

### Neutral

- **Implementation rigor**: Must follow spec exactly; no ad-hoc formats

## Alternatives Considered

### Docker Format Only

**Pros:**
- Maximum Docker compatibility
- Handles all Docker edge cases

**Cons:**
- Docker format is effectively deprecated
- Misses OCI improvements
- Not future-proof

**Decision**: Rejected. OCI is the standard; Docker format is legacy.

### OCI + Proprietary Extensions

**Pros:**
- Could add optimizations
- Differentiation from other runtimes

**Cons:**
- Images not portable to other runtimes
- Vendor lock-in for users
- Against OCI philosophy

**Decision**: Rejected. Portability is a core value; no lock-in.

### Support Both Equally

**Pros:**
- Maximum compatibility

**Cons:**
- Doubles testing burden
- Code complexity for dual paths
- Unclear which is "native"

**Decision**: Rejected. OCI as primary with Docker fallback is cleaner.

## Implementation Notes

**OCI Image Manifest v1.1:**
```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "digest": "sha256:...",
    "size": 7023
  },
  "layers": [
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+zstd",
      "digest": "sha256:...",
      "size": 32654
    }
  ]
}
```

**OCI Runtime Spec v1.2 config.json:**
```json
{
  "ociVersion": "1.2.0",
  "process": {
    "terminal": true,
    "user": { "uid": 0, "gid": 0 },
    "args": ["sh"],
    "env": ["PATH=/usr/bin"],
    "cwd": "/"
  },
  "root": {
    "path": "rootfs",
    "readonly": false
  },
  "linux": {
    "namespaces": [
      { "type": "pid" },
      { "type": "network" },
      { "type": "ipc" },
      { "type": "uts" },
      { "type": "mount" }
    ]
  }
}
```

**Registry API Support:**
- `GET /v2/<name>/manifests/<reference>` - Pull manifest
- `PUT /v2/<name>/manifests/<reference>` - Push manifest
- `GET /v2/<name>/blobs/<digest>` - Pull blob
- `DELETE /v2/<name>/blobs/<digest>` - Delete blob

## OCI Conformance Testing

**FerroCrate must pass OCI conformance test suite:**

- **OCI Image Spec v1.1 Validation**: Image manifest structure, config validation, layer reference verification
- **OCI Runtime Spec v1.2 Compliance**: config.json parsing, namespace creation, process lifecycle
- **OCI Distribution Spec v1.1**: Registry API compliance, authentication flows, blob management

**Test Infrastructure:**
```bash
# OCI Image spec compliance
cargo test --test oci-image-conformance

# OCI Runtime spec compliance
cargo test --test oci-runtime-conformance

# OCI Distribution spec compliance
cargo test --test oci-distribution-conformance
```

**Certification Target:**
- Pass all OCI runtime-spec conformance tests
- Pass all OCI image-spec conformance tests
- Interoperability verified with OCI Reference Implementations

## References

- [OCI Image Spec v1.1](https://github.com/opencontainers/image-spec/blob/v1.1.0/spec.md)
- [OCI Runtime Spec v1.2](https://github.com/opencontainers/runtime-spec/blob/v1.2.0/spec.md)
- [OCI Distribution Spec v1.1](https://github.com/opencontainers/distribution-spec/blob/v1.1.0/spec.md)
- [OCI Conformance Testing](https://github.com/opencontainers/runtime-tools/tree/master/validation)
- [ADR-015: Timeline Revision and MVP Scope](ADR-015-timeline-revision-and-mvp-scope.md) (Phase 5: Kubernetes CRI integration)
- PRD Requirements: COMPAT-01, COMPAT-02, COMPAT-03, CLM-01
