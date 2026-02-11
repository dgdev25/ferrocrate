# ADR-012: Docker Socket Compatibility

## Status

**Amended** (February 11, 2026 - Deprioritized Docker API in favor of OCI-first + CRI/K8s integration per AI consensus)

## Context

The Docker socket (`/var/run/docker.sock`) is the de facto standard API for container management. Many tools depend on it:

- **VS Code Dev Containers**: Development environment in containers
- **Testcontainers**: Integration testing with containers
- **Docker Compose**: Multi-container orchestration
- **CI/CD systems**: GitHub Actions, GitLab CI, Jenkins Docker plugins
- **Monitoring tools**: cAdvisor, Prometheus Docker SD

**Docker API Characteristics:**
- REST API over Unix socket
- JSON request/response format
- API versioning (currently v1.45+)
- Endpoints for containers, images, networks, volumes, etc.

**FerroCrate Compatibility Options:**

| Approach | Coverage | Complexity | Maintenance |
|----------|----------|------------|-------------|
| Full API emulation | 100% | High | High |
| Core endpoints only | 80% | Medium | Medium |
| Translation layer | 95% | High | High |
| Separate socket | 0% | None | None |

## Decision

**Implement OCI-first architecture with Docker API as optional translation layer. Prioritize CRI/K8s integration over Docker socket emulation.**

**Primary Strategy: OCI-First**
- FerroCrate is a **native OCI runtime** (OCI Image Spec v1.1, OCI Runtime Spec v1.2, OCI Distribution Spec v1.1)
- All containers run via OCI bundles; all images stored in OCI format
- No proprietary formats or extensions

**Secondary Strategy: Docker Compatibility Layer (Optional)**
- Docker socket emulation available via optional `--docker-compat` flag
- NOT installed by default; users explicitly opt-in
- Implemented as translation layer that converts Docker API calls to OCI operations
- Coverage: Core endpoints only (containers, images, basic networks/volumes)
- Explicitly out of scope: Swarm, plugins, secrets, configs (Swarm-specific features)

**Tertiary Strategy: CRI/K8s Integration (Phase 2)**
- CRI v1 shim (ferro-cri) for Kubernetes compatibility
- containerd/CRI-O interoperability
- Higher priority than Docker socket emulation

**Coverage Strategy (if Docker layer enabled):**
- **Containers**: 80% coverage (run, exec, logs, inspect - core operations only)
- **Images**: 80% coverage (pull, push, build, tag - core operations only)
- **Networks**: 70% coverage (bridge, host, none - custom networks require manual OCI config)
- **Volumes**: 70% coverage (create, list, inspect - advanced drivers not supported)
- **System**: 60% coverage (info, version - events, df not guaranteed)
- **Swarm**: 0% coverage (explicitly out of scope; use CRI/K8s instead)

## Consequences

### Positive (OCI-First Strategy)

- **Standards-based**: No vendor lock-in; images portable to containerd, CRI-O, Podman
- **Simplified maintenance**: Follow OCI specs, not Docker API evolution
- **Future-proof**: OCI is the industry standard; Docker format is legacy
- **K8s ready**: Native CRI support planned for Phase 2

### Negative (OCI-First Strategy)

- **Docker migration effort**: Users must use `docker-compose` or separate emulation layer
- **Tooling gaps**: VS Code Dev Containers, Testcontainers require Docker socket
- **Adoption friction**: Requires users to understand OCI vs Docker differences

### Positive (Docker Compat Layer - Optional)

- **Tool compatibility (opt-in)**: Teams that need it can enable Docker socket
- **Gradual migration**: Teams can use Docker API while transitioning to OCI workflows

### Negative (Docker Compat Layer - Optional)

- **Perpetual maintenance**: Docker API evolves; layer must track changes
- **False equivalence**: Users may assume 100% Docker compatibility when limited

### Neutral

- **Daemon required**: Socket emulation requires daemon mode (daemonless is still default)

## Alternatives Considered

### Separate Socket (No Compatibility)

**Pros:**
- No API emulation complexity
- Clear differentiation from Docker
- No behavior confusion

**Cons:**
- No tool compatibility
- High migration barrier
- Users must update all tooling

**Decision**: Rejected. Compatibility is essential for adoption.

### Full API Coverage (Including Swarm)

**Pros:**
- Complete Docker replacement
- No documentation gaps

**Cons:**
- Swarm is out of scope per PRD
- Massive implementation effort
- Declining Swarm usage makes this low value

**Decision**: Rejected. Swarm is explicitly out of scope.

### Translation Proxy (Sidecar)

**Pros:**
- FerroCrate API stays clean
- Proxy handles translation

**Cons:**
- Extra component to deploy
- Latency overhead
- More failure points

**Decision**: Rejected. Built-in emulation is simpler.

## Implementation Notes

**API Endpoint Priority (from PRD COMPAT-04):**

```rust
// High priority (most used by tools)
const PRIORITY_ENDPOINTS: &[&str] = &[
    "POST /containers/create",
    "POST /containers/{id}/start",
    "POST /containers/{id}/stop",
    "GET /containers/{id}/logs",
    "GET /containers/{id}/inspect",
    "POST /images/create",  // pull
    "POST /build",
    "GET /_ping",
    "GET /version",
    "GET /info",
];

// Out of scope
const UNSUPPORTED_ENDPOINTS: &[&str] = &[
    "/swarm/*",           // No Swarm support
    "/plugins/*",         // No plugin system initially
    "/secrets/*",         // Swarm feature
    "/configs/*",         // Swarm feature
    "/services/*",        // Swarm feature
    "/tasks/*",           // Swarm feature
    "/nodes/*",           // Swarm feature
];
```

**API Router:**
```rust
use axum::{
    routing::{get, post},
    Router,
};

pub fn docker_api_router() -> Router {
    Router::new()
        // Containers
        .route("/containers/create", post(create_container))
        .route("/containers/:id/start", post(start_container))
        .route("/containers/:id/stop", post(stop_container))
        .route("/containers/:id/logs", get(container_logs))
        .route("/containers/:id/inspect", get(inspect_container))
        // Images
        .route("/images/create", post(pull_image))
        .route("/build", post(build_image))
        // System
        .route("/_ping", get(ping))
        .route("/version", get(version))
        .route("/info", get(system_info))
}
```

**Version Negotiation:**
```rust
// Docker clients negotiate API version
// Report support for v1.45+
async fn version() -> Json<Value> {
    json!({
        "ApiVersion": "1.45",
        "MinAPIVersion": "1.24",
        "GitCommit": env!("VERGEN_GIT_SHA"),
        "GoVersion": "n/a",  // We're Rust, not Go
        "Os": "linux",
        "Arch": std::env::consts::ARCH,
        "KernelVersion": get_kernel_version(),
        "Version": env!("CARGO_PKG_VERSION"),
    })
}
```

## References

- [Docker Engine API v1.45](https://docs.docker.com/engine/api/v1.45/)
- [OCI Distribution Spec](https://github.com/opencontainers/distribution-spec)
- [Testcontainers](https://testcontainers.com/)
- PRD Requirements: CLI-02, COMPAT-04, US-4.2, US-4.3
