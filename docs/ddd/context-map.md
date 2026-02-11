# FerroCrate Context Map

> Strategic domain design showing relationships between bounded contexts in FerroCrate.

## Overview

The FerroCrate system is divided into six bounded contexts that together form the complete container runtime. This context map shows how these contexts interact, share data, and maintain their boundaries.

---

## Context Map Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           FERROCRATE CONTEXT MAP                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│    ┌─────────────────────────────────────────────────────────────────┐      │
│    │                    ComposeOrchestration                          │      │
│    │  (ferro-compose)                                                 │      │
│    │                                                                   │      │
│    │  Projects, Services, Dependency Resolution                        │      │
│    │                                                                   │      │
│    │  Relationships:                                                   │      │
│    │  ───────────────> ContainerRuntime (uses)                         │      │
│    │  ───────────────> ImageManagement (uses)                          │      │
│    │  ───────────────> Networking (uses)                               │      │
│    │  ───────────────> Storage (uses)                                  │      │
│    └─────────────────────────────────────────────────────────────────┘      │
│                                    │                                         │
│                                    │ commands                                │
│                                    ▼                                         │
│    ┌─────────────────────────────────────────────────────────────────┐      │
│    │                     ContainerRuntime                             │      │
│    │  (ferro-exec)                                                    │      │
│    │                                                                   │      │
│    │  Containers, Processes, Namespaces, Cgroups                       │      │
│    │                                                                   │      │
│    │  Relationships:                                                   │      │
│    │  <─────────────── ImageManagement (image IDs)                     │      │
│    │  <─────────────── Networking (endpoints)                          │      │
│    │  <─────────────── Storage (mounts)                                │      │
│    │  <─────────────── Security (contexts)                             │      │
│    │  <─────────────── Intelligence (recommendations)                  │      │
│    └─────────────────────────────────────────────────────────────────┘      │
│         ▲              ▲              ▲              ▲                       │
│         │              │              │              │                       │
│    image_id        endpoints       mounts      security_context               │
│         │              │              │              │                       │
│    ┌────┴────┐    ┌────┴────┐    ┌────┴────┐    ┌────┴────┐                  │
│    │ Image   │    │ Network │    │ Storage │    │Security │                  │
│    │ Mgmt    │    │  ing    │    │         │    │         │                  │
│    └─────────┘    └─────────┘    └─────────┘    └─────────┘                  │
│                                                                              │
│    ┌─────────────────────────────────────────────────────────────────┐      │
│    │                    IntelligenceLayer                             │      │
│    │  (ferro-mind)                                                    │      │
│    │                                                                   │      │
│    │  Predictions, Anomalies, Remediation                              │      │
│    │                                                                   │      │
│    │  Relationships:                                                   │      │
│    │  <─────────────── ALL CONTEXTS (metrics, read-only)               │      │
│    │  ───────────────> ContainerRuntime (recommendations)              │      │
│    │                                                                   │      │
│    │  [OHS/PL] Open Host Service / Published Language                  │      │
│    └─────────────────────────────────────────────────────────────────┘      │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Context Relationships

### 1. ContainerRuntime ↔ ImageManagement

**Relationship Type**: Customer/Supplier (Downstream/Upstream)

```
┌──────────────────┐                      ┌──────────────────┐
│ ContainerRuntime │ ─── image_id ─────> │ ImageManagement  │
│    (Customer)    │                      │   (Supplier)     │
│                  │ <── manifests ────  │                  │
└──────────────────┘                      └──────────────────┘
```

**Integration Pattern**: **Published Language (PL)**

- ContainerRuntime references images by `ImageId` (content-addressable digest)
- ImageManagement publishes manifests in OCI format (standard language)
- No direct object references; ID-based lookup

**Rust Implementation**:
```rust
// ContainerRuntime doesn't depend on ImageManagement crate directly
// Instead, it receives the necessary data through the ImageManifest value object

struct Container {
    image_id: ImageId,  // ID reference, not Arc<Image>
    // ...
}

// ImageManagement provides the manifest when needed
trait ImageService {
    async fn get_manifest(&self, id: &ImageId) -> Result<ImageManifest, ImageError>;
}
```

**Conformist**: ContainerRuntime conforms to the OCI image spec as defined by ImageManagement.

---

### 2. ContainerRuntime ↔ Storage

**Relationship Type**: Customer/Supplier

```
┌──────────────────┐                      ┌──────────────────┐
│ ContainerRuntime │ ─── mount request──> │     Storage      │
│    (Customer)    │                      │   (Supplier)     │
│                  │ <── MountPoint ────  │                  │
└──────────────────┘                      └──────────────────┘
```

**Integration Pattern**: **Published Language + ACL**

- ContainerRuntime requests rootfs preparation
- Storage returns a `MountPoint` (trait object for polymorphism)
- Storage driver abstraction via traits

**Rust Implementation**:
```rust
// ContainerRuntime doesn't know about specific storage implementations
trait StorageManager {
    async fn prepare_rootfs(
        &self,
        image: &ImageManifest,
        mounts: &[MountSpec],
    ) -> Result<Rootfs, StorageError>;
}

// Storage crate provides implementations
struct OverlayStorageDriver { /* ... */ }
impl StorageManager for OverlayStorageDriver { /* ... */ }
```

---

### 3. ContainerRuntime ↔ Networking

**Relationship Type**: Customer/Supplier

```
┌──────────────────┐                      ┌──────────────────┐
│ ContainerRuntime │ ─── attach request──>│   Networking     │
│    (Customer)    │                      │   (Supplier)     │
│                  │ <── Endpoint ──────  │                  │
└──────────────────┘                      └──────────────────┘
```

**Integration Pattern**: **Published Language**

- ContainerRuntime requests network attachment
- Networking returns `Endpoint` with IP configuration
- Network isolation enforced at kernel level

**Rust Implementation**:
```rust
trait NetworkManager {
    async fn attach(
        &self,
        container_id: &ContainerId,
        network_id: &NetworkId,
    ) -> Result<Endpoint, NetworkError>;
}

struct Endpoint {
    network_id: NetworkId,
    container_id: ContainerId,
    ip_address: IpAddr,
    // ...
}
```

---

### 4. ContainerRuntime ↔ Security

**Relationship Type**: Partnership

```
┌──────────────────┐                      ┌──────────────────┐
│ ContainerRuntime │ <── partnership ───> │    Security      │
│                  │                      │                  │
│  (spawns with    │ <── SecurityContext─ │ (builds context) │
│   context)       │                      │                  │
└──────────────────┘                      └──────────────────┘
```

**Integration Pattern**: **Partnership**

- Both contexts collaborate on container creation
- Security builds `SecurityContext`, Runtime applies it
- Tight coordination required for secure containers

**Rust Implementation**:
```rust
// Security context is built by Security, consumed by Runtime
trait SecurityEnforcer {
    fn build_context(&self, spec: &SecuritySpec) -> Result<SecurityContext, SecurityError>;
    async fn apply(&self, pid: Pid, context: &SecurityContext) -> Result<(), SecurityError>;
}

// Container creation flow
async fn create_container(
    &self,
    spec: ContainerSpec,
) -> Result<Container, Error> {
    // 1. Security builds context
    let security_context = self.security.build_context(&spec.security)?;

    // 2. Runtime spawns process with context
    let pid = self.spawn_process(&spec, &security_context)?;

    // 3. Security applies runtime enforcement
    self.security.apply(pid, &security_context).await?;

    // ...
}
```

---

### 5. IntelligenceLayer ↔ ALL Contexts

**Relationship Type**: Open Host Service (OHS)

```
┌──────────────────┐
│IntelligenceLayer │
│   (OHS Server)   │
└────────┬─────────┘
         │
    reads metrics (read-only)
         │
    ┌────┴────┬─────────┬─────────┬─────────┐
    ▼         ▼         ▼         ▼         ▼
┌───────┐ ┌───────┐ ┌───────┐ ┌───────┐ ┌───────┐
│Runtime│ │ Image │ │ Net   │ │Storage│ │Compose│
│       │ │ Mgmt  │ │       │ │       │ │       │
└───────┘ └───────┘ └───────┘ └───────┘ └───────┘
```

**Integration Pattern**: **Open Host Service / Published Language**

- IntelligenceLayer observes all contexts but doesn't control them
- Recommendations published as events (advisory, not mandatory)
- Metrics collected via read-only channels

**Key Principle**: AI is advisory only - never blocks critical operations

**Rust Implementation**:
```rust
// Intelligence reads metrics, publishes recommendations
trait IntelligenceService {
    async fn collect_metrics(&self) -> Result<SystemMetrics, Error>;
    async fn detect_anomalies(&self) -> Result<Vec<Anomaly>, Error>;
    async fn predict_resources(&self, container_id: &ContainerId) -> Result<Prediction, Error>;
}

// Recommendations are optional
struct ResourceRecommendation {
    container_id: ContainerId,
    recommended_limits: ResourceLimits,
    confidence: f32,
    reasoning: String,
}

// Runtime MAY apply recommendations but isn't required to
impl ContainerOrchestrator {
    async fn apply_recommendation(&self, rec: &ResourceRecommendation) -> Result<bool, Error> {
        if rec.confidence < self.config.ai_confidence_threshold {
            return Ok(false); // Ignored due to low confidence
        }
        // Apply recommendation...
        Ok(true)
    }
}
```

---

### 6. ComposeOrchestration ↔ Core Contexts

**Relationship Type**: Customer (Conformist)

```
┌──────────────────┐
│    Compose       │
│  Orchestration   │
└────────┬─────────┘
         │
         │ uses all core contexts
         │
    ┌────┴────┬─────────┬─────────┬─────────┐
    ▼         ▼         ▼         ▼         ▼
┌───────┐ ┌───────┐ ┌───────┐ ┌───────┐ ┌───────┐
│Runtime│ │ Image │ │ Net   │ │Storage│ │Security│
└───────┘ └───────┘ └───────┘ └───────┘ └───────┘
```

**Integration Pattern**: **Conformist + Anti-Corruption Layer**

- Compose translates docker-compose.yml to FerroCrate operations
- Conforms to FerroCrate's API patterns
- ACL for Docker-specific concepts

**Rust Implementation**:
```rust
// Compose translates compose spec to container specs
struct ComposeProject {
    services: HashMap<ServiceName, ServiceSpec>,
    networks: HashMap<NetworkName, NetworkSpec>,
    volumes: HashMap<VolumeName, VolumeSpec>,
}

impl ComposeOrchestrator {
    async fn up(&self, project: ComposeProject) -> Result<ProjectHandle, Error> {
        // 1. Create networks
        for (name, spec) in &project.networks {
            self.network_manager.create(name.clone(), spec.driver, spec.config).await?;
        }

        // 2. Create volumes
        for (name, spec) in &project.volumes {
            self.storage_manager.create_volume(name.clone(), spec).await?;
        }

        // 3. Start services in dependency order
        let order = self.resolve_dependencies(&project.services)?;
        for service_name in order {
            let service = &project.services[&service_name];
            self.start_service(service).await?;
        }

        Ok(ProjectHandle { project })
    }
}
```

---

## Context Communication Patterns

### 1. Synchronous Request/Response

Used for immediate, blocking operations.

```rust
// Container creation requires image manifest
let manifest = image_service.get_manifest(&image_id).await?;
```

**Contexts**: All core contexts
**Use When**: Operation must complete before proceeding

---

### 2. Domain Events (Async)

Used for cross-context notifications.

```rust
// ContainerStarted event notifies interested contexts
event_bus.publish(ContainerStarted {
    container_id,
    pid,
    started_at,
}).await?;

// NetworkManager subscribes and attaches to default network
impl EventHandler<ContainerStarted> for NetworkManager {
    async fn handle(&self, event: &ContainerStarted) {
        self.connect_to_bridge(&event.container_id).await?;
    }
}
```

**Contexts**: All contexts
**Use When**: Loose coupling, eventual consistency acceptable

---

### 3. Shared Kernel

Shared value objects and types.

```rust
// Shared kernel: value objects used across contexts
pub mod shared {
    pub use crate::ids::{ContainerId, ImageId, NetworkId, VolumeId};
    pub use crate::values::{Bytes, Timestamp, ExitCode};
    pub use crate::errors::{FerroCrateError, Result};
}
```

**Contents**:
- Value object types (`ContainerId`, `ImageId`, etc.)
- Common enums (`ContainerStatus`, `NetworkDriver`)
- Error types
- Utility types (`Bytes`, `Timestamp`)

---

### 4. Anti-Corruption Layer (ACL)

Translates external formats to internal models.

```rust
// ACL for Docker API compatibility
pub struct DockerApiAcl {
    inner: Arc<dyn ContainerOrchestrator>,
}

impl DockerApiAcl {
    // Translates Docker API request to FerroCrate domain
    pub async fn create_container(
        &self,
        docker_config: DockerContainerConfig,
    ) -> Result<DockerContainerId, DockerApiError> {
        // Translate Docker config to FerroCrate spec
        let spec = self.translate_config(&docker_config)?;

        // Create container using FerroCrate domain
        let container = self.inner.create(spec).await?;

        // Translate back to Docker response
        Ok(DockerContainerId::from(container.id()))
    }

    fn translate_config(&self, docker: &DockerContainerConfig) -> Result<ContainerSpec, Error> {
        // Map Docker-specific fields to FerroCrate domain
        Ok(ContainerSpec {
            image: docker.image.parse()?,
            command: docker.cmd.clone(),
            env: docker.env.iter().map(|e| e.parse()).collect()?,
            // Docker HostConfig -> FerroCrate types
            resource_limits: self.translate_host_config(&docker.host_config)?,
            // ...
        })
    }
}
```

**Use Cases**:
- Docker API compatibility layer
- docker-compose.yml parsing
- External registry protocols

---

## Module/Crate Structure

```
ferrocrate/
├── ferro-shared/          # Shared Kernel
│   ├── src/
│   │   ├── ids.rs         # ContainerId, ImageId, etc.
│   │   ├── values.rs      # Bytes, Timestamp, etc.
│   │   ├── errors.rs      # Common error types
│   │   └── events.rs      # Domain event traits
│   └── Cargo.toml
│
├── ferro-exec/            # ContainerRuntime Context
│   ├── src/
│   │   ├── container.rs   # Container aggregate
│   │   ├── process.rs     # Process management
│   │   ├── namespace.rs   # Namespace handling
│   │   ├── cgroup.rs      # Cgroup v2 management
│   │   └── repository.rs  # ContainerRepository trait
│   └── Cargo.toml
│
├── ferro-store/           # ImageManagement + Storage Contexts
│   ├── src/
│   │   ├── image.rs       # Image aggregate
│   │   ├── layer.rs       # Layer management
│   │   ├── registry.rs    # OCI registry client
│   │   ├── builder.rs     # Image builder
│   │   ├── volume.rs      # Volume aggregate
│   │   └── driver.rs      # Storage driver trait
│   └── Cargo.toml
│
├── ferro-net/             # Networking Context
│   ├── src/
│   │   ├── network.rs     # Network aggregate
│   │   ├── endpoint.rs    # Endpoint entity
│   │   ├── bridge.rs      # Bridge driver
│   │   ├── ebpf.rs        # eBPF packet handling
│   │   └── dns.rs         # Container DNS
│   └── Cargo.toml
│
├── ferro-security/        # Security Context
│   ├── src/
│   │   ├── context.rs     # SecurityContext value object
│   │   ├── seccomp.rs     # Seccomp profiles
│   │   ├── capabilities.rs # Linux capabilities
│   │   ├── rootless.rs    # Rootless operation
│   │   └── audit.rs       # Security audit
│   └── Cargo.toml
│
├── ferro-mind/            # IntelligenceLayer Context
│   ├── src/
│   │   ├── predictor.rs   # Resource prediction
│   │   ├── anomaly.rs     # Anomaly detection
│   │   ├── remediation.rs # Remediation engine
│   │   ├── wasm_model.rs  # WASM neural inference
│   │   └── router.rs      # Cost-tiered routing
│   └── Cargo.toml
│
├── ferro-compose/         # ComposeOrchestration Context
│   ├── src/
│   │   ├── project.rs     # Project aggregate
│   │   ├── service.rs     # Service entity
│   │   ├── parser.rs      # Compose file parser
│   │   └── acl.rs         # Docker ACL
│   └── Cargo.toml
│
└── ferro-cli/             # Application Layer
    ├── src/
    │   ├── commands/      # CLI commands
    │   ├── api/           # HTTP API (optional)
    │   └── main.rs
    └── Cargo.toml
```

---

## Summary Table

| Upstream Context | Downstream Context | Relationship | Integration Pattern |
|------------------|-------------------|--------------|---------------------|
| ImageManagement | ContainerRuntime | Customer/Supplier | Published Language |
| Storage | ContainerRuntime | Customer/Supplier | Published Language + ACL |
| Networking | ContainerRuntime | Customer/Supplier | Published Language |
| Security | ContainerRuntime | Partnership | Partnership |
| IntelligenceLayer | ALL | OHS | Published Language |
| ComposeOrchestration | Core Contexts | Customer | Conformist + ACL |
| External (Docker) | ferro-cli | External | ACL |

Key principles:
1. **ID-based references** between aggregates (no direct object references)
2. **Events** for cross-context notifications
3. **Shared Kernel** for common value objects
4. **ACL** for external format translation
5. **AI is advisory** - IntelligenceLayer observes but doesn't control
