# FerroCrate Domain-Driven Design Documentation

> Strategic and tactical DDD patterns adapted for a Rust systems programming project.

## Overview

This directory contains the complete Domain-Driven Design documentation for FerroCrate, an AI-native container runtime written in Rust. The DDD approach has been adapted to fit Rust's unique characteristics:

- **Ownership Model**: Aggregates map to Rust's ownership semantics
- **Trait-Based Abstraction**: Repository and service interfaces are Rust traits
- **Type Safety**: Value objects enforce domain invariants at compile time
- **Module Boundaries**: Bounded contexts map to Rust crates

## Documentation Index

| File | Description |
|------|-------------|
| [bounded-contexts.json](./bounded-contexts.json) | Definition of all bounded contexts and their relationships |
| [domain-model.json](./domain-model.json) | Core entities, value objects, and domain rules |
| [aggregates.md](./aggregates.md) | Aggregate roots: Container, Image, Volume, Network, Pod |
| [value-objects.md](./value-objects.md) | Immutable domain primitives with validation |
| [domain-events.md](./domain-events.md) | Events for cross-context communication |
| [repositories.md](./repositories.md) | Repository trait interfaces and implementations |
| [services.md](./services.md) | Domain service interfaces and implementations |
| [context-map.md](./context-map.md) | Strategic context relationships and integration patterns |
| [schemas.md](./schemas.md) | JSON schemas for API and persistence |

## Quick Reference

### Bounded Contexts

```
ContainerRuntime (ferro-exec)
    - Container lifecycle management
    - Process isolation, namespaces, cgroups

ImageManagement (ferro-store)
    - OCI image handling
    - Layer deduplication with Blake3

Networking (ferro-net)
    - Container networking
    - eBPF-based packet handling

Storage (ferro-storage)
    - Volume management
    - OverlayFS layer management

Security (ferro-security)
    - Rootless operation
    - Seccomp, capabilities, AppArmor

IntelligenceLayer (ferro-mind)
    - Resource prediction
    - Anomaly detection
    - Remediation engine

ComposeOrchestration (ferro-compose)
    - Multi-container coordination
    - docker-compose compatibility
```

### Aggregate Roots

| Aggregate | Root Type | Key Invariants |
|-----------|-----------|----------------|
| Container | `ContainerId` | State transitions, PID consistency |
| Image | `ImageId` | Content-addressable, immutable |
| Volume | `VolumeId` | Persistence, exclusive deletion |
| Network | `NetworkId` | IP uniqueness, single attachment |
| Pod | `PodId` | Replica consistency, cascading delete |

### Key Domain Services

| Service | Responsibility |
|---------|---------------|
| `ContainerOrchestrator` | Container lifecycle coordination |
| `ImageBuilder` | Image build from Dockerfile/Ferrofile |
| `NetworkManager` | Container network attachment |
| `SecurityEnforcer` | Security context building and application |
| `ResourcePredictor` | AI-powered resource prediction |
| `AnomalyDetector` | Container anomaly detection |

## Rust-Specific Patterns

### Newtype Pattern for Value Objects

```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ContainerId(IdInner);

impl ContainerId {
    pub fn new() -> Self { Self(IdInner::Uuid(Uuid::new_v4())) }
    pub fn parse(s: &str) -> Result<Self, ParseIdError> { /* ... */ }
}
```

### Trait-Based Repository Abstraction

```rust
#[async_trait]
pub trait ContainerRepository: Send + Sync {
    async fn find(&self, id: &ContainerId) -> Result<Option<Container>, RepositoryError>;
    async fn save(&self, container: &Container) -> Result<(), RepositoryError>;
    async fn delete(&self, id: &ContainerId) -> Result<(), RepositoryError>;
}
```

### Type-State for Lifecycle Enforcement

```rust
pub struct Container<State> { /* ... */ }

impl Container<Created> {
    pub fn start(self) -> Result<Container<Running>, ContainerError> { /* ... */ }
}

impl Container<Running> {
    pub fn stop(self) -> Result<Container<Stopped>, ContainerError> { /* ... */ }
}
```

### Event-Driven Cross-Context Communication

```rust
#[async_trait]
pub trait EventHandler<E: DomainEvent>: Send + Sync {
    async fn handle(&self, event: &E) -> Result<(), HandlerError>;
}

// NetworkManager handles ContainerStarted events
impl EventHandler<ContainerStarted> for NetworkManager {
    async fn handle(&self, event: &ContainerStarted) -> Result<(), HandlerError> {
        self.connect_to_bridge(&event.container_id).await
    }
}
```

## Design Decisions

### 1. ID-Based References Between Aggregates

Aggregates reference each other by ID, not direct object references. This:
- Avoids complex lifetime management
- Enables independent loading/unloading
- Maintains clear aggregate boundaries

```rust
struct Container {
    image_id: ImageId,  // NOT: image: Arc<Image>
}
```

### 2. AI is Advisory Only

The IntelligenceLayer observes but does not control other contexts:

```rust
// AI returns optional recommendations
async fn predict(&self, container_id: &ContainerId) -> Option<Prediction>

// Runtime MAY apply but isn't required
if let Some(pred) = predictor.predict(&id).await {
    if pred.confidence >= threshold {
        apply_recommendation(&pred).await?;
    }
}
```

### 3. Docker Compatibility via ACL

An Anti-Corruption Layer translates Docker API to FerroCrate domain:

```rust
impl DockerApiAcl {
    async fn create_container(&self, docker_config: DockerContainerConfig)
        -> Result<DockerContainerId, DockerApiError>
    {
        let spec = self.translate_config(&docker_config)?;
        let container = self.inner.create(spec).await?;
        Ok(DockerContainerId::from(container.id()))
    }
}
```

### 4. Graceful Degradation

All contexts work without the IntelligenceLayer:

```rust
// Container works with or without AI
impl ContainerOrchestrator {
    async fn start(&self, id: &ContainerId) -> Result<RunningContainer, Error> {
        // Core logic always works
        let container = self.start_container(id).await?;

        // AI enhancement is optional
        if let Some(predictor) = &self.predictor {
            if let Some(pred) = predictor.predict(id).await {
                self.maybe_apply_prediction(&pred).await;
            }
        }

        Ok(container)
    }
}
```

## Crate Structure

```
ferrocrate/
  ferro-shared/      # Shared Kernel (value objects, errors)
  ferro-exec/        # ContainerRuntime context
  ferro-store/       # ImageManagement + Storage contexts
  ferro-net/         # Networking context
  ferro-security/    # Security context
  ferro-mind/        # IntelligenceLayer context
  ferro-compose/     # ComposeOrchestration context
  ferro-cli/         # Application layer
```

## Integration with PRD

This DDD documentation aligns with the Product Requirements Document (PRD):

| PRD Section | DDD Mapping |
|-------------|-------------|
| Container Lifecycle (CLM-*) | Container aggregate, ContainerOrchestrator service |
| Image Management (IMG-*) | Image aggregate, ImageBuilder service |
| Networking (NET-*) | Network aggregate, NetworkManager service |
| Storage (STR-*) | Volume aggregate, StorageManager service |
| Security (SEC-*) | SecurityContext value object, SecurityEnforcer service |
| AI/Intelligence (AI-*) | Prediction, Anomaly value objects, Intelligence services |
| Compose (CMP-*) | Pod aggregate, ComposeOrchestrator service |

## Next Steps

1. **Implementation Planning**: Use this DDD model to create implementation milestones
2. **API Design**: Derive REST/gRPC API from repository and service interfaces
3. **Testing Strategy**: Create test fixtures based on aggregate invariants
4. **Documentation**: Generate API docs from JSON schemas

---

*Generated for FerroCrate v1.0 | February 2026*
