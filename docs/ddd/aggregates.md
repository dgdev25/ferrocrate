# FerroCrate Aggregates

> Domain-Driven Design aggregates mapped to Rust ownership and module boundaries.

## Overview

Aggregates are consistency boundaries that group entities and value objects. In Rust, aggregates map naturally to:

- **Ownership**: Aggregate root owns all internal entities
- **Visibility**: Internal state is private, accessed through the root
- **Invariants**: Methods on the root enforce consistency rules

---

## Container Aggregate

**Context**: `ContainerRuntime`
**Crate**: `ferro-exec`
**Root**: `ContainerId`

### Structure

```rust
// Aggregate Root
pub struct Container {
    id: ContainerId,
    spec: ContainerSpec,
    state: ContainerState,
    mounts: MountSet,
    network: NetworkAttachment,
    security: SecurityContext,
    health: Option<HealthStatus>,
    metadata: ContainerMetadata,
}

// Internal Entities (owned by Container)
struct ContainerState {
    status: ContainerStatus,
    pid: Option<Pid>,
    exit_code: Option<ExitCode>,
    created_at: Timestamp,
    started_at: Option<Timestamp>,
    finished_at: Option<Timestamp>,
}

struct HealthStatus {
    status: HealthState,
    last_check: Timestamp,
    failures: u32,
    last_output: String,
}

struct ContainerMetadata {
    name: Option<ContainerName>,
    labels: HashMap<String, String>,
    annotations: HashMap<String, String>,
}
```

### Invariants Enforced

1. **State Transitions**: Only valid status transitions allowed
2. **PID Consistency**: PID is Some only when status is Running
3. **Exit Code**: Exit code set only when status is Exited
4. **Mount Integrity**: All mount paths are absolute and non-overlapping
5. **Resource Limits**: Limits are validated before container creation

### Rust Ownership Model

```rust
impl Container {
    // Factory method - enforces invariants at construction
    pub fn create(spec: ContainerSpec) -> Result<Self, ContainerError> {
        spec.validate()?;
        Ok(Self {
            id: ContainerId::new(),
            spec,
            state: ContainerState::created(),
            // ...
        })
    }

    // State transition - consumes old state, returns new
    pub fn start(mut self, runtime: &Runtime) -> Result<RunningContainer, ContainerError> {
        if !self.state.status.can_start() {
            return Err(ContainerError::InvalidStateTransition {
                from: self.state.status,
                to: ContainerStatus::Running,
            });
        }

        let pid = runtime.spawn_process(&self.spec)?;
        self.state = ContainerState::running(pid);

        Ok(RunningContainer { inner: self })
    }

    // Query - borrows self, returns owned value object
    pub fn status(&self) -> ContainerStatus {
        self.state.status
    }

    // Command - mutable borrow for state change
    pub fn kill(&mut self, signal: Signal) -> Result<(), ContainerError> {
        match &self.state.status {
            ContainerStatus::Running(pid) => {
                kill(*pid, signal)?;
                self.state.status = ContainerStatus::Exited(ExitCode::from_signal(signal));
                Ok(())
            }
            _ => Err(ContainerError::NotRunning(self.id)),
        }
    }
}

// Type-state pattern alternative for compile-time guarantees
pub struct RunningContainer { inner: Container }
pub struct StoppedContainer { inner: Container }

impl RunningContainer {
    pub fn stop(self) -> Result<StoppedContainer, ContainerError> {
        // Only running containers can be stopped
    }
}
```

### External References

Other aggregates reference Container by ID only:

```rust
struct Endpoint {
    container_id: ContainerId,  // NOT Arc<Container> or &Container
    network_id: NetworkId,
    ip_address: IpAddress,
}
```

---

## Image Aggregate

**Context**: `ImageManagement`
**Crate**: `ferro-store`
**Root**: `ImageId` (content-addressable SHA-256 digest)

### Structure

```rust
// Aggregate Root - Immutable after creation
pub struct Image {
    id: ImageId,
    manifest: ImageManifest,
    config: ImageConfig,
    layers: Vec<LayerRef>,
    tags: HashSet<ImageTag>,
    metadata: ImageMetadata,
}

// Layer reference - points to shared Layer aggregate
struct LayerRef {
    digest: LayerHash,
    media_type: MediaType,
    size: Bytes,
    // Layers are shared across images via content-addressing
}

struct ImageMetadata {
    pulled_at: Option<Timestamp>,
    built_at: Option<Timestamp>,
    local_size: Bytes,
}
```

### Invariants Enforced

1. **Content-Addressable**: Image ID must match SHA-256 of manifest
2. **Layer Integrity**: All referenced layers must exist in store
3. **Immutability**: No mutable methods on Image (functional update returns new Image)
4. **Tag Uniqueness**: Same tag cannot point to different images

### Rust Immutability Pattern

```rust
impl Image {
    // Images are immutable - "modification" returns new instance
    pub fn with_tag(&self, tag: ImageTag) -> Result<Image, ImageError> {
        let mut new_tags = self.tags.clone();
        new_tags.insert(tag);
        Ok(Image {
            tags: new_tags,
            ..self.clone()
        })
    }

    // Verification on construction
    pub fn from_manifest(manifest: ImageManifest, store: &LayerStore) -> Result<Self, ImageError> {
        let id = ImageId::from_manifest(&manifest)?;

        // Verify all layers exist
        for layer in &manifest.layers {
            store.get_layer(layer)?;
        }

        Ok(Self {
            id,
            manifest,
            // ...
        })
    }
}

// Clone is cheap - Image is mostly Arc references internally
impl Clone for Image {
    fn clone(&self) -> Self {
        // Shallow clone - layers are Arc'd
    }
}
```

### Layer Sharing

```rust
// Layers are a separate aggregate, shared via content-addressing
pub struct Layer {
    digest: LayerHash,
    compressed_blob: BlobRef,
    uncompressed_size: Bytes,
    compression: CompressionType,
}

// Multiple images reference the same layer
let image_a: Image = store.get_image(&id_a)?;
let image_b: Image = store.get_image(&id_b)?;

// Both may reference the same layer by digest
assert!(image_a.layers.iter().any(|l| l.digest == shared_digest));
assert!(image_b.layers.iter().any(|l| l.digest == shared_digest));
```

---

## Volume Aggregate

**Context**: `Storage`
**Crate**: `ferro-storage`
**Root**: `VolumeId`

### Structure

```rust
pub struct Volume {
    id: VolumeId,
    name: VolumeName,
    driver: VolumeDriver,
    mountpoint: PathBuf,
    options: VolumeOptions,
    labels: HashMap<String, String>,
    usage: Option<VolumeUsage>,
    created_at: Timestamp,
}

pub struct VolumeOptions {
    driver_opts: HashMap<String, String>,
    labels: HashMap<String, String>,
    scope: VolumeScope,
}

pub enum VolumeDriver {
    Local,
    Overlay,
    Plugin(String),  // Extensible via trait objects
}
```

### Invariants Enforced

1. **Persistence**: Volume data survives container deletion
2. **Exclusive Deletion**: Cannot delete volume while mounted
3. **Path Validity**: Mount point must be absolute and exist
4. **Driver Compatibility**: Options must be valid for driver

### Rust Implementation

```rust
impl Volume {
    pub fn create(name: VolumeName, driver: VolumeDriver, opts: VolumeOptions) -> Result<Self, VolumeError> {
        let mountpoint = driver.create_volume(&name, &opts)?;

        Ok(Self {
            id: VolumeId::new(),
            name,
            driver,
            mountpoint,
            options: opts,
            // ...
        })
    }

    pub fn delete(self, force: bool) -> Result<(), VolumeError> {
        if self.is_mounted() && !force {
            return Err(VolumeError::InUse { volume: self.id, mounts: self.active_mounts() });
        }

        self.driver.delete_volume(&self.mountpoint)?;
        // self is consumed, cannot be used after deletion
        Ok(())
    }

    fn is_mounted(&self) -> bool {
        // Check if volume has active mounts
    }
}

// Volume mount is a separate value object
pub struct VolumeMount {
    volume_id: VolumeId,
    container_id: ContainerId,
    destination: PathBuf,
    read_only: bool,
}
```

---

## Network Aggregate

**Context**: `Networking`
**Crate**: `ferro-net`
**Root**: `NetworkId`

### Structure

```rust
pub struct Network {
    id: NetworkId,
    name: NetworkName,
    driver: NetworkDriver,
    config: NetworkConfig,
    endpoints: Vec<EndpointId>,
    labels: HashMap<String, String>,
    created_at: Timestamp,
}

pub struct NetworkConfig {
    subnet: IpCidr,
    gateway: IpAddress,
    ip_range: Option<IpCidr>,
    enable_ipv6: bool,
    dns_servers: Vec<IpAddress>,
}

pub enum NetworkDriver {
    Bridge,
    Host,
    Overlay,
    None,
    Macvlan,
}

// Endpoint is an entity within the Network aggregate
pub struct Endpoint {
    id: EndpointId,
    container_id: ContainerId,
    network_id: NetworkId,
    ip_address: IpAddress,
    mac_address: MacAddress,
    aliases: Vec<String>,
}
```

### Invariants Enforced

1. **IP Uniqueness**: No duplicate IPs within network subnet
2. **Single Attachment**: Container can only connect once to a network
3. **Subnet Validity**: All IPs must be within configured subnet
4. **Default Protection**: Cannot delete default bridge network

### Rust Implementation

```rust
impl Network {
    pub fn create(name: NetworkName, driver: NetworkDriver, config: NetworkConfig) -> Result<Self, NetworkError> {
        // Validate subnet doesn't conflict
        driver.validate_config(&config)?;

        Ok(Self {
            id: NetworkId::new(),
            name,
            driver,
            config,
            endpoints: Vec::new(),
            // ...
        })
    }

    pub fn connect(&mut self, container_id: ContainerId) -> Result<Endpoint, NetworkError> {
        // Check for duplicate connection
        if self.endpoints.iter().any(|e| e.container_id == container_id) {
            return Err(NetworkError::AlreadyConnected { container: container_id, network: self.id });
        }

        let ip = self.allocate_ip()?;
        let endpoint = Endpoint::new(container_id, self.id, ip);

        self.endpoints.push(endpoint.id);

        Ok(endpoint)
    }

    fn allocate_ip(&self) -> Result<IpAddress, NetworkError> {
        // Find next available IP in subnet
        let used_ips: HashSet<_> = self.endpoints.iter()
            .filter_map(|e| self.get_endpoint(e).map(|ep| ep.ip_address))
            .collect();

        self.config.subnet.iter()
            .find(|ip| !used_ips.contains(ip))
            .ok_or(NetworkError::SubnetExhausted(self.id))
    }
}
```

---

## Pod Aggregate

**Context**: `ComposeOrchestration`
**Crate**: `ferro-compose`
**Root**: `PodId`

### Structure

```rust
pub struct Pod {
    id: PodId,
    name: PodName,
    project: ProjectName,
    service: ServiceName,
    replicas: DesiredReplicas,
    containers: Vec<ContainerId>,
    template: ContainerTemplate,
    status: PodStatus,
}

pub struct ContainerTemplate {
    image: ImageId,
    command: Option<Vec<String>>,
    env: HashMap<String, String>,
    ports: Vec<PortSpec>,
    volumes: Vec<VolumeSpec>,
    networks: Vec<NetworkSpec>,
    resource_limits: ResourceLimits,
}

pub struct DesiredReplicas(u32);

pub enum PodStatus {
    Starting,
    Running { healthy: usize },
    Degraded { healthy: usize, total: usize },
    Stopped,
}
```

### Invariants Enforced

1. **Replica Consistency**: Container count matches desired replicas
2. **Template Uniformity**: All containers use same template
3. **Cascading Delete**: Pod deletion removes all containers
4. **Naming Convention**: Containers named `{project}-{service}-{index}`

### Rust Implementation

```rust
impl Pod {
    pub async fn scale(&mut self, desired: DesiredReplicas, runtime: &ContainerRuntime) -> Result<(), PodError> {
        let current = self.containers.len() as u32;

        match desired.0.cmp(&current) {
            Ordering::Greater => {
                for i in current..desired.0 {
                    let container = self.create_replica(i, runtime).await?;
                    self.containers.push(container.id());
                }
            }
            Ordering::Less => {
                for container_id in self.containers.drain(desired.0 as usize..) {
                    runtime.remove_container(container_id).await?;
                }
            }
            Ordering::Equal => {}
        }

        self.replicas = desired;
        Ok(())
    }

    async fn create_replica(&self, index: u32, runtime: &ContainerRuntime) -> Result<Container, PodError> {
        let name = ContainerName::new(format!("{}-{}-{}", self.project, self.service, index));

        let spec = ContainerSpec::builder()
            .name(name)
            .image(self.template.image.clone())
            .env(self.template.env.clone())
            .build()?;

        runtime.create_container(spec).await
    }

    pub fn health_status(&self, health_checker: &HealthChecker) -> PodStatus {
        let healthy = self.containers.iter()
            .filter(|id| health_checker.is_healthy(id))
            .count();

        if healthy == self.containers.len() {
            PodStatus::Running { healthy }
        } else {
            PodStatus::Degraded { healthy, total: self.containers.len() }
        }
    }
}
```

---

## Aggregate Interaction Rules

### Cross-Aggregate References

```rust
// Aggregates reference each other by ID, not direct reference
struct Container {
    image_id: ImageId,        // NOT: image: Arc<Image>
    volume_ids: Vec<VolumeId>, // NOT: volumes: Vec<Arc<Volume>>
    network_ids: Vec<NetworkId>, // NOT: networks: Vec<Arc<Network>>
}
```

### Consistency Boundaries

| Boundary | Scope | Consistency |
|----------|-------|-------------|
| Container | Single container | Strong (transactional) |
| Image | Single image | Strong |
| Network | Single network + endpoints | Strong |
| Pod | All replicas | Eventual (orchestration) |
| Cross-Aggregate | Multiple aggregates | Eventual consistency |

### Event-Driven Coordination

```rust
// Aggregates communicate via domain events
pub enum DomainEvent {
    ContainerStarted { container_id: ContainerId, image_id: ImageId },
    ContainerStopped { container_id: ContainerId, exit_code: ExitCode },
    ImagePulled { image_id: ImageId, layers: Vec<LayerHash> },
    NetworkCreated { network_id: NetworkId, subnet: IpCidr },
    AnomalyDetected { container_id: ContainerId, anomaly: Anomaly },
}

// Event handlers in other bounded contexts
impl EventHandler for NetworkContext {
    fn handle(&mut self, event: DomainEvent) {
        match event {
            DomainEvent::ContainerStarted { container_id, .. } => {
                // Attach to default network
            }
            _ => {}
        }
    }
}
```

---

## Summary

| Aggregate | Root | Crate | Key Invariants |
|-----------|------|-------|----------------|
| Container | ContainerId | ferro-exec | State transitions, PID consistency |
| Image | ImageId | ferro-store | Content-addressable, immutable |
| Volume | VolumeId | ferro-storage | Persistence, exclusive deletion |
| Network | NetworkId | ferro-net | IP uniqueness, single attachment |
| Pod | PodId | ferro-compose | Replica count, cascading delete |

These aggregates map directly to Rust's ownership model, ensuring compile-time enforcement of domain invariants where possible, and runtime validation for dynamic cases.
