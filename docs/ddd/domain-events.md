# FerroCrate Domain Events

> Events that represent significant occurrences in the domain. Used for cross-aggregate communication and event sourcing.

## Design Philosophy

Domain events in FerroCrate follow these principles:

1. **Past Tense Naming**: Events describe what happened, not what to do
2. **Immutable**: All event data is owned and immutable
3. **Timestamped**: Every event has a precise timestamp
4. **Causation Tracking**: Events can reference what caused them
5. **Serialization**: All events serialize to JSON for persistence

---

## Event Infrastructure

```rust
/// Base trait for all domain events.
pub trait DomainEvent: Send + Sync + 'static {
    /// Unique identifier for this event instance.
    fn event_id(&self) -> EventId;

    /// When the event occurred.
    fn occurred_at(&self) -> Timestamp;

    /// Which aggregate produced this event.
    fn aggregate_type(&self) -> &'static str;

    /// The aggregate's ID.
    fn aggregate_id(&self) -> String;

    /// Event type name for serialization.
    fn event_type(&self) -> &'static str;
}

/// Unique identifier for an event instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventId(uuid::Uuid);

impl EventId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }
}

/// Event metadata including causation and correlation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventMetadata {
    pub event_id: EventId,
    pub occurred_at: Timestamp,
    pub causation_id: Option<EventId>,
    pub correlation_id: Option<uuid::Uuid>,
    pub produced_by: String, // Agent/component that produced the event
}
```

---

## Container Lifecycle Events

### ContainerCreated

```rust
/// Emitted when a new container is created but not yet started.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ContainerCreated {
    pub metadata: EventMetadata,
    pub container_id: ContainerId,
    pub image_id: ImageId,
    pub name: Option<ContainerName>,
    pub labels: HashMap<String, String>,
    pub resource_limits: ResourceLimits,
    pub security_context_summary: SecurityContextSummary,
}

impl DomainEvent for ContainerCreated {
    fn event_id(&self) -> EventId { self.metadata.event_id }
    fn occurred_at(&self) -> Timestamp { self.metadata.occurred_at }
    fn aggregate_type(&self) -> &'static str { "Container" }
    fn aggregate_id(&self) -> String { self.container_id.to_string() }
    fn event_type(&self) -> &'static str { "container.created" }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityContextSummary {
    pub rootless: bool,
    pub capabilities_count: usize,
    pub seccomp_enabled: bool,
}
```

### ContainerStarted

```rust
/// Emitted when a container transitions from Created to Running.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ContainerStarted {
    pub metadata: EventMetadata,
    pub container_id: ContainerId,
    pub pid: Pid,
    pub started_at: Timestamp,
    pub network_endpoints: Vec<EndpointInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointInfo {
    pub network_id: NetworkId,
    pub network_name: String,
    pub ip_address: IpAddr,
}
```

### ContainerStopped

```rust
/// Emitted when a container stops (gracefully or killed).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ContainerStopped {
    pub metadata: EventMetadata,
    pub container_id: ContainerId,
    pub exit_code: ExitCode,
    pub stopped_at: Timestamp,
    pub reason: StopReason,
    pub oom_killed: bool,
    pub cpu_time: Duration,
    pub memory_peak: Bytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StopReason {
    /// Normal exit (exit code 0).
    Exited,
    /// Error exit (non-zero exit code).
    Error,
    /// Killed by signal.
    Signaled { signal: Signal },
    /// Out of memory killed by kernel.
    OomKilled,
    /// Killed by user/API request.
    Killed,
    /// Evicted due to resource pressure.
    Evicted,
}
```

### ContainerPaused / ContainerResumed

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerPaused {
    pub metadata: EventMetadata,
    pub container_id: ContainerId,
    pub paused_at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerResumed {
    pub metadata: EventMetadata,
    pub container_id: ContainerId,
    pub resumed_at: Timestamp,
    pub paused_duration: Duration,
}
```

### ContainerRemoved

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerRemoved {
    pub metadata: EventMetadata,
    pub container_id: ContainerId,
    pub removed_at: Timestamp,
    pub volumes_removed: Vec<VolumeId>,
    pub anonymous_volumes_kept: bool,
}
```

---

## Image Management Events

### ImagePulled

```rust
/// Emitted when an image is successfully pulled from a registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImagePulled {
    pub metadata: EventMetadata,
    pub image_id: ImageId,
    pub source_registry: RegistryInfo,
    pub repository: String,
    pub tag: Option<ImageTag>,
    pub layers_pulled: Vec<LayerInfo>,
    pub layers_cached: Vec<LayerHash>,
    pub pull_duration: Duration,
    pub total_bytes: Bytes,
    pub bytes_transferred: Bytes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryInfo {
    pub host: String,
    pub is_insecure: bool,
    pub authentication_used: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerInfo {
    pub digest: LayerHash,
    pub size: Bytes,
    pub media_type: String,
    pub cached: bool,
}

impl DomainEvent for ImagePulled {
    fn event_id(&self) -> EventId { self.metadata.event_id }
    fn occurred_at(&self) -> Timestamp { self.metadata.occurred_at }
    fn aggregate_type(&self) -> &'static str { "Image" }
    fn aggregate_id(&self) -> String { self.image_id.to_string() }
    fn event_type(&self) -> &'static str { "image.pulled" }
}
```

### ImagePushed

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImagePushed {
    pub metadata: EventMetadata,
    pub image_id: ImageId,
    pub destination_registry: RegistryInfo,
    pub repository: String,
    pub tag: ImageTag,
    pub layers_pushed: Vec<LayerInfo>,
    pub push_duration: Duration,
    pub total_bytes: Bytes,
}
```

### BuildStarted / BuildCompleted / BuildFailed

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildStarted {
    pub metadata: EventMetadata,
    pub build_id: BuildId,
    pub context_path: PathBuf,
    pub dockerfile_path: PathBuf,
    pub target_stage: Option<String>,
    pub build_args: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildCompleted {
    pub metadata: EventMetadata,
    pub build_id: BuildId,
    pub image_id: ImageId,
    pub stages_built: Vec<BuildStageInfo>,
    pub cache_hits: usize,
    pub cache_misses: usize,
    pub build_duration: Duration,
    pub image_size: Bytes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildStageInfo {
    pub name: String,
    pub duration: Duration,
    pub layers_produced: usize,
    pub commands_executed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildFailed {
    pub metadata: EventMetadata,
    pub build_id: BuildId,
    pub error: BuildError,
    pub failed_at_stage: Option<String>,
    pub failed_at_command: Option<String>,
    pub build_duration: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildError {
    pub code: String,
    pub message: String,
    pub details: Option<String>,
}
```

### ImageDeleted

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageDeleted {
    pub metadata: EventMetadata,
    pub image_id: ImageId,
    pub tags_removed: Vec<ImageTag>,
    pub layers_orphaned: Vec<LayerHash>,
    pub disk_freed: Bytes,
}
```

---

## Network Events

### NetworkCreated

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkCreated {
    pub metadata: EventMetadata,
    pub network_id: NetworkId,
    pub name: NetworkName,
    pub driver: NetworkDriver,
    pub subnet: IpCidr,
    pub gateway: IpAddr,
}
```

### ContainerConnected / ContainerDisconnected

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerConnected {
    pub metadata: EventMetadata,
    pub network_id: NetworkId,
    pub container_id: ContainerId,
    pub endpoint_id: EndpointId,
    pub ip_address: IpAddr,
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerDisconnected {
    pub metadata: EventMetadata,
    pub network_id: NetworkId,
    pub container_id: ContainerId,
    pub endpoint_id: EndpointId,
    pub disconnected_at: Timestamp,
}
```

---

## Storage Events

### VolumeCreated / VolumeDeleted

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeCreated {
    pub metadata: EventMetadata,
    pub volume_id: VolumeId,
    pub name: VolumeName,
    pub driver: VolumeDriver,
    pub mountpoint: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeDeleted {
    pub metadata: EventMetadata,
    pub volume_id: VolumeId,
    pub disk_freed: Bytes,
}
```

---

## Intelligence Layer Events

### AnomalyDetected

```rust
/// Emitted when the AI layer detects anomalous container behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyDetected {
    pub metadata: EventMetadata,
    pub anomaly_id: AnomalyId,
    pub container_id: ContainerId,
    pub anomaly_type: AnomalyType,
    pub severity: Severity,
    pub description: String,
    pub evidence: HashMap<String, f64>,
    pub baseline: HashMap<String, f64>,
    pub deviation_scores: HashMap<String, f32>,
    pub detected_at: Timestamp,
}

impl DomainEvent for AnomalyDetected {
    fn event_id(&self) -> EventId { self.metadata.event_id }
    fn occurred_at(&self) -> Timestamp { self.metadata.occurred_at }
    fn aggregate_type(&self) -> &'static str { "Intelligence" }
    fn aggregate_id(&self) -> String { self.container_id.to_string() }
    fn event_type(&self) -> &'static str { "intelligence.anomaly.detected" }
}
```

### ResourcePredicted

```rust
/// Emitted when the AI layer makes a resource prediction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcePredicted {
    pub metadata: EventMetadata,
    pub container_id: ContainerId,
    pub prediction: Prediction,
    pub historical_window: Duration,
    pub model_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prediction {
    pub predicted_memory: Range<Bytes>,
    pub predicted_cpu: Range<f32>,
    pub confidence: f32,
    pub source: PredictionSource,
    pub reasoning: String,
}
```

### RemediationSuggested

```rust
/// Emitted when the AI layer suggests remediation for an issue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationSuggested {
    pub metadata: EventMetadata,
    pub anomaly_id: AnomalyId,
    pub container_id: ContainerId,
    pub remediation: Remediation,
    pub automatic: bool,
    pub estimated_impact: ImpactEstimate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Remediation {
    pub action: RemediationAction,
    pub rationale: String,
    pub risk_level: RiskLevel,
    pub estimated_recovery_time: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactEstimate {
    pub service_availability: f32, // 0.0 - 1.0
    pub data_loss_risk: f32,
    pub recovery_probability: f32,
}
```

### RemediationApplied

```rust
/// Emitted when an automated remediation is executed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationApplied {
    pub metadata: EventMetadata,
    pub anomaly_id: AnomalyId,
    pub container_id: ContainerId,
    pub remediation: Remediation,
    pub result: RemediationResult,
    pub applied_at: Timestamp,
    pub applied_by: String, // "automatic" or user ID
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RemediationResult {
    Success { recovered_at: Timestamp },
    PartialSuccess { message: String },
    Failed { error: String },
    Pending { timeout: Duration },
}
```

### DecisionExplained

```rust
/// Emitted when the AI layer provides an explanation for a decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionExplained {
    pub metadata: EventMetadata,
    pub decision_id: DecisionId,
    pub decision_type: DecisionType,
    pub container_id: Option<ContainerId>,
    pub input_summary: String,
    pub reasoning_chain: Vec<ReasoningStep>,
    pub conclusion: String,
    pub confidence: f32,
    pub cost_tier: CostTier,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningStep {
    pub step_number: u32,
    pub observation: String,
    pub inference: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecisionType {
    ResourcePrediction,
    AnomalyDetection,
    RemediationSuggestion,
    BuildOptimization,
    NaturalLanguageQuery,
}
```

---

## Compose Events

### ProjectStarted / ProjectStopped

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectStarted {
    pub metadata: EventMetadata,
    pub project_name: ProjectName,
    pub compose_file: PathBuf,
    pub services_started: Vec<ServiceStartInfo>,
    pub dependency_order: Vec<String>,
    pub total_duration: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStartInfo {
    pub service_name: String,
    pub container_ids: Vec<ContainerId>,
    pub replicas: u32,
    pub startup_duration: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectStopped {
    pub metadata: EventMetadata,
    pub project_name: ProjectName,
    pub services_stopped: Vec<ServiceStopInfo>,
    pub volumes_removed: Vec<VolumeId>,
    pub networks_removed: Vec<NetworkId>,
}
```

### ServiceScaled

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceScaled {
    pub metadata: EventMetadata,
    pub project_name: ProjectName,
    pub service_name: String,
    pub previous_replicas: u32,
    pub new_replicas: u32,
    pub containers_added: Vec<ContainerId>,
    pub containers_removed: Vec<ContainerId>,
}
```

---

## Event Bus and Handlers

```rust
/// Event bus for publishing and subscribing to domain events.
pub trait EventBus: Send + Sync {
    /// Publish an event to all subscribers.
    async fn publish(&self, event: Box<dyn DomainEvent>) -> Result<(), EventError>;

    /// Publish multiple events atomically.
    async fn publish_batch(&self, events: Vec<Box<dyn DomainEvent>>) -> Result<(), EventError>;

    /// Subscribe to events of a specific type.
    async fn subscribe<E: DomainEvent + 'static>(
        &self,
        handler: Box<dyn EventHandler<E>>,
    ) -> SubscriptionId;
}

/// Handler for a specific event type.
#[async_trait]
pub trait EventHandler<E: DomainEvent>: Send + Sync {
    async fn handle(&self, event: &E) -> Result<(), HandlerError>;
}

// Example handler implementation
pub struct NetworkContainerHandler {
    network_service: Arc<NetworkService>,
}

#[async_trait]
impl EventHandler<ContainerStarted> for NetworkContainerHandler {
    async fn handle(&self, event: &ContainerStarted) -> Result<(), HandlerError> {
        // Connect container to default bridge network
        self.network_service.connect_to_bridge(&event.container_id).await?;
        Ok(())
    }
}
```

---

## Event Sourcing (Optional)

```rust
/// Event store for persisting and replaying events.
#[async_trait]
pub trait EventStore: Send + Sync {
    /// Append events to an aggregate's event stream.
    async fn append(
        &self,
        aggregate_type: &str,
        aggregate_id: &str,
        events: Vec<Box<dyn DomainEvent>>,
        expected_version: Option<u64>,
    ) -> Result<u64, EventStoreError>;

    /// Load all events for an aggregate.
    async fn load(
        &self,
        aggregate_type: &str,
        aggregate_id: &str,
    ) -> Result<Vec<StoredEvent>, EventStoreError>;

    /// Subscribe to all events after a given position.
    async fn subscribe_all(&self, after: Option<u64>) -> EventStream;
}

/// Stored event with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEvent {
    pub sequence: u64,
    pub aggregate_type: String,
    pub aggregate_id: String,
    pub event_type: String,
    pub event_data: serde_json::Value,
    pub metadata: EventMetadata,
}
```

---

## Event Summary

| Event | Aggregate | Purpose |
|-------|-----------|---------|
| ContainerCreated | Container | Track container creation |
| ContainerStarted | Container | Track container start, attach networking |
| ContainerStopped | Container | Track termination, collect metrics |
| ContainerPaused/Resumed | Container | Track pause state changes |
| ContainerRemoved | Container | Cleanup resources |
| ImagePulled | Image | Track downloads, cache stats |
| ImagePushed | Image | Track uploads |
| BuildStarted/Completed/Failed | Build | Track build progress |
| AnomalyDetected | Intelligence | Alert on anomalies |
| ResourcePredicted | Intelligence | Log predictions for learning |
| RemediationSuggested/Applied | Intelligence | Track automated fixes |
| DecisionExplained | Intelligence | Audit AI decisions |
| ProjectStarted/Stopped | Compose | Track multi-service lifecycle |
| ServiceScaled | Compose | Track scaling operations |
