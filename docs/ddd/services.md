# FerroCrate Domain Services

> Services that encapsulate domain logic not naturally fitting within entities or value objects.

## Design Philosophy

Domain services in FerroCrate follow these principles:

1. **Stateless**: Services don't hold domain state (may have config/clients)
2. **Trait-Based**: Interfaces are traits for testability and flexibility
3. **Named After Operations**: Service names describe what they do
4. **Coordinate Aggregates**: Services orchestrate operations across multiple aggregates
5. **Pure Domain Logic**: No infrastructure concerns (those go in application services)

---

## Core Domain Services

### ContainerOrchestrator

Manages container lifecycle operations that span multiple aggregates.

```rust
/// Service for orchestrating container lifecycle operations.
#[async_trait]
pub trait ContainerOrchestrator: Send + Sync {
    /// Create a new container from a specification.
    async fn create(
        &self,
        spec: ContainerSpec,
    ) -> Result<Container, OrchestrationError>;

    /// Start a created container.
    async fn start(
        &self,
        id: &ContainerId,
    ) -> Result<RunningContainer, OrchestrationError>;

    /// Stop a running container.
    async fn stop(
        &self,
        id: &ContainerId,
        timeout: Option<Duration>,
    ) -> Result<ExitCode, OrchestrationError>;

    /// Kill a container immediately.
    async fn kill(
        &self,
        id: &ContainerId,
        signal: Signal,
    ) -> Result<(), OrchestrationError>;

    /// Remove a stopped container.
    async fn remove(
        &self,
        id: &ContainerId,
        force: bool,
        remove_volumes: bool,
    ) -> Result<(), OrchestrationError>;

    /// Execute a command in a running container.
    async fn exec(
        &self,
        id: &ContainerId,
        cmd: ExecSpec,
    ) -> Result<ExecSession, OrchestrationError>;

    /// Pause a running container.
    async fn pause(&self, id: &ContainerId) -> Result<(), OrchestrationError>;

    /// Resume a paused container.
    async fn resume(&self, id: &ContainerId) -> Result<(), OrchestrationError>;

    /// Get container logs.
    async fn logs(
        &self,
        id: &ContainerId,
        opts: LogOptions,
    ) -> Result<BoxStream<'static, Result<LogChunk, OrchestrationError>>, OrchestrationError>;

    /// Check container health.
    async fn health_check(
        &self,
        id: &ContainerId,
    ) -> Result<HealthStatus, OrchestrationError>;
}

/// Implementation of ContainerOrchestrator.
pub struct ContainerOrchestratorService {
    container_repo: Arc<dyn ContainerRepository>,
    image_service: Arc<dyn ImageService>,
    network_service: Arc<dyn NetworkManager>,
    storage_service: Arc<dyn StorageManager>,
    security_service: Arc<dyn SecurityEnforcer>,
    process_manager: Arc<dyn ProcessManager>,
    event_bus: Arc<dyn EventBus>,
}

impl ContainerOrchestratorService {
    pub fn new(
        container_repo: Arc<dyn ContainerRepository>,
        image_service: Arc<dyn ImageService>,
        network_service: Arc<dyn NetworkManager>,
        storage_service: Arc<dyn StorageManager>,
        security_service: Arc<dyn SecurityEnforcer>,
        process_manager: Arc<dyn ProcessManager>,
        event_bus: Arc<dyn EventBus>,
    ) -> Self {
        Self {
            container_repo,
            image_service,
            network_service,
            storage_service,
            security_service,
            process_manager,
            event_bus,
        }
    }
}

#[async_trait]
impl ContainerOrchestrator for ContainerOrchestratorService {
    async fn create(
        &self,
        spec: ContainerSpec,
    ) -> Result<Container, OrchestrationError> {
        // 1. Validate image exists
        let image = self.image_service
            .ensure_available(&spec.image)
            .await?;

        // 2. Prepare rootfs
        let rootfs = self.storage_service
            .prepare_rootfs(&image, &spec.mounts)
            .await?;

        // 3. Build security context
        let security_context = self.security_service
            .build_context(&spec.security)
            .await?;

        // 4. Create container aggregate
        let container = Container::create(spec)?;

        // 5. Persist container
        self.container_repo.save(&container).await?;

        // 6. Publish event
        self.event_bus.publish(Box::new(ContainerCreated {
            metadata: EventMetadata::new(),
            container_id: container.id().clone(),
            image_id: image.id().clone(),
            // ...
        })).await?;

        Ok(container)
    }

    async fn start(
        &self,
        id: &ContainerId,
    ) -> Result<RunningContainer, OrchestrationError> {
        // 1. Load container
        let container = self.container_repo
            .find(id)
            .await?
            .ok_or(OrchestrationError::NotFound(id.clone()))?;

        // 2. Ensure image is available
        let image = self.image_service
            .ensure_available(&container.image_id())
            .await?;

        // 3. Prepare storage
        let rootfs = self.storage_service
            .mount_rootfs(&container)
            .await?;

        // 4. Create network endpoints
        let endpoints = self.network_service
            .attach_container(&container)
            .await?;

        // 5. Spawn process
        let pid = self.process_manager
            .spawn(&container, &image, &rootfs, &security_context)
            .await?;

        // 6. Update container state
        let container = container.start(pid)?;

        // 7. Persist updated state
        self.container_repo.save(&container).await?;

        // 8. Publish event
        self.event_bus.publish(Box::new(ContainerStarted {
            metadata: EventMetadata::new(),
            container_id: container.id().clone(),
            pid,
            // ...
        })).await?;

        Ok(RunningContainer { inner: container })
    }

    async fn stop(
        &self,
        id: &ContainerId,
        timeout: Option<Duration>,
    ) -> Result<ExitCode, OrchestrationError> {
        let container = self.container_repo
            .find(id)
            .await?
            .ok_or(OrchestrationError::NotFound(id.clone()))?;

        let timeout = timeout.unwrap_or(Duration::from_secs(10));

        // 1. Send SIGTERM
        self.process_manager.signal(container.pid(), Signal::Term)?;

        // 2. Wait for graceful shutdown or force kill
        let exit_code = tokio::select! {
            result = self.process_manager.wait(container.pid()) => {
                result?
            }
            _ = tokio::time::sleep(timeout) => {
                // Force kill
                self.process_manager.signal(container.pid(), Signal::Kill)?;
                self.process_manager.wait(container.pid()).await?
            }
        };

        // 3. Cleanup resources
        self.network_service.detach_container(&container).await?;
        self.storage_service.unmount_rootfs(&container).await?;

        // 4. Update state
        let container = container.stop(exit_code);
        self.container_repo.save(&container).await?;

        // 5. Publish event
        self.event_bus.publish(Box::new(ContainerStopped {
            metadata: EventMetadata::new(),
            container_id: container.id().clone(),
            exit_code,
            // ...
        })).await?;

        Ok(exit_code)
    }

    // ... other methods
}
```

---

### ImageBuilder

Manages image build operations from Dockerfile or Ferrofile.

```rust
/// Service for building container images.
#[async_trait]
pub trait ImageBuilder: Send + Sync {
    /// Build image from Dockerfile.
    async fn build_dockerfile(
        &self,
        context: BuildContext,
        dockerfile: PathBuf,
        opts: BuildOptions,
    ) -> Result<Image, BuildError>;

    /// Build image from Ferrofile (declarative format).
    async fn build_ferrofile(
        &self,
        ferrofile: PathBuf,
        opts: BuildOptions,
    ) -> Result<Image, BuildError>;

    /// Get build status.
    async fn status(&self, build_id: &BuildId) -> Result<BuildStatus, BuildError>;

    /// Cancel a running build.
    async fn cancel(&self, build_id: &BuildId) -> Result<(), BuildError>;

    /// Prune build cache.
    async fn prune_cache(&self, opts: CachePruneOptions) -> Result<Bytes, BuildError>;
}

/// Implementation of ImageBuilder.
pub struct ImageBuilderService {
    layer_repo: Arc<dyn LayerRepository>,
    image_repo: Arc<dyn ImageRepository>,
    build_repo: Arc<dyn BuildRepository>,
    cache: Arc<dyn BuildCache>,
    event_bus: Arc<dyn EventBus>,
}

#[async_trait]
impl ImageBuilder for ImageBuilderService {
    async fn build_dockerfile(
        &self,
        context: BuildContext,
        dockerfile: PathBuf,
        opts: BuildOptions,
    ) -> Result<Image, BuildError> {
        let build_id = BuildId::new();

        // 1. Parse Dockerfile
        let stages = self.parse_dockerfile(&dockerfile).await?;

        // 2. Publish build started
        self.event_bus.publish(Box::new(BuildStarted {
            metadata: EventMetadata::new(),
            build_id: build_id.clone(),
            // ...
        })).await?;

        // 3. Execute each stage
        let mut stage_results = Vec::new();
        for stage in &stages {
            let result = self.execute_stage(&build_id, stage, &context, &opts).await?;
            stage_results.push(result);
        }

        // 4. Create final image from last stage
        let final_stage = stage_results.last().ok_or(BuildError::NoStages)?;
        let image = self.create_image(final_stage, &opts).await?;

        // 5. Persist image
        self.image_repo.save(&image).await?;

        // 6. Publish build completed
        self.event_bus.publish(Box::new(BuildCompleted {
            metadata: EventMetadata::new(),
            build_id,
            image_id: image.id().clone(),
            // ...
        })).await?;

        Ok(image)
    }

    async fn execute_stage(
        &self,
        build_id: &BuildId,
        stage: &BuildStage,
        context: &BuildContext,
        opts: &BuildOptions,
    ) -> Result<StageResult, BuildError> {
        let mut layers = Vec::new();

        for instruction in &stage.instructions {
            match instruction {
                Instruction::From { image, .. } => {
                    // Pull base image
                    let base = self.ensure_base_image(image).await?;
                    layers.extend(base.layers);
                }
                Instruction::Run { command } => {
                    // Check cache
                    let cache_key = self.compute_cache_key(&layers, command)?;
                    if let Some(cached) = self.cache.get(&cache_key).await? {
                        if !opts.no_cache {
                            layers.push(cached);
                            continue;
                        }
                    }

                    // Execute command
                    let layer = self.run_command(&layers, command, context).await?;
                    self.cache.set(cache_key, layer.clone()).await?;
                    layers.push(layer);
                }
                Instruction::Copy { src, dest, .. } => {
                    let layer = self.copy_files(&layers, src, dest, context).await?;
                    layers.push(layer);
                }
                // ... other instructions
            }
        }

        Ok(StageResult { layers, stage: stage.clone() })
    }
}
```

---

### NetworkManager

Manages container networking operations.

```rust
/// Service for managing container networks.
#[async_trait]
pub trait NetworkManager: Send + Sync {
    /// Create a new network.
    async fn create(
        &self,
        name: NetworkName,
        driver: NetworkDriver,
        config: NetworkConfig,
    ) -> Result<Network, NetworkError>;

    /// Delete a network.
    async fn delete(&self, id: &NetworkId) -> Result<(), NetworkError>;

    /// Connect a container to a network.
    async fn connect(
        &self,
        network_id: &NetworkId,
        container_id: &ContainerId,
        opts: ConnectOptions,
    ) -> Result<Endpoint, NetworkError>;

    /// Disconnect a container from a network.
    async fn disconnect(
        &self,
        network_id: &NetworkId,
        container_id: &ContainerId,
        force: bool,
    ) -> Result<(), NetworkError>;

    /// List all networks.
    async fn list(&self) -> Result<Vec<Network>, NetworkError>;

    /// Get network by ID or name.
    async fn get(&self, id: &NetworkId) -> Result<Option<Network>, NetworkError>;

    /// Prune unused networks.
    async fn prune(&self) -> Result<Vec<NetworkId>, NetworkError>;

    /// Setup port mapping for a container.
    async fn setup_port_mapping(
        &self,
        container_id: &ContainerId,
        mappings: Vec<PortMapping>,
    ) -> Result<(), NetworkError>;

    /// Remove port mapping.
    async fn remove_port_mapping(
        &self,
        container_id: &ContainerId,
        mapping: &PortMapping,
    ) -> Result<(), NetworkError>;
}

/// Implementation using eBPF for packet handling.
pub struct NetworkManagerService {
    network_repo: Arc<dyn NetworkRepository>,
    ebpf_manager: Arc<dyn EbpfManager>,
    dns_manager: Arc<dyn DnsManager>,
    event_bus: Arc<dyn EventBus>,
}

#[async_trait]
impl NetworkManager for NetworkManagerService {
    async fn create(
        &self,
        name: NetworkName,
        driver: NetworkDriver,
        config: NetworkConfig,
    ) -> Result<Network, NetworkError> {
        // 1. Validate config
        config.validate()?;

        // 2. Create network aggregate
        let network = Network::create(name, driver, config)?;

        // 3. Setup kernel networking
        match driver {
            NetworkDriver::Bridge => {
                self.ebpf_manager.create_bridge(&network).await?;
            }
            NetworkDriver::Overlay => {
                self.ebpf_manager.create_overlay(&network).await?;
            }
            // ...
        }

        // 4. Setup DNS for this network
        self.dns_manager.create_zone(&network).await?;

        // 5. Persist
        self.network_repo.save(&network).await?;

        // 6. Publish event
        self.event_bus.publish(Box::new(NetworkCreated {
            metadata: EventMetadata::new(),
            network_id: network.id().clone(),
            // ...
        })).await?;

        Ok(network)
    }

    async fn connect(
        &self,
        network_id: &NetworkId,
        container_id: &ContainerId,
        opts: ConnectOptions,
    ) -> Result<Endpoint, NetworkError> {
        // 1. Load network
        let mut network = self.network_repo
            .find(network_id)
            .await?
            .ok_or(NetworkError::NotFound(network_id.clone()))?;

        // 2. Create endpoint
        let endpoint = network.connect(container_id.clone(), opts)?;

        // 3. Setup eBPF rules
        self.ebpf_manager.attach_endpoint(&endpoint).await?;

        // 4. Add DNS entry
        self.dns_manager.add_record(
            &network,
            &opts.aliases,
            endpoint.ip_address,
        ).await?;

        // 5. Persist
        self.network_repo.save(&network).await?;

        // 6. Publish event
        self.event_bus.publish(Box::new(ContainerConnected {
            metadata: EventMetadata::new(),
            network_id: network_id.clone(),
            container_id: container_id.clone(),
            // ...
        })).await?;

        Ok(endpoint)
    }

    // ... other methods
}
```

---

### SecurityEnforcer

Manages security context creation and enforcement.

```rust
/// Service for container security configuration.
#[async_trait]
pub trait SecurityEnforcer: Send + Sync {
    /// Build security context from specification.
    fn build_context(&self, spec: &SecuritySpec) -> Result<SecurityContext, SecurityError>;

    /// Apply security context to a process.
    async fn apply(&self, pid: Pid, context: &SecurityContext) -> Result<(), SecurityError>;

    /// Load seccomp profile.
    async fn load_seccomp(&self, profile: &SeccompProfile) -> Result<SeccompFd, SecurityError>;

    /// Validate security specification.
    fn validate(&self, spec: &SecuritySpec) -> Result<(), SecurityError>;

    /// Get available capabilities.
    fn available_capabilities(&self) -> Vec<Capability>;

    /// Check if running rootless.
    fn is_rootless(&self) -> bool;

    /// Get current user namespace mappings.
    fn user_namespace_mappings(&self) -> Vec<IdMapping>;
}

/// Implementation using Linux security APIs.
pub struct SecurityEnforcerService {
    rootless: bool,
    default_seccomp: SeccompProfile,
    available_caps: Vec<Capability>,
}

impl SecurityEnforcerService {
    pub fn new() -> Result<Self, SecurityError> {
        let rootless = !is_root();
        let available_caps = get_available_capabilities()?;
        let default_seccomp = SeccompProfile::default();

        Ok(Self {
            rootless,
            default_seccomp,
            available_caps,
        })
    }
}

#[async_trait]
impl SecurityEnforcer for SecurityEnforcerService {
    fn build_context(&self, spec: &SecuritySpec) -> Result<SecurityContext, SecurityError> {
        let mut context = if self.rootless {
            SecurityContext::default_secure()
        } else {
            SecurityContext::default()
        };

        // Apply user specification
        if let Some(user) = &spec.user {
            context.user = Some(user.clone());
        }

        // Apply capabilities
        for cap in &spec.cap_add {
            if !self.available_caps.contains(cap) {
                return Err(SecurityError::CapabilityNotAvailable(cap.clone()));
            }
            context.capabilities.add.insert(*cap);
        }

        for cap in &spec.cap_drop {
            context.capabilities.add.remove(cap);
        }

        // Apply seccomp
        context.seccomp_profile = match &spec.seccomp_profile {
            Some(path) => Some(SeccompProfile::load(path)?),
            None => Some(self.default_seccomp.clone()),
            None if spec.privileged => None,
        };

        // Privileged mode disables most security
        if spec.privileged {
            context.capabilities = Capabilities::all();
            context.seccomp_profile = None;
            context.read_only_rootfs = false;
        }

        Ok(context)
    }

    async fn apply(&self, pid: Pid, context: &SecurityContext) -> Result<(), SecurityError> {
        // 1. Apply user namespace mappings
        if let Some(user_ns) = &context.user_namespace {
            user_ns.apply(pid)?;
        }

        // 2. Apply capabilities
        context.capabilities.apply(pid)?;

        // 3. Apply seccomp
        if let Some(seccomp) = &context.seccomp_profile {
            seccomp.apply(pid)?;
        }

        // 4. Apply no_new_privileges
        if context.no_new_privileges {
            set_no_new_privileges(pid)?;
        }

        Ok(())
    }

    // ... other methods
}
```

---

## Intelligence Layer Services

### ResourcePredictor

AI-powered resource prediction service.

```rust
/// Service for predicting container resource needs.
#[async_trait]
pub trait ResourcePredictor: Send + Sync {
    /// Predict resource needs for a container.
    async fn predict(
        &self,
        container_id: &ContainerId,
    ) -> Result<Prediction, PredictionError>;

    /// Predict for a new container (no history).
    async fn predict_for_spec(
        &self,
        spec: &ContainerSpec,
    ) -> Result<Prediction, PredictionError>;

    /// Train model with new data.
    async fn train(
        &self,
        container_id: &ContainerId,
        actual: ActualResources,
    ) -> Result<(), PredictionError>;

    /// Get prediction confidence threshold.
    fn confidence_threshold(&self) -> f32;
}

/// Implementation using WASM neural inference.
pub struct ResourcePredictorService {
    wasm_model: WasmNeuralModel,
    history_store: Arc<dyn MetricsHistoryStore>,
    config: PredictorConfig,
}

#[derive(Debug, Clone)]
pub struct PredictorConfig {
    pub confidence_threshold: f32,
    pub history_window: Duration,
    pub fallback_to_heuristics: bool,
}

#[async_trait]
impl ResourcePredictor for ResourcePredictorService {
    async fn predict(
        &self,
        container_id: &ContainerId,
    ) -> Result<Prediction, PredictionError> {
        // 1. Get historical metrics
        let history = self.history_store
            .get_history(container_id, self.config.history_window)
            .await?;

        if history.is_empty() {
            // No history - use spec-based prediction
            return self.predict_from_similar_containers(container_id).await;
        }

        // 2. Extract features
        let features = self.extract_features(&history);

        // 3. Run WASM inference
        let inference_result = self.wasm_model.predict(&features)?;

        // 4. Build prediction
        let prediction = Prediction {
            resources: PredictedResources {
                memory: inference_result.memory_range(),
                cpu: inference_result.cpu_range(),
                recommended_limits: inference_result.recommended_limits(),
            },
            confidence: inference_result.confidence,
            reasoning: inference_result.reasoning,
            source: PredictionSource::WasmInference,
            timestamp: Timestamp::now(),
        };

        Ok(prediction)
    }

    async fn train(
        &self,
        container_id: &ContainerId,
        actual: ActualResources,
    ) -> Result<(), PredictionError> {
        // Store for future predictions
        self.history_store.record(container_id, actual).await?;
        Ok(())
    }

    fn confidence_threshold(&self) -> f32 {
        self.config.confidence_threshold
    }
}
```

### AnomalyDetector

AI-powered anomaly detection service.

```rust
/// Service for detecting container anomalies.
#[async_trait]
pub trait AnomalyDetector: Send + Sync {
    /// Detect anomalies for a container.
    async fn detect(
        &self,
        container_id: &ContainerId,
    ) -> Result<Vec<Anomaly>, AnomalyError>;

    /// Get baseline metrics for a container.
    async fn baseline(&self, container_id: &ContainerId) -> Result<MetricBaseline, AnomalyError>;

    /// Update baseline with new observations.
    async fn update_baseline(
        &self,
        container_id: &ContainerId,
    ) -> Result<(), AnomalyError>;

    /// Configure anomaly thresholds.
    fn configure(&mut self, config: AnomalyConfig);
}

/// Implementation using statistical analysis and WASM models.
pub struct AnomalyDetectorService {
    wasm_model: WasmAnomalyModel,
    metrics_collector: Arc<dyn MetricsCollector>,
    baseline_store: Arc<dyn BaselineStore>,
    config: AnomalyConfig,
    event_bus: Arc<dyn EventBus>,
}

#[async_trait]
impl AnomalyDetector for AnomalyDetectorService {
    async fn detect(
        &self,
        container_id: &ContainerId,
    ) -> Result<Vec<Anomaly>, AnomalyError> {
        // 1. Get current metrics
        let current = self.metrics_collector
            .collect(container_id)
            .await?;

        // 2. Get baseline
        let baseline = self.baseline_store
            .get(container_id)
            .await?
            .unwrap_or_else(|| self.compute_baseline_heuristically(&current));

        // 3. Compute deviation scores
        let deviations = self.compute_deviations(&current, &baseline);

        // 4. Run WASM model for classification
        let classifications = self.wasm_model.classify(&deviations)?;

        // 5. Build anomalies from classifications
        let anomalies: Vec<Anomaly> = classifications
            .into_iter()
            .filter(|c| c.severity >= self.config.min_severity)
            .map(|c| Anomaly {
                id: AnomalyId::new(),
                container_id: container_id.clone(),
                anomaly_type: c.anomaly_type,
                severity: c.severity,
                description: c.description,
                evidence: deviations.clone(),
                remediation: self.suggest_remediations(&c),
                detected_at: Timestamp::now(),
            })
            .collect();

        // 6. Publish events for each anomaly
        for anomaly in &anomalies {
            self.event_bus.publish(Box::new(AnomalyDetected {
                metadata: EventMetadata::new(),
                anomaly_id: anomaly.id,
                container_id: container_id.clone(),
                anomaly_type: anomaly.anomaly_type,
                severity: anomaly.severity,
                description: anomaly.description.clone(),
                evidence: anomaly.evidence.clone(),
                baseline: baseline.to_hashmap(),
                deviation_scores: deviations.clone(),
                detected_at: anomaly.detected_at,
            })).await?;
        }

        Ok(anomalies)
    }

    fn suggest_remediations(&self, classification: &Classification) -> Vec<Remediation> {
        match classification.anomaly_type {
            AnomalyType::MemoryLeak => vec![
                Remediation {
                    action: RemediationAction::RestartContainer,
                    description: "Restart container to release leaked memory".to_string(),
                    automatic: false,
                },
                Remediation {
                    action: RemediationAction::IncreaseMemory { bytes: Bytes::mb(256) },
                    description: "Increase memory limit as temporary mitigation".to_string(),
                    automatic: true,
                },
            ],
            AnomalyType::CpuSpike => vec![
                Remediation {
                    action: RemediationAction::ScaleOut { replicas: 2 },
                    description: "Scale out to handle increased load".to_string(),
                    automatic: true,
                },
            ],
            // ... other types
        }
    }

    // ... other methods
}
```

---

## Service Summary

| Service | Responsibility | Dependencies |
|---------|---------------|--------------|
| ContainerOrchestrator | Container lifecycle | Repositories, ImageService, NetworkManager, StorageManager, SecurityEnforcer |
| ImageBuilder | Image build | LayerRepository, ImageRepository, BuildCache |
| NetworkManager | Container networking | NetworkRepository, EbpfManager, DnsManager |
| SecurityEnforcer | Security context | Linux APIs, Seccomp |
| ResourcePredictor | AI resource prediction | WasmModel, MetricsHistoryStore |
| AnomalyDetector | AI anomaly detection | WasmModel, MetricsCollector, BaselineStore |

Key patterns:
- Services are stateless and thread-safe
- Dependencies injected via Arc<dyn Trait>
- Async operations for I/O
- Events published for cross-context communication
- Clear separation between domain and infrastructure
