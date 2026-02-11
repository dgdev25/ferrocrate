# M3: Integration Milestone

**⚠️ LEGACY NOTICE:** This milestone structure has been superseded by the 6-phase implementation plan (Phase 1-6). Maintained for historical reference only. See `INDEX.md` for the current Phase 1-6 timeline.

**Duration:** Weeks 13-16 | **Story Points:** 45 | **Tasks:** 7

---

## 1. Objective

Deliver the complete FerroCrate experience with docker-compose support, AI-native intelligence features, and migration tooling. This milestone transforms FerroCrate from a container runtime into an intelligent, production-ready platform.

## 2. Scope

### In Scope
- ferro-compose crate (docker-compose.yml v3.x)
- ferro-mind crate (WASM AI inference)
- Resource prediction models
- Anomaly detection and alerting
- Intelligent container restart
- Claude-Flow integration (MCP subprocess)
- Docker migration tool
- Natural language container queries
- AI decision explainability

### Out of Scope
- Kubernetes CRI (Phase 4)
- WireGuard overlay (post-v1.0)
- GPU/VRAM scheduling (post-v1.0)
- Desktop GUI (FerroCrate Pro)

## 3. Architecture

### Component Structure

```
ferro-compose/
+-- Cargo.toml
+-- src/
|   +-- lib.rs
|   +-- parser/
|   |   +-- mod.rs           # Compose file parser
|   |   +-- v3.rs            # Version 3.x parsing
|   |   +-- interpolate.rs   # Variable interpolation
|   +-- planner/
|   |   +-- mod.rs           # Execution planner
|   |   +-- dependency.rs    # Service dependencies
|   |   +-- graph.rs         # Service graph
|   +-- executor/
|   |   +-- mod.rs           # Plan executor
|   |   +-- parallel.rs      # Parallel execution
|   |   +-- health.rs        # Health check waiting
|   +-- commands/
|   |   +-- up.rs            # compose up
|   |   +-- down.rs          # compose down
|   |   +-- ps.rs            # compose ps
|   |   +-- logs.rs          # compose logs
|   |   +-- scale.rs         # compose scale
|   +-- error.rs

ferro-mind/
+-- Cargo.toml
+-- src/
|   +-- lib.rs
|   +-- inference/
|   |   +-- mod.rs           # Inference engine
|   |   +-- wasm.rs          # WASM runtime
|   |   +-- models.rs        # Model management
|   +-- predictors/
|   |   +-- mod.rs           # Prediction traits
|   |   +-- resource.rs      # Resource prediction
|   |   +-- anomaly.rs       # Anomaly detection
|   |   +-- restart.rs       # Restart decisions
|   +-- patterns/
|   |   +-- mod.rs           # Pattern storage
|   |   +-- store.rs         # ruvector integration
|   |   +-- learning.rs      # Pattern learning
|   +-- claude_flow/
|   |   +-- mod.rs           # Claude-Flow client
|   |   +-- mcp.rs           # MCP protocol
|   |   +-- subprocess.rs    # Process management
|   +-- explain/
|   |   +-- mod.rs           # Explainability
|   |   +-- decision.rs      # Decision logging
|   |   +-- format.rs        # Output formatting
|   +-- error.rs
```

### Key Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| wasmtime | 19.0 | WASM runtime |
| serde_yaml | 0.9 | YAML parsing |
| petgraph | 0.6 | Service dependency graph |
| tokio | 1.35 | Async runtime |
| uuid | 1.6 | Decision IDs |
| chrono | 0.4 | Timestamps |

## 4. Tasks

### TASK-016: Implement ferro-mind crate skeleton

**Effort:** 3 days | **Points:** 5 | **Priority:** P1 | **Depends On:** -

**Description:**
Create the AI intelligence crate with WASM runtime integration, inference engine interface, and pattern storage.

**Acceptance Criteria:**
- [ ] Cargo.toml with wasmtime dep
- [ ] WASM module loading works
- [ ] Inference trait defined
- [ ] cargo test passes

**Implementation Notes:**
```rust
// src/lib.rs
pub mod inference;
pub mod predictors;
pub mod patterns;
pub mod claude_flow;
pub mod explain;
pub mod error;

pub use inference::InferenceEngine;
pub use error::Error;

/// AI features can be completely disabled
pub struct MindConfig {
    pub enabled: bool,
    pub wasm_models_path: PathBuf,
    pub claude_flow_enabled: bool,
}
```

---

### TASK-017: Implement WASM resource prediction

**Effort:** 5 days | **Points:** 8 | **Priority:** P1 | **Depends On:** TASK-016

**Description:**
Implement WASM neural network for predicting container memory and CPU needs based on historical patterns. Sub-1ms inference.

**Acceptance Criteria:**
- [ ] Inference latency <1ms
- [ ] Prediction accuracy >80%
- [ ] No external API calls
- [ ] Offline operation verified

**Implementation Notes:**
```rust
// inference/wasm.rs
pub struct WasmInference {
    engine: wasmtime::Engine,
    module: wasmtime::Module,
    resource_predictor: wasmtime::Instance,
}

impl WasmInference {
    pub fn new(models_path: &Path) -> Result<Self> {
        let engine = wasmtime::Engine::default();
        let module = wasmtime::Module::from_file(
            &engine,
            models_path.join("resource_predictor.wasm"),
        )?;

        Ok(Self { engine, module, .. })
    }

    pub fn predict_memory(&self, features: &ResourceFeatures) -> Result<u64> {
        let mut store = wasmtime::Store::new(&self.engine, ());

        // Prepare input features
        let input = self.serialize_features(features)?;

        // Call WASM function
        let predict = self.resource_predictor
            .get_typed_func::<(i32, i32), i32>(&mut store, "predict")?;

        let result = predict.call(&mut store, (input.ptr(), input.len()))?;

        Ok(result as u64)
    }
}

// Feature vector for prediction
pub struct ResourceFeatures {
    pub container_age_hours: f32,
    pub historical_avg_memory_mb: f32,
    pub historical_peak_memory_mb: f32,
    pub historical_avg_cpu_percent: f32,
    pub process_count: f32,
    pub image_size_mb: f32,
}
```

**WASM Model (Rust compiled to WASM):**
```rust
// models/resource_predictor/src/lib.rs
#[no_mangle]
pub extern "C" fn predict(features: *const f32, len: i32) -> i32 {
    let features = unsafe { std::slice::from_raw_parts(features, len as usize) };

    // ruv-FANN neural network inference
    let output = NEURAL_NETWORK.run(features);

    output[0] as i32  // Predicted memory in MB
}
```

---

### TASK-018: Implement anomaly detection

**Effort:** 5 days | **Points:** 8 | **Priority:** P1 | **Depends On:** TASK-016, TASK-017

**Description:**
Implement real-time container anomaly detection for resource usage, network connections, and syscall patterns. Alert with severity and recommendations.

**Acceptance Criteria:**
- [ ] Anomalies detected within 5 seconds
- [ ] Severity classification accurate
- [ ] Recommendations actionable
- [ ] eBPF-based syscall monitoring

**Implementation Notes:**
```rust
// predictors/anomaly.rs
pub struct AnomalyDetector {
    baseline: ContainerBaseline,
    thresholds: AnomalyThresholds,
}

pub struct ContainerBaseline {
    avg_cpu: f32,
    avg_memory: f32,
    avg_network_rx: f32,
    avg_network_tx: f32,
    syscall_whitelist: HashSet<i32>,
}

pub struct Anomaly {
    pub severity: Severity,
    pub kind: AnomalyKind,
    pub description: String,
    pub recommendation: String,
    pub detected_at: DateTime<Utc>,
}

pub enum Severity {
    Info,
    Warning,
    Critical,
}

pub enum AnomalyKind {
    MemorySpike,
    CpuSpike,
    UnexpectedNetworkConnection,
    UnusualSyscall,
    ResourceExhaustion,
}

impl AnomalyDetector {
    pub fn check(&self, metrics: &ContainerMetrics) -> Option<Anomaly> {
        // Memory spike detection
        if metrics.memory > self.baseline.avg_memory * self.thresholds.memory_spike_ratio {
            return Some(Anomaly {
                severity: Severity::Warning,
                kind: AnomalyKind::MemorySpike,
                description: format!(
                    "Memory usage {} MB exceeds baseline {} MB",
                    metrics.memory, self.baseline.avg_memory
                ),
                recommendation: "Consider increasing memory limit or investigating memory leak".to_string(),
                detected_at: Utc::now(),
            });
        }

        // ... other checks

        None
    }
}
```

---

### TASK-019: Implement intelligent container restart

**Effort:** 4 days | **Points:** 6 | **Priority:** P1 | **Depends On:** TASK-017, TASK-018

**Description:**
Implement diagnostic analysis before container restart. Adjust configuration if pattern detected (OOM, resource exhaustion).

**Acceptance Criteria:**
- [ ] Diagnosis before restart
- [ ] Auto-adjust resource limits
- [ ] Explain restart decision
- [ ] Fall back to simple restart if diagnosis fails

**Implementation Notes:**
```rust
// predictors/restart.rs
pub struct RestartDecider {
    inference: Arc<WasmInference>,
    anomaly: Arc<AnomalyDetector>,
}

pub struct RestartDecision {
    pub should_restart: bool,
    pub diagnosis: Option<Diagnosis>,
    pub adjusted_config: Option<ContainerConfig>,
    pub explanation: String,
}

pub struct Diagnosis {
    pub root_cause: RootCause,
    pub confidence: f32,
    pub evidence: Vec<String>,
}

pub enum RootCause {
    OomKilled,
    CpuStarvation,
    IoWait,
    ApplicationCrash,
    NetworkFailure,
    Unknown,
}

impl RestartDecider {
    pub async fn analyze_and_decide(
        &self,
        container: &Container,
        exit_status: &ExitStatus,
    ) -> Result<RestartDecision> {
        // Collect diagnostic data
        let metrics = container.get_historical_metrics()?;
        let last_logs = container.get_logs(Duration::from_secs(60)).await?;
        let anomalies = self.anomaly.detect_recent(&container.id)?;

        // Analyze exit status
        let diagnosis = match exit_status {
            ExitStatus::OomKilled => Some(Diagnosis {
                root_cause: RootCause::OomKilled,
                confidence: 0.95,
                evidence: vec!["Exit status indicates OOM kill".to_string()],
            }),
            ExitStatus::ExitCode(137) => {
                // SIGKILL - could be OOM or manual kill
                if metrics.peak_memory > metrics.limit * 0.9 {
                    Some(Diagnosis {
                        root_cause: RootCause::OomKilled,
                        confidence: 0.8,
                        evidence: vec![
                            "Exit code 137 (SIGKILL)".to_string(),
                            format!("Memory near limit: {} / {}", metrics.peak_memory, metrics.limit),
                        ],
                    })
                } else {
                    None
                }
            }
            _ => None,
        };

        // Determine if should adjust config
        let adjusted_config = if let Some(ref diag) = diagnosis {
            match diag.root_cause {
                RootCause::OomKilled => {
                    let predicted = self.inference.predict_memory(&metrics.to_features())?;
                    let new_limit = (predicted as f64 * 1.5) as u64; // 50% headroom

                    Some(ContainerConfig {
                        memory_limit: new_limit,
                        ..container.config.clone()
                    })
                }
                _ => None,
            }
        } else {
            None
        };

        let explanation = self.format_explanation(&diagnosis, &adjusted_config);

        Ok(RestartDecision {
            should_restart: true,
            diagnosis,
            adjusted_config,
            explanation,
        })
    }
}
```

---

### TASK-020: Implement claude-flow integration

**Effort:** 4 days | **Points:** 6 | **Priority:** P2 | **Depends On:** TASK-016

**Description:**
Integrate claude-flow via MCP subprocess for complex multi-agent diagnostics and natural language queries. Lazy load Node.js.

**Acceptance Criteria:**
- [ ] Node.js spawned on demand only
- [ ] MCP protocol over stdio works
- [ ] Natural language queries answered
- [ ] Graceful degradation without Node.js

**Implementation Notes:**
```rust
// claude_flow/subprocess.rs
pub struct ClaudeFlowProcess {
    process: Option<Child>,
    stdin: BufWriter<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    pending_requests: HashMap<Uuid, oneshot::Sender<Result<Value>>>,
}

impl ClaudeFlowProcess {
    pub async fn spawn_if_needed(&mut self) -> Result<()> {
        if self.process.is_none() {
            // Check Node.js availability
            which::which("node").map_err(|_| Error::NodeJsNotFound)?;

            // Lazy spawn
            self.process = Some(
                Command::new("node")
                    .arg(&self.claude_flow_path)
                    .arg("mcp-server")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .spawn()?,
            );

            // Initialize connection
            self.initialize().await?;
        }
        Ok(())
    }

    pub async fn invoke(&mut self, method: &str, params: Value) -> Result<Value> {
        self.spawn_if_needed().await?;

        let request_id = Uuid::new_v4();
        let request = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": request_id.to_string()
        });

        // Write request
        self.stdin.write_all(&serde_json::to_vec(&request)?)?;
        self.stdin.write_all(b"\n")?;
        self.stdin.flush()?;

        // Read response
        let response = self.read_response().await?;
        Ok(response)
    }

    pub async fn diagnose(&mut self, query: &str, context: &ContainerContext) -> Result<DiagnosisResult> {
        let response = self.invoke("diagnose", json!({
            "query": query,
            "container": context,
        })).await?;

        Ok(serde_json::from_value(response)?)
    }
}
```

**Natural Language Query:**
```rust
// Commands
pub async fn handle_ask_command(
    query: &str,
    container_id: Option<&str>,
) -> Result<()> {
    let mut claude_flow = ClaudeFlowProcess::new()?;

    let context = if let Some(id) = container_id {
        Some(get_container_context(id).await?)
    } else {
        None
    };

    let result = claude_flow.diagnose(query, &context).await?;

    println!("{}", result.explanation);

    if !result.recommendations.is_empty() {
        println!("\nRecommendations:");
        for rec in &result.recommendations {
            println!("  - {}", rec);
        }
    }

    Ok(())
}
```

---

### TASK-021: Implement ferro-compose crate

**Effort:** 6 days | **Points:** 10 | **Priority:** P0 | **Depends On:** TASK-006, TASK-011, TASK-014

**Description:**
Implement docker-compose.yml v3.x parser and executor. Support service dependencies, environment files, profiles, and scaling.

**Acceptance Criteria:**
- [ ] Parse docker-compose.yml v3.x
- [ ] depends_on with condition support
- [ ] Environment file substitution
- [ ] ferrocrate compose up/down works

**Implementation Notes:**
```rust
// parser/v3.rs
#[derive(Deserialize)]
pub struct ComposeFile {
    pub version: String,
    pub services: HashMap<String, Service>,
    pub networks: Option<HashMap<String, Network>>,
    pub volumes: Option<HashMap<String, Volume>>,
    pub configs: Option<HashMap<String, Config>>,
    pub secrets: Option<HashMap<String, Secret>>,
}

#[derive(Deserialize)]
pub struct Service {
    pub image: Option<String>,
    pub build: Option<Build>,
    pub command: Option<Command>,
    pub entrypoint: Option<String>,
    pub environment: Option<Environment>,
    pub env_file: Option<Vec<String>>,
    pub ports: Option<Vec<String>>,
    pub volumes: Option<Vec<String>>,
    pub networks: Option<Vec<String>>,
    pub depends_on: Option<DependsOn>,
    pub restart: Option<String>,
    pub healthcheck: Option<HealthCheck>,
    pub deploy: Option<Deploy>,
    pub labels: Option<HashMap<String, String>>,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum DependsOn {
    Simple(Vec<String>),
    Conditional(HashMap<String, DependsCondition>),
}

#[derive(Deserialize)]
pub struct DependsCondition {
    pub condition: String,  // "service_started", "service_healthy", "service_completed_successfully"
}

impl ComposeFile {
    pub fn parse(content: &str, env: &HashMap<String, String>) -> Result<Self> {
        // Variable interpolation
        let interpolated = interpolate_variables(content, env)?;

        // Parse YAML
        let compose: ComposeFile = serde_yaml::from_str(&interpolated)?;

        // Validate
        compose.validate()?;

        Ok(compose)
    }
}
```

**Service Graph:**
```rust
// planner/graph.rs
pub struct ServiceGraph {
    graph: petgraph::Graph<String, ()>,
    node_indices: HashMap<String, petgraph::NodeIndex>,
}

impl ServiceGraph {
    pub fn from_compose(compose: &ComposeFile) -> Result<Self> {
        let mut graph = Self::new();

        // Add all services
        for name in compose.services.keys() {
            graph.add_service(name);
        }

        // Add dependencies
        for (name, service) in &compose.services {
            if let Some(deps) = &service.depends_on {
                for dep in deps.iter() {
                    graph.add_dependency(name, dep)?;
                }
            }
        }

        // Detect cycles
        if graph.has_cycle() {
            return Err(Error::CyclicDependency);
        }

        Ok(graph)
    }

    pub fn start_order(&self) -> Vec<Vec<String>> {
        // Topological sort with parallel grouping
        petgraph::algo::toposort(&self.graph, None)
            .unwrap()
            .into_iter()
            .map(|idx| self.graph[idx].clone())
            .collect()
    }
}
```

**Compose Up:**
```rust
// commands/up.rs
pub async fn compose_up(
    compose: &ComposeFile,
    options: UpOptions,
) -> Result<()> {
    let graph = ServiceGraph::from_compose(compose)?;
    let start_order = graph.start_order();

    for batch in start_order {
        let mut tasks = Vec::new();

        for service_name in batch {
            let service = &compose.services[&service_name];

            tasks.push(tokio::spawn(async move {
                // Pull/build image
                let image = ensure_image(&service).await?;

                // Create container
                let container = create_container(&service_name, service, &image).await?;

                // Start container
                container.start().await?;

                // Wait for health check if needed
                if let Some(deps) = &service.depends_on {
                    for dep in deps {
                        wait_for_condition(&dep).await?;
                    }
                }

                Ok::<_, Error>(container)
            }));
        }

        // Wait for batch to complete
        let results = futures::future::join_all(tasks).await;
        for result in results {
            result??;  // Propagate errors
        }
    }

    Ok(())
}
```

---

### TASK-022: Implement Docker migration tool

**Effort:** 4 days | **Points:** 6 | **Priority:** P1 | **Depends On:** TASK-015

**Description:**
Implement ferrocrate migrate command to scan Docker installation, analyze containers/images, and generate FerroCrate configuration.

**Acceptance Criteria:**
- [ ] Scan Docker containers and images
- [ ] Generate ferrocrate-equivalent config
- [ ] Validate migration plan
- [ ] Migration report with warnings

**Implementation Notes:**
```rust
// commands/migrate.rs
pub struct MigrationReport {
    pub containers: Vec<ContainerMigration>,
    pub images: Vec<ImageMigration>,
    pub networks: Vec<NetworkMigration>,
    pub volumes: Vec<VolumeMigration>,
    pub warnings: Vec<MigrationWarning>,
    pub unsupported_features: Vec<String>,
}

pub struct ContainerMigration {
    pub docker_name: String,
    pub ferrocrate_config: ContainerConfig,
    pub warnings: Vec<String>,
}

pub async fn migrate_docker(docker_host: Option<&str>) -> Result<MigrationReport> {
    // Connect to Docker
    let docker = DockerClient::new(docker_host)?;

    // Scan containers
    let containers = docker.list_containers().await?;
    let container_migrations: Vec<_> = containers
        .iter()
        .map(|c| migrate_container(c))
        .collect();

    // Scan images
    let images = docker.list_images().await?;
    let image_migrations: Vec<_> = images
        .iter()
        .map(|i| migrate_image(i))
        .collect();

    // Scan networks
    let networks = docker.list_networks().await?;
    // ...

    // Scan volumes
    let volumes = docker.list_volumes().await?;
    // ...

    // Check for unsupported features
    let unsupported = check_unsupported_features(&container_migrations);

    Ok(MigrationReport {
        containers: container_migrations,
        images: image_migrations,
        networks,
        volumes,
        warnings: collect_warnings(&container_migrations),
        unsupported_features: unsupported,
    })
}

fn migrate_container(docker: &DockerContainer) -> ContainerMigration {
    let mut warnings = Vec::new();

    // Check for unsupported features
    if docker.host_config.privileged {
        warnings.push("Privileged mode may have different behavior".to_string());
    }

    // Translate config
    let config = ContainerConfig {
        image: docker.config.image.clone(),
        command: docker.config.cmd.clone(),
        environment: docker.config.env.clone(),
        ports: translate_ports(&docker.host_config.port_bindings),
        volumes: translate_volumes(&docker.host_config.binds),
        // ...
    };

    ContainerMigration {
        docker_name: docker.names[0].clone(),
        ferrocrate_config: config,
        warnings,
    }
}
```

**CLI Usage:**
```bash
# Scan and report
ferrocrate migrate --dry-run

# Generate migration scripts
ferrocrate migrate --output ./migration/

# Execute migration
ferrocrate migrate --execute
```

---

## 5. Quality Gate

### Step 1: Code Complete
- [ ] All 7 tasks complete
- [ ] No TODOs
- [ ] Clippy clean
- [ ] rustfmt applied

### Step 2: Unit Tests
- [ ] >80% coverage
- [ ] WASM model tests
- [ ] Compose parser tests
- [ ] Migration tests

### Step 3: Integration Tests
- [ ] docker-compose up works
- [ ] AI features functional
- [ ] Migration tool tested

### Step 4: Performance Tests
- [ ] WASM inference <1ms
- [ ] Compose up time
- [ ] AI overhead measurement

### Step 5: Security Audit
- [ ] MCP protocol secure
- [ ] No credential exposure
- [ ] AI decision logging

### Step 6: Documentation
- [ ] AI feature documentation
- [ ] Compose compatibility matrix
- [ ] Migration guide

### Step 7: Review Sign-off
- [ ] All reviews complete
- [ ] Beta tester sign-off

---

## 6. Dependencies

### Internal Dependencies
- All previous milestones

### External Dependencies
- Node.js 18+ (optional, for advanced AI)
- claude-flow npm package

---

## 7. Risks and Mitigations

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| WASM model accuracy | Medium | Medium | Continuous training, fallback |
| Compose edge cases | High | Medium | Document unsupported features |
| Node.js dependency | Low | Low | Graceful degradation |
| Claude API costs | Medium | Low | WASM-first, API-last routing |

---

## 8. Exit Criteria

Before v1.0 release, demonstrate:

```bash
# Compose workflow
cat > docker-compose.yml << 'EOF'
version: '3.8'
services:
  web:
    image: nginx
    ports:
      - "8080:80"
    depends_on:
      db:
        condition: service_healthy
  db:
    image: postgres:15
    environment:
      POSTGRES_PASSWORD: secret
    healthcheck:
      test: ["CMD", "pg_isready"]
      interval: 5s
      timeout: 5s
      retries: 5
EOF

ferrocrate compose up -d
ferrocrate compose ps
curl localhost:8080
ferrocrate compose down

# AI features
ferrocrate ask "why is my container using so much memory?"
ferrocrate predict --memory web
ferrocrate explain <decision-id>

# Migration
ferrocrate migrate --dry-run
# ... review migration report
```

---

*Milestone Owner: TBD | Last Updated: 2026-02-11*
