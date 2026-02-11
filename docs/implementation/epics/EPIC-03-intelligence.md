# EPIC-03: Intelligence

**Phase:** Phase 5 (Weeks 25-32) | **Tasks:** 5 | **Story Points:** 33

---

## 1. Overview

This epic delivers the AI-native capabilities of FerroCrate, including predictive resource allocation, anomaly detection, intelligent restart decisions, and natural language container management.

### User Stories Covered
- US-3.1: Predict container memory needs based on patterns
- US-3.2: Natural language queries about container issues
- US-3.3: Automatic resource limit adjustment
- US-3.4: Anomalous container behavior detection
- US-3.5: Disable all AI features with single flag

### PRD Requirements Covered
- AI-01 through AI-12 (Intelligence Layer)
- PERF-08 (AI inference latency)

---

## 2. Intelligence Architecture

### Three-Tier Inference System

```
+------------------------------------------------------------------+
|                    FerroCrate Intelligence                        |
|                                                                   |
|  +-----------------+  +-----------------+  +-----------------+    |
|  |     Tier 1      |  |     Tier 2      |  |     Tier 3      |    |
|  |     WASM        |  |   Local LLM     |  |   Cloud API     |    |
|  |   <1ms, Free    |  | 100-500ms, $$   |  | 500-2000ms, $$$ |    |
|  +-----------------+  +-----------------+  +-----------------+    |
|                                                                   |
|  +------------------------------------------------------------+  |
|  |                    Inference Router                         |  |
|  |  - Complexity analysis                                      |  |
|  |  - Cost optimization                                        |  |
|  |  - Fallback handling                                        |  |
|  +------------------------------------------------------------+  |
+------------------------------------------------------------------+
```

### Tier Capabilities

| Tier | Technology | Latency | Cost | Use Cases |
|------|------------|---------|------|-----------|
| 1 | WASM (ruv-FANN) | <1ms | Free | Resource prediction, anomaly scoring, restart decisions |
| 2 | Local LLM (Ollama) | 100-500ms | Hardware | Log analysis, error explanation, simple diagnostics |
| 3 | Cloud API (Claude) | 500-2000ms | Per-request | Complex debugging, multi-agent orchestration, NLP queries |

---

## 3. Components

### ferro-mind Crate Structure

```
ferro-mind/
+-- src/
|   +-- inference/
|   |   +-- mod.rs           # Inference engine abstraction
|   |   +-- wasm.rs          # WASM runtime (Wasmtime)
|   |   +-- local_llm.rs     # Ollama integration
|   |   +-- cloud.rs         # Claude API client
|   +-- predictors/
|   |   +-- resource.rs      # Memory/CPU prediction
|   |   +-- anomaly.rs       # Anomaly detection
|   |   +-- restart.rs       # Intelligent restart
|   +-- router/
|   |   +-- mod.rs           # Request routing
|   |   +-- complexity.rs    # Complexity analysis
|   |   +-- cost.rs          # Cost optimization
|   +-- claude_flow/
|   |   +-- mod.rs           # Claude-Flow client
|   |   +-- mcp.rs           # MCP protocol
|   +-- explain/
|   |   +-- mod.rs           # Explainability
|   |   +-- decision_log.rs  # Decision logging
```

---

## 4. Tasks

| ID | Title | Points | Depends On | Status |
|----|-------|--------|------------|--------|
| TASK-016 | Implement ferro-mind crate skeleton | 5 | - | Not Started |
| TASK-017 | Implement WASM resource prediction | 8 | TASK-016 | Not Started |
| TASK-018 | Implement anomaly detection | 8 | TASK-016, TASK-017 | Not Started |
| TASK-019 | Implement intelligent container restart | 6 | TASK-017, TASK-018 | Not Started |
| TASK-020 | Implement claude-flow integration | 6 | TASK-016 | Not Started |

**Total Story Points:** 33

---

## 5. Key Interfaces

### Inference Engine

```rust
/// Generic inference engine trait
pub trait InferenceEngine: Send + Sync {
    /// Predict resource requirements
    fn predict_resources(&self, features: &ResourceFeatures) -> Result<ResourcePrediction>;

    /// Detect anomalies
    fn detect_anomaly(&self, metrics: &ContainerMetrics) -> Result<Option<Anomaly>>;

    /// Analyze restart decision
    fn analyze_restart(&self, context: &RestartContext) -> Result<RestartDecision>;

    /// Get inference latency (for routing)
    fn expected_latency(&self) -> Duration;

    /// Get cost tier
    fn cost_tier(&self) -> CostTier;
}

pub enum CostTier {
    Free,       // WASM
    Low,        // Local LLM
    High,       // Cloud API
}
```

### Resource Prediction

```rust
/// Input features for resource prediction
pub struct ResourceFeatures {
    pub container_age_hours: f32,
    pub historical_avg_memory_mb: f32,
    pub historical_peak_memory_mb: f32,
    pub historical_avg_cpu_percent: f32,
    pub process_count: f32,
    pub image_size_mb: f32,
    pub network_connections: f32,
    pub disk_io_rate: f32,
}

/// Predicted resource requirements
pub struct ResourcePrediction {
    pub recommended_memory_mb: u64,
    pub recommended_cpu_percent: f32,
    pub confidence: f32,
    pub model_version: String,
}
```

### Anomaly Detection

```rust
/// Anomaly types
pub enum AnomalyKind {
    MemorySpike,
    CpuSpike,
    UnexpectedNetworkConnection,
    UnusualSyscall,
    ResourceExhaustion,
    ProcessCountAnomaly,
}

/// Detected anomaly
pub struct Anomaly {
    pub severity: Severity,
    pub kind: AnomalyKind,
    pub description: String,
    pub recommendation: String,
    pub detected_at: DateTime<Utc>,
    pub confidence: f32,
}

pub enum Severity {
    Info,
    Warning,
    Critical,
}
```

### Restart Decision

```rust
/// Root cause analysis
pub enum RootCause {
    OomKilled,
    CpuStarvation,
    IoWait,
    ApplicationCrash,
    NetworkFailure,
    DependencyFailure,
    Unknown,
}

/// Intelligent restart decision
pub struct RestartDecision {
    pub should_restart: bool,
    pub diagnosis: Option<Diagnosis>,
    pub adjusted_config: Option<ContainerConfig>,
    pub explanation: String,
    pub decision_id: Uuid,
}

pub struct Diagnosis {
    pub root_cause: RootCause,
    pub confidence: f32,
    pub evidence: Vec<String>,
    pub similar_incidents: u32,
}
```

---

## 6. WASM Models

### Resource Predictor Model

```rust
// models/resource_predictor/src/lib.rs

/// Neural network for resource prediction
/// Input: 8 features (normalized)
/// Output: 2 values (memory_mb, cpu_percent)
#[no_mangle]
pub extern "C" fn predict_resource(features: *const f32, len: i32) -> i64 {
    let features = unsafe { std::slice::from_raw_parts(features, len as usize) };

    // ruv-FANN neural network
    let output = RESOURCE_PREDICTOR.run(features);

    // Pack outputs: memory (high 32 bits), cpu (low 32 bits)
    let memory_mb = output[0] as i32;
    let cpu_percent = output[1] as i32;

    ((memory_mb as i64) << 32) | (cpu_percent as i64 & 0xFFFFFFFF)
}
```

### Anomaly Detector Model

```rust
// models/anomaly_detector/src/lib.rs

/// Anomaly score (0-1)
#[no_mangle]
pub extern "C" fn anomaly_score(metrics: *const f32, len: i32) -> f32 {
    let metrics = unsafe { std::slice::from_raw_parts(metrics, len as usize) };

    ANOMALY_DETECTOR.run(metrics)[0]
}

/// Anomaly classification
#[no_mangle]
pub extern "C" fn classify_anomaly(features: *const f32, len: i32) -> i32 {
    let features = unsafe { std::slice::from_raw_parts(features, len as usize) };

    let output = ANOMALY_CLASSIFIER.run(features);

    // Return index of highest output
    output.iter()
        .enumerate()
        .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap())
        .map(|(i, _)| i as i32)
        .unwrap_or(-1)
}
```

---

## 7. Claude-Flow Integration

### MCP Protocol

```rust
// claude_flow/mcp.rs
pub struct McpClient {
    process: Option<Child>,
    stdin: BufWriter<ChildStdin>,
    stdout: BufReader<ChildStdout>,
}

impl McpClient {
    /// Invoke Claude-Flow tool
    pub async fn invoke(&mut self, tool: &str, params: Value) -> Result<Value> {
        let request = json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": tool,
                "arguments": params
            },
            "id": Uuid::new_v4().to_string()
        });

        self.send(&request).await?;
        let response = self.recv().await?;

        Ok(response["result"].clone())
    }

    /// Diagnose container issue
    pub async fn diagnose(
        &mut self,
        query: &str,
        context: &ContainerContext,
    ) -> Result<DiagnosisResult> {
        let result = self.invoke("diagnose", json!({
            "query": query,
            "container_id": context.id,
            "logs": context.recent_logs,
            "metrics": context.metrics,
        })).await?;

        Ok(serde_json::from_value(result)?)
    }
}
```

### Natural Language Query

```bash
# Ask about container issues
ferrocrate ask "why did my web server crash?"

# Ask about resource usage
ferrocrate ask "why is database using so much memory?"

# Ask for recommendations
ferrocrate ask "how can I optimize my container performance?"
```

---

## 8. Explainability

### Decision Logging

```rust
// explain/decision_log.rs
pub struct DecisionLog {
    db: sled::Db,
}

pub struct Decision {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub kind: DecisionKind,
    pub input: Value,
    pub output: Value,
    pub reasoning: String,
    pub model_tier: CostTier,
    pub latency_ms: u64,
}

impl DecisionLog {
    pub fn log(&self, decision: Decision) -> Result<()> {
        self.db.insert(
            decision.id.as_bytes(),
            serde_json::to_vec(&decision)?,
        )?;
        Ok(())
    }

    pub fn get(&self, id: &Uuid) -> Result<Option<Decision>> {
        let bytes = self.db.get(id.as_bytes())?;
        match bytes {
            Some(b) => Ok(Some(serde_json::from_slice(&b)?)),
            None => Ok(None),
        }
    }
}
```

### Explanation Command

```bash
$ ferrocrate explain 550e8400-e29b-41d4-a716-446655440000

Decision: Restart container 'web-server'
Timestamp: 2026-02-11 14:32:15 UTC
Model Tier: WASM (Tier 1)
Latency: 0.8ms

Root Cause: OOM Killed (95% confidence)

Evidence:
  - Exit code: 137 (SIGKILL)
  - Peak memory: 490MB / 500MB limit
  - Memory usage trend: increasing over 2 hours
  - Similar incidents: 3 in past week

Action Taken:
  - Container restarted
  - Memory limit increased from 500MB to 750MB
  - Reason: Predicted need 650MB based on growth trend

Recommendation:
  - Monitor for further memory growth
  - Consider implementing memory limits in application
  - Review for potential memory leak
```

---

## 9. AI Opt-Out

```rust
// Configuration
pub struct MindConfig {
    /// Completely disable all AI features
    pub enabled: bool,
}

// When disabled, runtime operates as pure static runtime
impl Mind {
    pub fn new(config: MindConfig) -> Self {
        if !config.enabled {
            return Self::disabled();
        }
        // ... initialize AI components
    }

    fn disabled() -> Self {
        Self {
            inference: None,
            anomaly_detector: None,
            claude_flow: None,
        }
    }
}

// All AI methods return None or defaults when disabled
impl Mind {
    pub fn predict_resources(&self, features: &ResourceFeatures) -> Option<ResourcePrediction> {
        self.inference.as_ref()?.predict_resources(features).ok()
    }
}
```

---

## 10. Acceptance Criteria

This epic is complete when:

1. **WASM Inference**
   - [ ] Inference latency <1ms
   - [ ] Resource prediction accuracy >80%
   - [ ] Anomaly detection F1 >0.85

2. **Integration**
   - [ ] Claude-Flow MCP works
   - [ ] Natural language queries answered
   - [ ] Lazy Node.js loading

3. **Explainability**
   - [ ] All decisions logged
   - [ ] `ferrocrate explain` works
   - [ ] Clear reasoning provided

4. **Opt-Out**
   - [ ] Single flag disables all AI
   - [ ] Runtime works identically without AI
   - [ ] No AI dependencies loaded when disabled

---

*Epic Owner: TBD | Last Updated: 2026-02-11*
