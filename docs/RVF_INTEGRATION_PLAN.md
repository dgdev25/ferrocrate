# RVF Integration & FerroCrate Improvement Plan

**Status:** Active
**Version:** 2.0 (supersedes draft v1.0 from 2026-02-14)
**Date:** 2026-02-17
**Scope:** Comprehensive — covers RVF integration, runtime disconnection fix, refactoring, and strategic architecture

---

## Critical Upfront Assessment

The existing draft plan (v1.0) was too narrow. It focused only on persistence and missed four more important problems. Fix these in order:

1. **ferro-mind is architecturally disconnected from ferro-core** — AnomalyDetector and AdaptiveRestartPolicy exist but are never called. ResourcePredictor is only partially wired (runtime.rs:3010–3046). The AI stack learns nothing from live containers.
2. **rvf-runtime is version-pinned to 0.1; the published version is 0.2.0** — API surface has changed; existing optional wrappers may be using a stale interface.
3. **rvf-crypto, rvf-quant, and rvf-index are not used** — ferro-core rolls its own crypto (ed25519-dalek + blake3) when rvf-crypto provides a superset. Models can't be quantized. Index configuration can't be tuned.
4. **Training data is never collected from running containers** — models can't improve without a data collection pipeline wired into the container lifecycle.

Everything else in this document is predicated on fixing these four issues first.

---

## Table of Contents

1. [Current State: Honest Audit](#1-current-state-honest-audit)
2. [Phase 0: Fix the Runtime Disconnection](#2-phase-0-fix-the-runtime-disconnection)
3. [Phase 1: RVF Upgrade and Consolidation](#3-phase-1-rvf-upgrade-and-consolidation)
4. [Phase 2: ferro-core Crypto Replacement](#4-phase-2-ferro-core-crypto-replacement)
5. [Phase 3: Quantization and Model Compression](#5-phase-3-quantization-and-model-compression)
6. [Phase 4: Training Data Collection Pipeline](#6-phase-4-training-data-collection-pipeline)
7. [Phase 5: Online Learning Scheduler](#7-phase-5-online-learning-scheduler)
8. [Phase 6: Code Refactoring and Waste Removal](#8-phase-6-code-refactoring-and-waste-removal)
9. [Phase 7: Strategic — RVF as Native Image Format](#9-phase-7-strategic--rvf-as-native-image-format)
10. [Phase 8: AGI Cognitive Container Primitive](#10-phase-8-agi-cognitive-container-primitive)
11. [Testing Gaps](#11-testing-gaps)
12. [Dependency Cleanup](#12-dependency-cleanup)
13. [Prioritised Execution Order](#13-prioritised-execution-order)
14. [Risk Register](#14-risk-register)

---

## 1. Current State: Honest Audit

### ferro-mind AI modules — what's wired vs. what's not

| Module | Implemented | Wired into ferro-core | Data flows in | Notes |
|---|---|---|---|---|
| `resource.rs` — OOM prediction | ✅ | ⚠️ Partial | ⚠️ Partial | runtime.rs:3010–3046: ResourcePredictor created, cgroup metrics read, OOM prediction called. Missing: outcomes never recorded back, no persistence. |
| `anomaly.rs` — Anomaly detection | ✅ | ❌ Never called | ❌ | NeuralAnomalyDetector exists and trains, but there is no call site in runtime.rs or any other ferro-core module. |
| `restart.rs` — Adaptive restart | ✅ | ❌ Never called | ❌ | AdaptiveRestartPolicy exists but ferro-core uses a plain `RestartPolicy` enum (No/OnFailure/Always/UnlessStopped). The learning layer is completely bypassed. |
| `training.rs` — Training pipeline | ⚠️ Scaffold | ❌ | ❌ | 1,507 lines of framework; no call sites for data export, no loader that reads cgroup history. |
| `agents.rs` — Claude-Flow hooks | ✅ | ❌ | ❌ | Spawns claude-flow CLI. No trigger points in runtime. |
| `vector_memory.rs` — HNSW store | ✅ | ⚠️ Via resource.rs | ⚠️ | Used inside ResourcePredictor, but the ResourcePredictor instance in runtime.rs is local to the OOM monitor function — it doesn't persist or learn across container restarts. |

### RVF version drift

| Crate | Used in ferro-mind | Published (crates.io) | Gap |
|---|---|---|---|
| rvf-runtime | 0.1 (optional) | 0.2.0 | Minor version behind |
| rvf-types | 0.1 (optional) | 0.2.0 | Minor version behind |
| rvf-crypto | Not used | 0.2.0 | Entire crate missing |
| rvf-quant | Not used | 0.1.0 | Entire crate missing |
| rvf-index | Not used | 0.1.0 | Entire crate missing |
| rvf-wire | Not used | 0.1.0 | Entire crate missing |

### Thin wrapper files adding no value

| File | Lines | What it does | Problem |
|---|---|---|---|
| `ferro-mind/src/ai/learning/rvf_store.rs` | 190 | Wraps rvf-runtime RvfStore | Thin shim; adds error mapping but no logic. Direct usage of rvf-runtime is simpler. |
| `ferro-mind/src/ruv/rvf_cache.rs` | 103 | Wraps rvf-runtime for dedup cache | Same issue. The abstraction layer adds nothing. |

### Dead or unimplemented stubs

| File | Lines | Status | Decision needed |
|---|---|---|---|
| `ferro-mind/src/ai/gpu.rs` | 160 | Detection stubs only, no inference path | Delete or implement. Stubs rot. |
| `ferro-mind/src/wasm.rs` | 274 | Trait abstraction with LinearWasmEngine; zero external WASM loaded | Delete or implement. NoopEngine confirms it's a placeholder. |
| `ferro-mind/src/ai/explain.rs` | 23 | DecisionTrace stub | Implement alongside anomaly wiring, or delete. |

---

## 2. Phase 0: Fix the Runtime Disconnection

**Priority: Highest. Nothing else matters until the AI stack is actually called.**

### 2.1 Wire AnomalyDetector into the container metrics loop

In `ferro-core/src/runtime.rs`, the OOM monitor loop at ~line 3033 already reads cgroup metrics. Add anomaly detection to the same loop.

```rust
// runtime.rs — extend the existing metrics loop
let mut predictor = ferro_mind::ai::resource::ResourcePredictor::new(60)
    .with_memory_limit(memory_limit);
let mut anomaly = ferro_mind::ai::anomaly::NeuralAnomalyDetector::new(5);
let ai_logger = ferro_mind::ai::audit::AuditLogger::from_env();

loop {
    if let Ok(metrics) = ferro_mind::ai::resource::read_cgroup_metrics(&cgroup_path) {
        let sample = ferro_mind::ai::resource::ResourceSample { /* existing */ };
        predictor.add_sample(sample.clone());

        // NEW: anomaly detection
        let features = [
            sample.cpu_percent,
            sample.memory_bytes as f32 / memory_limit as f32,
            // io_read, io_write, net — add when cgroup metrics expose them
            0.0, 0.0, 0.0,
        ];
        if anomaly.is_trained() {
            if let Some(score) = anomaly.detect(&features) {
                if score > 0.8 {
                    ai_logger.log_anomaly(&container_id, score);
                    // emit metric / log event — do NOT kill the container here
                }
            }
        }

        // OOM prediction — existing, but record it
        if let Some(prediction) = predictor.predict_oom(oom_horizon) {
            ai_logger.log_oom_prediction(&container_id, &prediction);
        }
    }
    tokio::time::sleep(sample_interval).await;
}
```

**Verification:** Run a container with a memory leak. Confirm anomaly scores increase and are logged before OOM.

### 2.2 Wire AdaptiveRestartPolicy into the restart supervisor

`ferro-core/src/runtime.rs` has a `should_restart()` function (~line 1327) that takes a plain `RestartPolicy` enum. This needs to consult `ferro-mind::ai::restart::AdaptiveRestartPolicy` and record outcomes.

```rust
// Current (plain enum):
if !should_restart(&restart_policy, &current_status, exit_code) {
    break;
}

// Target: consult adaptive policy AND record outcome
let mut adaptive = ferro_mind::ai::restart::AdaptiveRestartPolicy::load_or_new(&container_id);
let signal = ferro_mind::ai::restart::RestartSignal {
    recent_failures: restart_count,
    last_exit_code: exit_code,
    uptime_before_crash: uptime,
};
match adaptive.decide(signal) {
    RestartDecision::RestartAfterDelay { delay_secs } => {
        tokio::time::sleep(Duration::from_secs(delay_secs)).await;
        // restart...
        adaptive.record_outcome(RestartOutcome::Restarted);
        adaptive.persist(&container_id); // write to .rvf
    }
    RestartDecision::DoNotRestart => {
        adaptive.record_outcome(RestartOutcome::Abandoned);
        adaptive.persist(&container_id);
        break;
    }
}
```

**Verification:** Run a container that crashes repeatedly with different patterns. Confirm backoff adjusts based on learned history.

### 2.3 Make ResourcePredictor persistent across invocations

Currently the ResourcePredictor in runtime.rs is created fresh each time the OOM monitor function runs. It learns nothing across restarts. Fix:

- Give each container a persistent `.rvf` file at `$FERROCRATE_DATA_DIR/ai/containers/{id}/resource.rvf`
- Load on monitor start; flush on container stop
- Record OOM outcomes (did prediction trigger? was it correct?)

---

## 3. Phase 1: RVF Upgrade and Consolidation

### 3.1 Version bump — ferro-mind/Cargo.toml

```toml
[dependencies]
# RVF ecosystem — upgrade from 0.1 and add missing crates
rvf-runtime = { version = "0.2", default-features = false }
rvf-types   = { version = "0.2" }
rvf-quant   = { version = "0.1" }   # NEW: model quantization
rvf-index   = { version = "0.1" }   # NEW: HNSW tuning

[features]
default = ["rvf-persistence"]        # Make RVF the default, not legacy
rvf-persistence = ["dep:rvf-runtime", "dep:rvf-types", "dep:rvf-quant", "dep:rvf-index"]
legacy-memory = []                   # Keep as escape hatch, not default
```

**Why remove `optional = true`:** The existing code already has an RVF persistence path. Making it non-optional is an assertion that we're committed to the design. Having it optional creates a second code path that's untested in CI (since default features don't enable it) and rots silently.

### 3.2 Eliminate the thin wrappers

`rvf_store.rs` (190 lines) wraps `rvf-runtime::RvfStore` with error mapping that adds no domain logic. `rvf_cache.rs` (103 lines) wraps the same for dedup. Both should be deleted. Call rvf-runtime directly from `vector_memory.rs` and `dedup.rs`.

Before: `vector_memory.rs → rvf_store.rs → rvf-runtime`
After: `vector_memory.rs → rvf-runtime`

The 293 lines saved reduce indirection and eliminate a class of bugs where the wrapper silently swallows errors.

### 3.3 Consolidate the three HNSW indexes in VectorMemory

`vector_memory.rs` maintains three separate HNSW indexes: `db_cosine`, `db_euclidean`, `db_manhattan`. This triples memory usage and index build time for no measurable benefit — the AI subsystem uses Cosine almost exclusively. For the cases where Euclidean is needed (OOM feature space), the raw cgroup numbers are already dimensionally consistent.

```rust
// Current: three indexes
pub struct VectorMemory {
    db_cosine:    Arc<RwLock<Option<VectorDB>>>,
    db_euclidean: Arc<RwLock<Option<VectorDB>>>,
    db_manhattan: Arc<RwLock<Option<VectorDB>>>,
    entries:      Vec<VectorEntry>,
    rvf:          Option<RvfStore>,
    // ...
}

// Target: one RVF-backed store, metric is a query-time parameter
pub struct VectorMemory {
    store: rvf_runtime::RvfStore,
}
// DistanceMetric::Cosine is the default; Euclidean falls back to brute-force
// over the 1k-entry window which is fast enough for the anomaly detector's window size
```

---

## 4. Phase 2: ferro-core Crypto Replacement

### 4.1 Problem

`ferro-core/Cargo.toml` manually manages:
- `ed25519-dalek 2.1` — image layer signing
- `blake3 1.5` — content-addressable hashing
- `sha2 0.10` — OCI spec digest (SHA-256 required by spec, keep this)

`rvf-crypto 0.2.0` provides:
- SHAKE-256 witness chains — tamper-evident, append-only audit log
- Ed25519 — same signing as ed25519-dalek but with TEE attestation integration
- ML-DSA-65 (FIPS 204) — post-quantum signing for image manifests
- SLH-DSA-128s — post-quantum alternative

### 4.2 What to replace

| Current | Replace with | Keep? |
|---|---|---|
| `blake3` for CAS hashing | `rvf-crypto` SHAKE-256 witness chains | Replace — witness chains give tamper evidence for free |
| `ed25519-dalek` for image signing | `rvf-crypto` Ed25519 + ML-DSA-65 | Replace — adds post-quantum signing without extra dep |
| `sha2` for OCI layer digests | Keep sha2 | Keep — OCI spec mandates SHA-256; cannot swap |

### 4.3 What witness chains give you

Currently, image manifests are signed but there is no tamper-evident audit trail of operations (pull, push, layer application, container start). With rvf-crypto witness chains:

```rust
// Every container operation appends a SHAKE-256-linked entry
let mut chain = rvf_crypto::WitnessChain::open_or_create(&audit_path)?;
chain.append(WitnessEntry {
    op: "container.start",
    container_id: &id,
    image_digest: &digest,
    timestamp: Utc::now(),
})?;
// Single-byte change to any entry causes all subsequent entries to fail verification
```

This directly addresses the AUDIT_REPORT gap and gives supply chain provenance without a separate auditing system.

### 4.4 ferro-core/Cargo.toml changes

```toml
[dependencies]
# Replace these:
# blake3 = "1.5"          ← remove
# ed25519-dalek = "2.1"   ← remove

# Add:
rvf-crypto = { version = "0.2", features = ["witness", "pq-signing"] }

# Keep:
sha2 = "0.10"   # Required by OCI spec for layer digests
```

**Risk:** The existing CAS uses Blake3 hashes as content addresses stored in `sled`. Migrating these requires a one-time re-hash pass on the image store. Write a migration function; don't try to maintain both simultaneously.

---

## 5. Phase 3: Quantization and Model Compression

### 5.1 Why this matters

Current ferro-mind AI models:
- Resource predictor: 128-dimensional f32 vectors
- Anomaly detector: 5-dimensional f32 input, autoencoder
- No quantization whatsoever

`rvf-quant 0.1.0` provides scalar, product, and binary quantization with 4–8× storage reduction. For a resource predictor trained on 100k container samples at 128 dimensions × f32 (4 bytes) = 51 MB. After 8-bit scalar quantization: ~13 MB. After binary: ~6 MB.

### 5.2 Which quantization to apply where

| Model | Recommended quantization | Rationale |
|---|---|---|
| Resource predictor vectors | Scalar (8-bit) | Continuous values, moderate precision needed |
| Anomaly detector signatures | Binary | Boolean "is-anomalous" patterns tolerate lossy compression |
| Restart policy history | Product quantization | High-cardinality feature space, need cluster structure |

### 5.3 Implementation

```rust
// ferro-mind/src/ai/training.rs — add quantization step before persist
use rvf_quant::{QuantConfig, QuantMethod};

pub fn quantize_and_save(store: &mut RvfStore, method: QuantMethod) -> Result<()> {
    let config = QuantConfig {
        method,
        bits: 8,  // for scalar
        subvectors: 16,  // for product
    };
    store.quantize(config)?;
    Ok(())
}
```

Add a CLI flag: `ferrocrate ai-train --quantize scalar|product|binary`

---

## 6. Phase 4: Training Data Collection Pipeline

**This is the highest-impact missing piece.** Without it, the AI stack never improves from real workloads.

### 6.1 Collection points

Four lifecycle events in ferro-core must emit training records to ferro-mind:

| Event | Location in runtime.rs | Data to collect |
|---|---|---|
| Container stopped normally | ~line 864 (restart loop) | cpu_mean, memory_peak, uptime, exit_code=0, image |
| Container OOM-killed | OOM monitor path | memory_at_kill, growth_rate, time_to_oom, exit_code=137 |
| Container crash (non-OOM) | Restart supervisor | exit_code, recent_failures, crash_pattern, uptime |
| Container healthy checkpoint | Health check pass | cpu_p95, memory_stable, network_rate, uptime > 24h |

### 6.2 Architecture

Do NOT write telemetry synchronously in the hot path. Use a channel:

```rust
// ferro-core/src/runtime.rs — add to ContainerRuntime struct
struct ContainerRuntime {
    // existing fields...
    ai_tx: tokio::sync::mpsc::Sender<AiTelemetryEvent>,
}

enum AiTelemetryEvent {
    ContainerStopped { id: String, metrics: ContainerLifecycleMetrics },
    OomKilled        { id: String, metrics: OomMetrics },
    CrashDetected    { id: String, signal: RestartSignal },
    HealthCheckPass  { id: String, metrics: HealthMetrics },
}
```

A background task consumes the channel and writes to `.rvf` in batches:

```rust
// ferro-mind/src/ai/collector.rs (new file)
pub async fn run_collector(
    mut rx: Receiver<AiTelemetryEvent>,
    data_dir: PathBuf,
) {
    let mut buffer: Vec<AiTelemetryEvent> = Vec::with_capacity(256);

    loop {
        // Drain up to 256 events or flush every 30 seconds
        tokio::select! {
            Some(event) = rx.recv() => {
                buffer.push(event);
                if buffer.len() >= 256 {
                    flush_to_rvf(&buffer, &data_dir).await;
                    buffer.clear();
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(30)) => {
                if !buffer.is_empty() {
                    flush_to_rvf(&buffer, &data_dir).await;
                    buffer.clear();
                }
            }
        }
    }
}
```

### 6.3 Data directory structure

```
$FERROCRATE_DATA_DIR/
  ai/
    models/
      resource-predictor.rvf      ← global resource prediction model
      anomaly-signatures.rvf      ← per-image anomaly baselines
      restart-policies/
        {container_id}.rvf        ← per-container restart learning
    telemetry/
      {YYYY-MM-DD}.jsonl          ← raw event log for batch retraining
```

### 6.4 Backward compatibility

If `FERROCRATE_AI=0` is set or the data directory is read-only, the channel send is a no-op. The container runtime must never block or fail due to AI subsystem errors.

---

## 7. Phase 5: Online Learning Scheduler

The training pipeline in `training.rs` (1,507 lines) defines batch training but the online learning background process referenced in config exists only as a config key with no executing task.

### 7.1 What needs to exist

```rust
// ferro-mind/src/ai/training.rs — add the actual scheduler
pub async fn run_online_learner(
    data_dir: PathBuf,
    config: OnlineLearningConfig,
) {
    let mut interval = tokio::time::interval(config.check_interval);

    loop {
        interval.tick().await;

        let new_samples = count_new_telemetry_samples(&data_dir);

        if new_samples >= config.min_samples_to_retrain {
            log::info!("Online learning: {} new samples, retraining", new_samples);

            // Load existing model, apply incremental training, version it
            if let Err(e) = incremental_retrain(&data_dir) {
                log::warn!("Online learning failed: {e}. Previous model retained.");
                // Never panic here. Log and continue.
            }
        }
    }
}
```

### 7.2 Model versioning before update

Before any online retrain, snapshot the current model:
```
resource-predictor.rvf        ← current (active)
resource-predictor.v2.rvf     ← previous (rollback target)
resource-predictor.v1.rvf     ← older
```

Keep the last 3 versions. Use `rvf-runtime`'s COW derive to create versions without copying the full vector set.

---

## 8. Phase 6: Code Refactoring and Waste Removal

### 8.1 training.rs — reduce from 1,507 to ~400 lines

The current file is mostly scaffolding: type definitions repeated multiple times, ModelVersion structs that duplicate information, placeholder feature extraction that pads with zeros. The actual training logic is ~100 lines.

Action: Extract types to `ferro-mind/src/ai/types.rs`, collapse the ModelVersion tracking into RVF's native versioning (COW branching IS model versioning), and delete the padded feature extraction stubs — write real normalization or nothing.

### 8.2 gpu.rs — delete or implement

160 lines of detection stubs with no downstream effect:
```rust
// gpu.rs:140 — the whole file leads here:
pub fn get_gpu_info() -> Vec<GpuInfo> {
    vec![]  // Always empty
}
```

Decision: Delete unless GPU inference is on the roadmap for the next milestone. Dead code is a maintenance burden. If GPU support is planned, create a tracking issue and remove the file until implementation is ready.

### 8.3 wasm.rs — delete or implement

274 lines of trait abstraction (`WasmInferenceEngine`, `LinearWasmEngine`, `NoopEngine`). The `NoopEngine` confirms this is a placeholder. `LinearWasmEngine` implements a weight-bias multiply that could be 10 lines in the caller. There are no users of this trait in the codebase.

Decision: Delete. If WASM inference is needed, `rvf-runtime` already includes a 5.5 KB embedded WASM runtime in the `.rvf` file format (WASM_SEG 0x10). Use that instead of rolling a new abstraction.

### 8.4 explain.rs — implement properly or delete

23 lines, `DecisionTrace::new()` returns an empty struct with no methods implemented. If the decision audit trail is a product requirement (it's in AUDIT_REPORT.md), implement it properly using rvf-crypto witness chains. If not, delete.

### 8.5 VectorMemory: remove the brute-force fallback

`vector_memory.rs` has a `search_bruteforce()` O(n) fallback that is invoked when a metric other than Cosine is requested. Once the three-index consolidation is done (Phase 1), this fallback is invoked for a window of ~100 entries max (the anomaly detector's sliding window). At that scale brute-force is fine and the HNSW index is overkill. Remove the complexity of managing separate indexes and just brute-force the small window explicitly.

---

## 9. Phase 7: Strategic — RVF as Native Image Format

**This is the architectural bet. It does not block any of Phase 0–6.**

### 9.1 What OCI images cannot do that RVF can

| Capability | OCI (current) | RVF native |
|---|---|---|
| Embed AI model weights alongside rootfs | ❌ Separate artifact | ✅ OVERLAY_SEG |
| Cryptographic tamper evidence | ❌ External (cosign) | ✅ WITNESS_SEG built-in |
| Post-quantum signing | ❌ Ed25519 only | ✅ ML-DSA-65 (FIPS 204) |
| COW image layers | ⚠️ Filesystem-level | ✅ Data-format-level, more efficient |
| TEE attestation in image | ❌ External | ✅ SGX/SEV-SNP/TDX quotes in CRYPTO_SEG |
| Embedded eBPF programs | ❌ | ✅ EBPF_SEG 0x0F |
| Self-booting microkernel | ❌ Requires runtime | ✅ KERNEL_SEG 0x0E, boots in <125ms |

### 9.2 Proposed native image format: `.rvf` container

A FerroCrate native image would be a single `.rvf` file containing:

```
MANIFEST_SEG       ← image metadata (name, tag, entrypoint, env)
VEC_SEG            ← content-addressable layer hashes
OVERLAY_SEG        ← (optional) embedded LoRA weights or ONNX model
KERNEL_SEG         ← (optional) microkernel for VM-isolated containers
EBPF_SEG           ← (optional) network policy BPF programs
WITNESS_SEG        ← tamper-evident build provenance chain
CRYPTO_SEG         ← image signing (Ed25519 + ML-DSA-65 + TEE quotes)
```

### 9.3 Why not do this instead of OCI

Do not do this instead of OCI. OCI compatibility is a requirement (IMG-01, IMG-02 are "Done" in ROADMAP.md). The `.rvf` container format is an additive native format for workloads that opt into AI-native features.

Proposed CLI:
```bash
# Build OCI-compatible image (existing)
ferrocrate build -t myapp:latest .

# Build native .rvf image with embedded model weights
ferrocrate build --format rvf \
  --embed-model ./resource-predictor.rvf \
  --sign-pq \        # ML-DSA-65 signing
  -t myapp:1.0 .     # outputs myapp-1.0.rvf
```

### 9.4 Implementation path

1. Add `rvf-kernel 0.1.0` to ferro-core for the kernel builder pipeline
2. Add `rvf-launch 0.1.0` to ferro-core for QEMU microvm launching (second runtime path alongside namespace isolation)
3. Define `FerroImageManifest` that maps to RVF segments
4. Add `ferrocrate build --format rvf` command to ferro-cli
5. Add `ferrocrate run` support for `.rvf` images (auto-detect format)

---

## 10. Phase 8: AGI Cognitive Container Primitive

### 10.1 What RVF's AGI Cognitive Container (ADR-036) provides

RVF defines a bounded agentic execution model with:
- **Execution modes**: sync/async task execution
- **Authority levels**: guest / user / admin (like Unix privilege levels)
- **Resource budgets**: CPU%, memory cap, token budget (for LLM calls)
- **Coherence gates**: conditions that must hold for the container to proceed

This maps directly onto FerroCrate's security and resource model.

### 10.2 Mapping to FerroCrate concepts

| RVF Cognitive Container | FerroCrate equivalent | Gap |
|---|---|---|
| Authority level: guest | seccomp restricted profile | Gap: authority not auto-selected by image type |
| Authority level: admin | seccomp unconfined | Gap: needs to be opt-in with audit |
| Resource budget: CPU%, memory | cgroup limits | Direct mapping, already implemented |
| Resource budget: token_budget | ❌ None | New concept — limits LLM API calls made by AI agents running inside container |
| Coherence gates | health checks | Partial — health checks exist but don't gate execution |

### 10.3 What to implement

For AI agent containers (containers running LLM-backed workloads):

```toml
# ferrofile.toml — new optional section
[ai_runtime]
authority = "user"           # guest | user | admin
token_budget = 10000         # max LLM tokens this container may consume
memory_budget_mb = 512
coherence_gates = [
  "model_loaded",
  "vector_store_healthy",
]
```

This gives operators a first-class primitive for running AI agents in containers with enforced resource budgets — a capability no other container runtime has.

---

## 11. Testing Gaps

These are not addressed anywhere in the existing plan and represent production readiness blockers:

### 11.1 No persistence integration tests

There are unit tests for VectorMemory and RvfStore in isolation, but no test that:
1. Inserts 1000 vectors into a `.rvf` store
2. Kills the process (simulated)
3. Reopens the store
4. Verifies all 1000 vectors are present and searchable

This is the most critical test for the persistence claim.

### 11.2 No end-to-end AI behavior tests

No test that:
1. Runs a container with a known resource usage pattern
2. Collects telemetry
3. Verifies the anomaly detector trained on that data
4. Verifies the resource predictor's prediction improves over multiple runs

### 11.3 No benchmark baseline for AI overhead

`PERF-01..08` are listed as Partial in the roadmap. There is no benchmark that measures AI subsystem overhead on container operations. The target should be: AI monitoring overhead < 2% CPU on a container running at 50% CPU.

### 11.4 No rollback test

No test verifies that `FERROCRATE_AI_BACKEND=legacy` works after an RVF migration, or that a corrupted `.rvf` file causes graceful fallback rather than a panic.

---

## 12. Dependency Cleanup

### ferro-core/Cargo.toml changes after Phase 2

```toml
# Remove:
# blake3 = "1.5"          → replaced by rvf-crypto SHAKE-256
# ed25519-dalek = "2.1"   → replaced by rvf-crypto Ed25519 + ML-DSA-65

# Add:
rvf-crypto = { version = "0.2", features = ["witness", "pq-signing", "tee-attest"] }

# Keep (OCI spec requires SHA-256):
sha2 = "0.10"
```

### ferro-mind/Cargo.toml changes after Phase 1

```toml
# Remove:
# rvf-runtime = { version = "0.1", optional = true }   → upgrade + make default
# rvf-types   = { version = "0.1", optional = true }   → upgrade + make default

# Replace with:
rvf-runtime = { version = "0.2" }
rvf-types   = { version = "0.2" }
rvf-quant   = { version = "0.1" }
rvf-index   = { version = "0.1" }
```

---

## 13. Prioritised Execution Order

Work in this sequence. Each phase has clear done-criteria before moving to the next.

### Phase 0 — Runtime Disconnection (fix first, ~1 week)
- [ ] Wire `NeuralAnomalyDetector` into the OOM monitor loop in runtime.rs
- [ ] Wire `AdaptiveRestartPolicy` into the restart supervisor
- [ ] Make `ResourcePredictor` load from and persist to `.rvf` per-container
- **Done when:** Running a crashing container produces anomaly logs and learned restart delays

### Phase 1 — RVF Upgrade & Consolidation (~3 days)
- [ ] Bump rvf-runtime to 0.2.0, rvf-types to 0.2.0
- [ ] Add rvf-quant 0.1.0 and rvf-index 0.1.0 to ferro-mind
- [ ] Remove `optional = true`, make rvf-persistence the default feature
- [ ] Delete `rvf_store.rs` and `rvf_cache.rs` (293 lines)
- [ ] Consolidate VectorMemory to a single RVF-backed store
- **Done when:** `cargo build --no-default-features` gives a clean legacy path; default path uses rvf-runtime 0.2

### Phase 2 — ferro-core Crypto (~4 days)
- [ ] Add rvf-crypto to ferro-core
- [ ] Replace blake3 CAS hashing with SHAKE-256 witness chains
- [ ] Replace ed25519-dalek signing with rvf-crypto Ed25519 + ML-DSA-65
- [ ] Write one-time CAS migration function for existing image stores
- [ ] Remove blake3 and ed25519-dalek from ferro-core Cargo.toml
- **Done when:** `ferrocrate pull` and `ferrocrate run` work end-to-end with rvf-crypto; existing image store migrates cleanly

### Phase 3 — Quantization (~2 days)
- [ ] Add quantization step to training pipeline
- [ ] Add `--quantize` flag to `ferrocrate ai-train`
- [ ] Benchmark: verify 4× storage reduction, <5% accuracy drop
- **Done when:** A 50 MB model compresses to ~13 MB scalar or ~6 MB binary

### Phase 4 — Training Data Collection (~1 week)
- [ ] Add `AiTelemetryEvent` channel to ContainerRuntime
- [ ] Add four lifecycle collection points (stopped, OOM, crash, health)
- [ ] Implement background collector that flushes to `.rvf`
- [ ] Add data directory structure and env var config
- **Done when:** Running 10 containers, then running `ferrocrate ai-stats`, shows 10+ training records

### Phase 5 — Online Learning Scheduler (~3 days)
- [ ] Implement `run_online_learner()` async task
- [ ] Implement model versioning with COW derive
- [ ] Wire into ContainerRuntime startup
- **Done when:** After 1000 samples accumulated, model version increments automatically with no manual intervention

### Phase 6 — Refactoring (~3 days)
- [ ] Reduce training.rs from 1,507 → ~400 lines
- [ ] Delete gpu.rs (160 lines)
- [ ] Delete wasm.rs (274 lines) or replace with rvf-runtime WASM_SEG
- [ ] Implement or delete explain.rs (23 lines)
- **Done when:** `cargo clippy -- -D warnings` passes on all of ferro-mind

### Phase 7 — Native Image Format (~3–4 weeks, strategic)
- [ ] Define `.rvf` container manifest spec
- [ ] Add rvf-kernel and rvf-launch to ferro-core
- [ ] Implement `ferrocrate build --format rvf`
- [ ] Implement `ferrocrate run` auto-detect for `.rvf` images
- **Done when:** Can build, ship, and run a complete container as a single `.rvf` file with embedded model weights and attestation

### Phase 8 — AGI Cognitive Container (~1 week, strategic)
- [ ] Add `[ai_runtime]` section to ferrofile.toml spec
- [ ] Implement authority level → seccomp profile mapping
- [ ] Implement token_budget enforcement via metered LLM proxy
- [ ] Implement coherence gates as pre-run health assertions
- **Done when:** A container with `authority = "guest"` auto-applies restricted seccomp; `token_budget = 5000` enforces a cap on LLM API calls

---

## 14. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| rvf-runtime 0.2 API breaks existing 0.1 usage | Medium | Medium | Read 0.1→0.2 changelog before upgrading; fix compile errors before merging |
| CAS migration corrupts existing image store | Low | Critical | Run migration only on a copy first; verify all digests before swapping |
| AI overhead causes container startup regression | Medium | High | Benchmark before and after Phase 0; enforce <50ms overhead in CI |
| Removing blake3 breaks OCI layer digest logic | Low | High | sha2 handles OCI digests; blake3 is only used for CAS. Keep sha2. |
| Online learning degrades model on bad data | Medium | Medium | Version models with COW before every retrain; keep last 3 versions |
| Phase 7 (native image format) has no ecosystem | High | Low | This is expected — native format is opt-in, OCI remains default |
| wasm.rs deletion breaks undiscovered callers | Low | Low | Grep for all callers before deleting; currently: zero external callers found |

---

## What the Previous Draft Missed

For reference, here are the gaps in the 2026-02-14 v1.0 draft:

- **Did not address** the runtime disconnection (the actual #1 blocker)
- **Did not address** rvf-crypto as a replacement for manual ferro-core crypto
- **Did not address** rvf-quant for model compression
- **Did not address** training data collection — the plan assumed data would exist, with no pipeline to produce it
- **Did not address** the online learning scheduler having no executor
- **Did not address** dead code (gpu.rs, wasm.rs, explain.rs)
- **Did not address** the three-HNSW-index proliferation in VectorMemory
- **Did not address** version drift (0.1 → 0.2 upgrade)
- **Kept** the thin wrapper files that add no value
- **Scoped out** anything beyond ferro-mind, missing the strategic crypto replacement in ferro-core

The CLI command examples and training workflow documentation in the v1.0 draft are still valid and are incorporated by reference; they do not need to be rewritten.
