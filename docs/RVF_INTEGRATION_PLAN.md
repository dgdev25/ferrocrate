# RVF Integration Implementation Plan
## FerroCrate AI Persistence Layer

**Status:** Draft
**Version:** 1.0
**Last Updated:** 2026-02-14
**Owner:** AI/ML Team

---

## Executive Summary

### Objective
Integrate RVF (RuVector Format) into FerroCrate's `ferro-mind` crate to enable persistent AI learning, cross-session memory, and portable model distribution.

### Problem Statement
**Current State:**
- AI learns container patterns but forgets everything on restart
- Anomaly detection must retrain from scratch every session
- Image deduplication knowledge doesn't persist
- Cannot share learned patterns between ferrocrate instances

**Target State:**
- Persistent AI memory across restarts via `.rvf` files
- Ship trained models as single-file artifacts
- Cross-container learning through shared `.rvf` databases
- Git-like versioning of AI models with copy-on-write branching

### Success Metrics
| Metric | Current | Target | Measurement |
|--------|---------|--------|-------------|
| AI cold-start accuracy | 0% (no memory) | 70% | Query accuracy on restart |
| Model distribution size | 90MB+ (multi-file) | Single `.rvf` | File count |
| Cross-session learning | ❌ None | ✅ Full history | Pattern recall rate |
| Storage efficiency | 100% baseline | 60% (CoW) | Disk usage for model variants |

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Implementation Phases](#implementation-phases)
3. [Phase 1: Core Integration](#phase-1-core-integration)
4. [Phase 2: CLI & Training](#phase-2-cli--training)
5. [Phase 3: Advanced Features](#phase-3-advanced-features)
6. [Training Workflows](#training-workflows)
7. [Testing Strategy](#testing-strategy)
8. [Migration Path](#migration-path)
9. [Rollback Plan](#rollback-plan)
10. [Appendix: Code Examples](#appendix-code-examples)

---

## Architecture Overview

### Current Architecture

```
ferro-mind/
├── src/
│   ├── ai/
│   │   ├── learning/
│   │   │   └── vector_memory.rs       ← Uses ruvector-core VectorDB (in-memory)
│   │   ├── anomaly.rs                 ← Anomaly detection
│   │   ├── resource.rs                ← Resource prediction
│   │   └── training.rs                ← Model training
│   ├── ruv/
│   │   ├── embeddings.rs              ← HashEmbedding + optional ONNX
│   │   ├── dedup.rs                   ← Image layer deduplication
│   │   └── distance.rs                ← Distance metrics
│   └── wasm.rs                        ← WASM inference
└── Cargo.toml
```

**Key Dependencies:**
- `ruvector-core` (HNSW indexing, in-memory)
- `ruv-fann` (neural networks)
- `tract-onnx` (optional, semantic embeddings)

### Target Architecture

```
ferro-mind/
├── src/
│   ├── ai/
│   │   ├── learning/
│   │   │   ├── vector_memory.rs       ← RVF-backed persistent storage
│   │   │   └── rvf_store.rs           ← NEW: RVF wrapper
│   │   ├── anomaly.rs                 ← Enhanced with persistent patterns
│   │   ├── resource.rs                ← Enhanced with historical learning
│   │   └── training.rs                ← RVF training pipeline
│   ├── ruv/
│   │   ├── embeddings.rs              ← Unchanged
│   │   ├── dedup.rs                   ← RVF-backed layer cache
│   │   └── rvf_cache.rs               ← NEW: Persistent dedup cache
│   └── wasm.rs                        ← Unchanged
└── Cargo.toml                         ← Add rvf-runtime dependency
```

**New Dependencies:**
```toml
[dependencies]
rvf-runtime = "0.1"      # Core RVF functionality
rvf-types = "0.1"        # Type definitions
```

---

## Implementation Phases

### Phase 1: Core Integration (2 weeks)
**Goal:** Replace in-memory VectorMemory with RVF-backed persistent storage

**Deliverables:**
- RVF-backed VectorMemory implementation
- Backward compatibility layer
- Unit tests with 90% coverage
- Benchmark comparison (RVF vs in-memory)

**Risk:** Low (drop-in replacement)

### Phase 2: CLI & Training (2 weeks)
**Goal:** Enable users to train, export, and import `.rvf` files

**Deliverables:**
- `ferrocrate ai-train` command
- `ferrocrate ai-export` command
- `ferrocrate ai-import` command
- `ferrocrate ai-stats` command
- Documentation and examples

**Risk:** Medium (new CLI surface area)

### Phase 3: Advanced Features (3 weeks)
**Goal:** CoW branching, cryptographic lineage, image deduplication

**Deliverables:**
- `ferrocrate ai-branch` command (Git-like model versioning)
- `ferrocrate ai-lineage` command (cryptographic proof chains)
- RVF-backed image layer deduplication
- Community model marketplace integration

**Risk:** Medium-High (complex features)

---

## Phase 1: Core Integration

### 1.1 Add RVF Dependencies

**File:** `ferro-mind/Cargo.toml`

```toml
[dependencies]
# Existing dependencies...
ruvector-core = { version = "2.0", default-features = false, features = ["simd", "parallel"] }
ruv-fann = "0.2"

# NEW: RVF integration
rvf-runtime = "0.1"
rvf-types = "0.1"

[features]
default = ["rvf-persistence"]
rvf-persistence = ["dep:rvf-runtime", "dep:rvf-types"]
legacy-memory = []  # Fallback to old in-memory implementation
```

### 1.2 Create RVF Store Wrapper

**File:** `ferro-mind/src/ai/learning/rvf_store.rs` (NEW)

```rust
//! RVF-backed persistent vector storage
//!
//! Provides persistent vector memory using RuVector Format (.rvf files).
//! Replaces in-memory VectorDB with disk-backed storage for cross-session learning.

use rvf_runtime::{RvfStore as RvfBackend, RvfOptions, QueryOptions};
use crate::ruv::types::{DistanceMetric, SearchResult, VectorEntry, VectorId};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RvfError {
    #[error("RVF store error: {0}")]
    StoreError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Invalid dimensions: expected {expected}, got {actual}")]
    DimensionMismatch { expected: usize, actual: usize },
}

type Result<T> = std::result::Result<T, RvfError>;

/// RVF-backed vector store with persistent storage
pub struct RvfStore {
    backend: RvfBackend,
    path: PathBuf,
    dimensions: usize,
}

impl RvfStore {
    /// Create a new RVF store at the specified path
    pub fn create<P: AsRef<Path>>(path: P, dimensions: usize) -> Result<Self> {
        let path = path.as_ref().to_path_buf();

        let options = RvfOptions {
            dimension: dimensions,
            metric: rvf_types::DistanceMetric::Cosine,
            ..Default::default()
        };

        let backend = RvfBackend::create(&path, options)
            .map_err(|e| RvfError::StoreError(e.to_string()))?;

        Ok(Self {
            backend,
            path,
            dimensions,
        })
    }

    /// Open an existing RVF store
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref().to_path_buf();

        let backend = RvfBackend::open(&path)
            .map_err(|e| RvfError::StoreError(e.to_string()))?;

        let dimensions = backend.dimensions();

        Ok(Self {
            backend,
            path,
            dimensions,
        })
    }

    /// Open existing store or create new one
    pub fn open_or_create<P: AsRef<Path>>(path: P, dimensions: usize) -> Result<Self> {
        if path.as_ref().exists() {
            Self::open(path)
        } else {
            Self::create(path, dimensions)
        }
    }

    /// Insert a vector entry
    pub fn insert(&mut self, entry: VectorEntry) -> Result<()> {
        if entry.vector.len() != self.dimensions {
            return Err(RvfError::DimensionMismatch {
                expected: self.dimensions,
                actual: entry.vector.len(),
            });
        }

        let id = entry.id
            .as_ref()
            .map(|id| id.as_bytes())
            .unwrap_or_else(|| uuid::Uuid::new_v4().as_bytes());

        self.backend
            .ingest(&entry.vector, id, entry.metadata)
            .map_err(|e| RvfError::StoreError(e.to_string()))?;

        Ok(())
    }

    /// Insert multiple entries in batch
    pub fn insert_batch(&mut self, entries: &[VectorEntry]) -> Result<()> {
        let vectors: Vec<&[f32]> = entries.iter().map(|e| e.vector.as_slice()).collect();
        let ids: Vec<&[u8]> = entries.iter()
            .map(|e| e.id.as_ref().map(|id| id.as_bytes()).unwrap_or(&[]))
            .collect();

        self.backend
            .ingest_batch(&vectors, &ids, None)
            .map_err(|e| RvfError::StoreError(e.to_string()))?;

        Ok(())
    }

    /// Search for k nearest neighbors
    pub fn search(&self, query: &[f32], k: usize) -> Result<Vec<SearchResult>> {
        if query.len() != self.dimensions {
            return Err(RvfError::DimensionMismatch {
                expected: self.dimensions,
                actual: query.len(),
            });
        }

        let results = self.backend
            .query(query, k, &QueryOptions::default())
            .map_err(|e| RvfError::StoreError(e.to_string()))?;

        Ok(results
            .into_iter()
            .map(|r| SearchResult {
                id: VectorId::from(String::from_utf8_lossy(&r.id).to_string()),
                score: r.score,
                vector: Some(r.vector),
                metadata: r.metadata,
            })
            .collect())
    }

    /// Get the number of vectors in the store
    pub fn len(&self) -> usize {
        self.backend.len()
    }

    /// Check if store is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get the dimensionality of vectors
    pub fn dimensions(&self) -> usize {
        self.dimensions
    }

    /// Get the file path
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Close the store (flushes pending writes)
    pub fn close(self) -> Result<()> {
        self.backend
            .close()
            .map_err(|e| RvfError::StoreError(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::collections::HashMap;

    #[test]
    fn test_create_and_open() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test.rvf");

        // Create
        {
            let store = RvfStore::create(&path, 128).unwrap();
            assert_eq!(store.dimensions(), 128);
            assert!(store.is_empty());
            store.close().unwrap();
        }

        // Open
        {
            let store = RvfStore::open(&path).unwrap();
            assert_eq!(store.dimensions(), 128);
        }
    }

    #[test]
    fn test_insert_and_search() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test.rvf");

        let mut store = RvfStore::create(&path, 3).unwrap();

        // Insert vectors
        store.insert(VectorEntry {
            id: Some(VectorId::from("vec1")),
            vector: vec![1.0, 0.0, 0.0],
            metadata: None,
        }).unwrap();

        store.insert(VectorEntry {
            id: Some(VectorId::from("vec2")),
            vector: vec![0.0, 1.0, 0.0],
            metadata: None,
        }).unwrap();

        assert_eq!(store.len(), 2);

        // Search
        let results = store.search(&[1.0, 0.1, 0.0], 2).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].id.as_str(), "vec1");  // Closest to query
    }

    #[test]
    fn test_persistence() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test.rvf");

        // Write data
        {
            let mut store = RvfStore::create(&path, 4).unwrap();
            store.insert(VectorEntry {
                id: Some(VectorId::from("persistent")),
                vector: vec![1.0, 2.0, 3.0, 4.0],
                metadata: Some(HashMap::from([
                    ("type".to_string(), serde_json::json!("test")),
                ])),
            }).unwrap();
            store.close().unwrap();
        }

        // Read data
        {
            let store = RvfStore::open(&path).unwrap();
            assert_eq!(store.len(), 1);

            let results = store.search(&[1.0, 2.0, 3.0, 4.0], 1).unwrap();
            assert_eq!(results[0].id.as_str(), "persistent");
            assert_eq!(results[0].metadata.as_ref().unwrap()["type"], "test");
        }
    }
}
```

### 1.3 Update VectorMemory to Use RVF

**File:** `ferro-mind/src/ai/learning/vector_memory.rs`

```rust
//! Vector Memory with optional RVF persistence
//!
//! Provides O(log n) approximate nearest neighbor search with optional
//! persistent storage via RVF format.

use crate::ruv::types::{DistanceMetric, SearchResult, VectorEntry};
use std::path::Path;

#[cfg(feature = "rvf-persistence")]
use crate::ai::learning::rvf_store::RvfStore;

#[cfg(feature = "legacy-memory")]
use crate::ai::learning::legacy_memory::LegacyVectorMemory;

/// Vector memory backend
pub enum VectorMemory {
    #[cfg(feature = "rvf-persistence")]
    Rvf(RvfStore),

    #[cfg(feature = "legacy-memory")]
    Legacy(LegacyVectorMemory),
}

impl VectorMemory {
    /// Create new persistent vector memory backed by RVF
    #[cfg(feature = "rvf-persistence")]
    pub fn persistent<P: AsRef<Path>>(path: P, dimensions: usize) -> Result<Self, String> {
        let store = RvfStore::open_or_create(path, dimensions)
            .map_err(|e| e.to_string())?;
        Ok(VectorMemory::Rvf(store))
    }

    /// Create new in-memory vector memory (legacy)
    #[cfg(feature = "legacy-memory")]
    pub fn in_memory(dimensions: usize) -> Self {
        VectorMemory::Legacy(LegacyVectorMemory::with_dimensions(dimensions))
    }

    /// Insert a vector entry
    pub fn insert(&mut self, entry: VectorEntry) -> Result<(), String> {
        match self {
            #[cfg(feature = "rvf-persistence")]
            VectorMemory::Rvf(store) => store.insert(entry).map_err(|e| e.to_string()),

            #[cfg(feature = "legacy-memory")]
            VectorMemory::Legacy(mem) => {
                mem.insert(entry);
                Ok(())
            }
        }
    }

    /// Search for k nearest neighbors
    pub fn search(&self, query: &[f32], k: usize, metric: DistanceMetric) -> Vec<SearchResult> {
        match self {
            #[cfg(feature = "rvf-persistence")]
            VectorMemory::Rvf(store) => {
                // RVF currently only supports Cosine in HNSW mode
                if metric == DistanceMetric::Cosine {
                    store.search(query, k).unwrap_or_else(|_| Vec::new())
                } else {
                    // Fall back to brute-force for other metrics
                    Vec::new()  // TODO: Implement fallback
                }
            }

            #[cfg(feature = "legacy-memory")]
            VectorMemory::Legacy(mem) => mem.search(query, k, metric),
        }
    }

    /// Get the number of stored vectors
    pub fn len(&self) -> usize {
        match self {
            #[cfg(feature = "rvf-persistence")]
            VectorMemory::Rvf(store) => store.len(),

            #[cfg(feature = "legacy-memory")]
            VectorMemory::Legacy(mem) => mem.len(),
        }
    }

    /// Check if memory is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
```

### 1.4 Update AI Systems to Use Persistent Memory

**File:** `ferro-mind/src/ai/resource.rs` (Example)

```rust
use crate::ai::learning::VectorMemory;
use std::path::PathBuf;

pub struct ResourcePredictor {
    memory: VectorMemory,
    config: PredictorConfig,
}

impl ResourcePredictor {
    pub fn new(config: PredictorConfig) -> Result<Self, String> {
        // Use persistent storage by default
        let memory_path = config.data_dir
            .join("resource-patterns.rvf");

        let memory = VectorMemory::persistent(memory_path, 128)?;

        Ok(Self { memory, config })
    }

    pub fn learn_from_container(&mut self, container: &ContainerMetrics) -> Result<(), String> {
        let vector = self.extract_features(container);
        let entry = VectorEntry {
            id: Some(VectorId::from(container.id.clone())),
            vector,
            metadata: Some(serde_json::to_value(container).ok()),
        };

        self.memory.insert(entry)?;
        Ok(())
    }

    pub fn predict(&self, container: &ContainerInfo) -> Prediction {
        let query = self.extract_features_from_info(container);
        let similar = self.memory.search(&query, 10, DistanceMetric::Cosine);

        // Aggregate predictions from similar past containers
        self.aggregate_predictions(&similar)
    }
}
```

---

## Phase 2: CLI & Training

### 2.1 Add CLI Commands

**File:** `ferro-cli/src/commands/ai.rs` (NEW)

```rust
//! AI model management commands

use clap::{Args, Subcommand};
use ferro_mind::ai::training::ModelTrainer;
use std::path::PathBuf;

#[derive(Debug, Args)]
pub struct AiCommand {
    #[command(subcommand)]
    command: AiSubcommand,
}

#[derive(Debug, Subcommand)]
enum AiSubcommand {
    /// Train a new model from historical data
    Train(TrainArgs),

    /// Export current model to .rvf file
    Export(ExportArgs),

    /// Import a trained model from .rvf file
    Import(ImportArgs),

    /// Show model statistics
    Stats(StatsArgs),

    /// Branch a model (copy-on-write)
    Branch(BranchArgs),

    /// Show model lineage (cryptographic proof chain)
    Lineage(LineageArgs),
}

#[derive(Debug, Args)]
struct TrainArgs {
    /// Input training data (JSONL format)
    #[arg(long)]
    input: PathBuf,

    /// Output .rvf file
    #[arg(long)]
    output: PathBuf,

    /// Vector dimensions
    #[arg(long, default_value = "128")]
    dimension: usize,

    /// Model type (resource-prediction, anomaly-detection, crash-prediction)
    #[arg(long, value_enum)]
    model_type: ModelType,

    /// Incremental training (add to existing model)
    #[arg(long)]
    incremental: bool,
}

#[derive(Debug, Args)]
struct ExportArgs {
    /// Source model (from ferrocrate data directory)
    #[arg(long)]
    model: String,

    /// Output .rvf file
    #[arg(long)]
    output: PathBuf,
}

#[derive(Debug, Args)]
struct ImportArgs {
    /// Input .rvf file
    #[arg(long)]
    input: PathBuf,

    /// Target model name
    #[arg(long)]
    name: String,

    /// Overwrite existing model
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct StatsArgs {
    /// Model .rvf file
    file: PathBuf,

    /// Show detailed statistics
    #[arg(long)]
    verbose: bool,
}

#[derive(Debug, Args)]
struct BranchArgs {
    /// Source .rvf file
    source: PathBuf,

    /// Target .rvf file
    target: PathBuf,
}

#[derive(Debug, Args)]
struct LineageArgs {
    /// Model .rvf file
    file: PathBuf,

    /// Show full cryptographic proof chain
    #[arg(long)]
    verify: bool,
}

pub fn execute(cmd: AiCommand) -> Result<(), Box<dyn std::error::Error>> {
    match cmd.command {
        AiSubcommand::Train(args) => train(args),
        AiSubcommand::Export(args) => export(args),
        AiSubcommand::Import(args) => import(args),
        AiSubcommand::Stats(args) => stats(args),
        AiSubcommand::Branch(args) => branch(args),
        AiSubcommand::Lineage(args) => lineage(args),
    }
}

fn train(args: TrainArgs) -> Result<(), Box<dyn std::error::Error>> {
    println!("Training {} model from {}", args.model_type, args.input.display());

    let trainer = ModelTrainer::new(args.dimension, args.model_type);

    if args.incremental && args.output.exists() {
        println!("Incremental training: loading existing model...");
        trainer.load(&args.output)?;
    }

    trainer.train_from_file(&args.input)?;
    trainer.save(&args.output)?;

    println!("✓ Model saved to {}", args.output.display());
    println!("  Vectors: {}", trainer.vector_count());
    println!("  Size: {:.2} MB", trainer.file_size_mb());

    Ok(())
}

// Additional command implementations...
```

### 2.2 Model Trainer Implementation

**File:** `ferro-mind/src/ai/training.rs` (Enhanced)

```rust
//! Model training pipeline for RVF-backed models

use crate::ai::learning::rvf_store::RvfStore;
use crate::ruv::types::VectorEntry;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::fs::File;
use std::io::{BufRead, BufReader};

#[derive(Debug, Clone, Copy)]
pub enum ModelType {
    ResourcePrediction,
    AnomalyDetection,
    CrashPrediction,
}

pub struct ModelTrainer {
    store: Option<RvfStore>,
    dimensions: usize,
    model_type: ModelType,
}

impl ModelTrainer {
    pub fn new(dimensions: usize, model_type: ModelType) -> Self {
        Self {
            store: None,
            dimensions,
            model_type,
        }
    }

    /// Train from JSONL file (one JSON object per line)
    pub fn train_from_file<P: AsRef<Path>>(&mut self, path: P) -> Result<(), String> {
        let file = File::open(path).map_err(|e| e.to_string())?;
        let reader = BufReader::new(file);

        let mut entries = Vec::new();

        for line in reader.lines() {
            let line = line.map_err(|e| e.to_string())?;
            let data: TrainingExample = serde_json::from_str(&line)
                .map_err(|e| format!("Parse error: {}", e))?;

            let vector = self.extract_features(&data)?;
            entries.push(VectorEntry {
                id: Some(data.id.into()),
                vector,
                metadata: Some(data.metadata),
            });
        }

        if let Some(store) = &mut self.store {
            store.insert_batch(&entries).map_err(|e| e.to_string())?;
        }

        Ok(())
    }

    /// Extract feature vector based on model type
    fn extract_features(&self, example: &TrainingExample) -> Result<Vec<f32>, String> {
        match self.model_type {
            ModelType::ResourcePrediction => {
                self.extract_resource_features(example)
            }
            ModelType::AnomalyDetection => {
                self.extract_anomaly_features(example)
            }
            ModelType::CrashPrediction => {
                self.extract_crash_features(example)
            }
        }
    }

    fn extract_resource_features(&self, example: &TrainingExample) -> Result<Vec<f32>, String> {
        let metrics = &example.metrics;

        // Build 128-dimensional feature vector
        let mut features = Vec::with_capacity(128);

        // CPU features (0-31)
        features.extend(&[
            metrics.cpu_mean,
            metrics.cpu_max,
            metrics.cpu_min,
            metrics.cpu_std,
            metrics.cpu_p50,
            metrics.cpu_p95,
            metrics.cpu_p99,
            // ... pad to 32 features
        ]);

        // Memory features (32-63)
        features.extend(&[
            metrics.memory_mean,
            metrics.memory_max,
            metrics.memory_growth_rate,
            metrics.memory_std,
            // ... pad to 32 features
        ]);

        // I/O features (64-95)
        features.extend(&[
            metrics.disk_read_bytes_per_sec,
            metrics.disk_write_bytes_per_sec,
            metrics.network_rx_bytes_per_sec,
            metrics.network_tx_bytes_per_sec,
            // ... pad to 32 features
        ]);

        // Context features (96-127)
        features.extend(&[
            metrics.container_age_hours,
            metrics.restart_count as f32,
            metrics.hour_of_day as f32 / 24.0,
            metrics.day_of_week as f32 / 7.0,
            // ... pad to 32 features
        ]);

        // Pad to exact dimension if needed
        while features.len() < self.dimensions {
            features.push(0.0);
        }

        Ok(features)
    }

    pub fn load<P: AsRef<Path>>(&mut self, path: P) -> Result<(), String> {
        self.store = Some(RvfStore::open(path).map_err(|e| e.to_string())?);
        Ok(())
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), String> {
        if let Some(store) = &self.store {
            // RVF auto-saves, but we can trigger explicit flush
            Ok(())
        } else {
            Err("No model loaded".to_string())
        }
    }

    pub fn vector_count(&self) -> usize {
        self.store.as_ref().map(|s| s.len()).unwrap_or(0)
    }
}

#[derive(Debug, Deserialize)]
struct TrainingExample {
    id: String,
    metrics: ContainerMetrics,
    metadata: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct ContainerMetrics {
    cpu_mean: f32,
    cpu_max: f32,
    cpu_min: f32,
    cpu_std: f32,
    cpu_p50: f32,
    cpu_p95: f32,
    cpu_p99: f32,
    memory_mean: f32,
    memory_max: f32,
    memory_growth_rate: f32,
    memory_std: f32,
    disk_read_bytes_per_sec: f32,
    disk_write_bytes_per_sec: f32,
    network_rx_bytes_per_sec: f32,
    network_tx_bytes_per_sec: f32,
    container_age_hours: f32,
    restart_count: u32,
    hour_of_day: u8,
    day_of_week: u8,
}
```

---

## Training Data Sources

### Overview

RVF files learn from real-world container operations. Training data comes from 6 primary sources, ranging from fully automated telemetry collection to external integrations. The key insight: **FerroCrate learns from itself** — every container you run contributes to the AI's knowledge base.

### Source 1: FerroCrate's Own Telemetry (Automatic)

**How it works:**
- Every container emits metrics every 5 seconds (CPU, memory, I/O, network)
- Resource predictor automatically samples telemetry on container lifecycle events
- Anomaly detector learns "normal" patterns from baseline operations
- Crash predictor correlates exit codes with pre-crash metrics

**Configuration:**

```bash
# Enable automatic telemetry capture (default: enabled)
export FERROCRATE_AI_TELEMETRY=1

# Configure sampling rate (default: 5s)
export FERROCRATE_AI_SAMPLE_INTERVAL=5s

# Enable crash predictor auto-learning (default: enabled)
export FERROCRATE_AI_LEARN_FROM_CRASHES=1
```

**What gets learned:**

```rust
// Automatic learning trigger points
impl ResourcePredictor {
    // Learn when container stops (normal or crash)
    fn on_container_stopped(&mut self, container: &Container) {
        let features = self.extract_lifecycle_features(container);
        self.memory.insert(features)?;  // Auto-persists to .rvf
    }

    // Learn from resource exhaustion events
    fn on_oom_killed(&mut self, container: &Container) {
        let features = self.extract_oom_features(container);
        self.anomaly_detector.learn_anomaly(features, Severity::Critical)?;
    }

    // Learn from successful patterns
    fn on_container_healthy(&mut self, container: &Container) {
        if container.uptime > Duration::from_hours(24) {
            let features = self.extract_health_features(container);
            self.memory.insert(features)?;  // Positive example
        }
    }
}
```

**Real-world example:**

```bash
# Run a container — FerroCrate learns automatically
ferrocrate run --name web-server nginx:alpine

# After 24 hours of uptime, FerroCrate has learned:
# - Nginx's normal CPU pattern (spikes on request bursts)
# - Memory baseline (stable around 10 MB)
# - Network I/O characteristics (bursty)
# - This becomes training data for future nginx containers
```

### Source 2: Export Historical Data (On-Demand)

**Use case:** You've run FerroCrate for months. Now you want to train a production-grade model from that historical experience.

**Export command:**

```bash
# Export last 30 days of metrics
ferrocrate ai-export \
  --history 30d \
  --format jsonl \
  --filter image=postgres:* \
  > postgres-training.jsonl

# Export only crashed containers
ferrocrate ai-export \
  --history 90d \
  --filter crashed=true \
  --format jsonl \
  > crash-patterns.jsonl

# Export specific container by ID
ferrocrate ai-export \
  --container abc123 \
  --format jsonl \
  > container-abc123.jsonl
```

**Example output (JSONL format):**

```jsonl
{"id":"container-1","image":"postgres:14","metrics":{"cpu_mean":0.34,"memory_mean":536870912,"memory_growth_rate":0.02,"restart_count":0},"metadata":{"crashed":false,"oom_killed":false,"uptime_hours":168}}
{"id":"container-2","image":"postgres:14","metrics":{"cpu_mean":0.89,"memory_mean":2147483648,"memory_growth_rate":0.15,"restart_count":2},"metadata":{"crashed":true,"oom_killed":true,"uptime_hours":4}}
```

**Training from export:**

```bash
ferrocrate ai-train \
  --input postgres-training.jsonl \
  --output models/postgres-predictor.rvf \
  --dimension 128 \
  --model-type resource-prediction
```

### Source 3: Import from Docker/Podman (Migration)

**Use case:** You're migrating from Docker to FerroCrate. Import Docker's historical data so FerroCrate starts with your existing knowledge.

**Docker stats export:**

```bash
# Export Docker stats to JSONL (requires custom script)
docker ps -a --format '{{.ID}}' | while read id; do
  docker inspect $id | jq -c '{
    id: .[0].Id,
    image: .[0].Config.Image,
    metrics: {
      cpu_mean: (.[0].HostConfig.NanoCpus // 0) / 1000000000,
      memory_mean: (.[0].HostConfig.Memory // 0),
      restart_count: .[0].RestartCount
    },
    metadata: {
      crashed: (.[0].State.ExitCode != 0),
      oom_killed: .[0].State.OOMKilled,
      uptime_hours: ((now - (.[0].State.StartedAt | fromdateiso8601)) / 3600)
    }
  }'
done > docker-export.jsonl
```

**Import to FerroCrate:**

```bash
ferrocrate ai-train \
  --input docker-export.jsonl \
  --output models/migrated-from-docker.rvf \
  --dimension 128 \
  --model-type resource-prediction
```

### Source 4: Community Models (Transfer Learning)

**Use case:** You don't have enough local data yet. Bootstrap from community-trained models.

**Download community base model:**

```bash
# Browse community models
ferrocrate ai-search --query "nginx production resource"

# Download a community model
ferrocrate ai-download \
  --name "nginx-prod-baseline-v2" \
  --author ferrocrate-community \
  --output ~/.ferrocrate/models/nginx-baseline.rvf

# Branch it (copy-on-write, no duplication)
ferrocrate ai-branch \
  ~/.ferrocrate/models/nginx-baseline.rvf \
  ~/.ferrocrate/models/my-nginx-custom.rvf

# Add your local data incrementally
ferrocrate ai-train \
  --input my-local-nginx-data.jsonl \
  --output ~/.ferrocrate/models/my-nginx-custom.rvf \
  --incremental  # Adds to existing model

# Result: my-nginx-custom.rvf = community baseline + your local patterns
```

**Community model marketplace:**

| Model Name | Description | Downloads | Accuracy | Size |
|------------|-------------|-----------|----------|------|
| `nginx-prod-baseline-v2` | Nginx production patterns from 1000+ deployments | 5.2K | 94% | 12 MB |
| `postgres-memory-predictor` | PostgreSQL OOM prevention model | 3.8K | 91% | 18 MB |
| `nodejs-crash-detector` | Node.js heap exhaustion detector | 2.1K | 87% | 8 MB |
| `redis-eviction-predictor` | Redis memory eviction patterns | 1.5K | 89% | 6 MB |

### Source 5: Synthetic Data (Testing & Bootstrapping)

**Use case:** You're developing a new predictor but don't have real-world data yet. Generate synthetic patterns for initial testing.

**Synthetic data generator:**

```rust
// ferro-mind/src/ai/testing/synthetic.rs
pub fn generate_synthetic_crash_patterns(count: usize) -> Vec<VectorEntry> {
    let mut entries = Vec::new();

    for i in 0..count {
        let is_crash = i % 3 == 0;  // 33% crash rate

        let metrics = if is_crash {
            // Crash pattern: high CPU, memory growth, network anomalies
            ContainerMetrics {
                cpu_mean: 0.85 + rand::gen_range(0.0..0.15),
                memory_mean: 1.5e9 + rand::gen_range(0.0..5e8),
                memory_growth_rate: 0.12 + rand::gen_range(0.0..0.05),
                network_rx_bytes_per_sec: 1e7 + rand::gen_range(0.0..5e6),
                restart_count: rand::gen_range(1..5),
            }
        } else {
            // Healthy pattern: stable resources
            ContainerMetrics {
                cpu_mean: 0.25 + rand::gen_range(0.0..0.15),
                memory_mean: 5e8 + rand::gen_range(0.0..1e8),
                memory_growth_rate: 0.01 + rand::gen_range(0.0..0.02),
                network_rx_bytes_per_sec: 5e6 + rand::gen_range(0.0..2e6),
                restart_count: 0,
            }
        };

        let vector = extract_features(&metrics);
        entries.push(VectorEntry {
            id: Some(format!("synthetic-{}", i).into()),
            vector,
            metadata: Some(serde_json::json!({
                "synthetic": true,
                "crashed": is_crash,
            })),
        });
    }

    entries
}
```

**Generate and train:**

```bash
# Generate 10,000 synthetic examples
ferrocrate ai-generate-synthetic \
  --model-type crash-prediction \
  --count 10000 \
  --output synthetic-crash-data.jsonl

# Train initial model
ferrocrate ai-train \
  --input synthetic-crash-data.jsonl \
  --output models/crash-predictor-bootstrap.rvf \
  --dimension 64

# Later: Blend with real data using incremental training
ferrocrate ai-train \
  --input real-crash-data.jsonl \
  --output models/crash-predictor-bootstrap.rvf \
  --incremental  # Real data overrides synthetic patterns
```

### Source 6: Kubernetes/External Logs (Integration)

**Use case:** You run Kubernetes with FerroCrate as the container runtime. Import Kubernetes metrics for centralized learning.

**Kubernetes Prometheus integration:**

```yaml
# kubernetes/ferrocrate-telemetry-exporter.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ferrocrate-telemetry
spec:
  selector:
    matchLabels:
      app: ferrocrate-telemetry
  template:
    spec:
      containers:
      - name: telemetry-exporter
        image: ferrocrate/telemetry-exporter:latest
        env:
        - name: FERROCRATE_AI_BACKEND
          value: "rvf"
        - name: FERROCRATE_MODEL_PATH
          value: "/models/k8s-cluster-wide.rvf"
        volumeMounts:
        - name: models
          mountPath: /models
        - name: ferrocrate-socket
          mountPath: /var/run/ferrocrate.sock
      volumes:
      - name: models
        hostPath:
          path: /var/lib/ferrocrate/models
      - name: ferrocrate-socket
        hostPath:
          path: /var/run/ferrocrate.sock
```

**Query Prometheus, export to FerroCrate:**

```bash
# Query last 24h of container metrics from Prometheus
curl -G http://prometheus:9090/api/v1/query_range \
  --data-urlencode 'query=container_cpu_usage_seconds_total' \
  --data-urlencode 'start=2026-02-13T00:00:00Z' \
  --data-urlencode 'end=2026-02-14T00:00:00Z' \
  | jq -c '.data.result[] | {
      id: .metric.container_id,
      image: .metric.image,
      metrics: {
        cpu_mean: (.values | map(.[1] | tonumber) | add / length),
        # ... extract other metrics
      },
      metadata: {
        node: .metric.node,
        namespace: .metric.namespace
      }
    }' \
  > k8s-prometheus-export.jsonl

# Train FerroCrate model from K8s data
ferrocrate ai-train \
  --input k8s-prometheus-export.jsonl \
  --output models/k8s-cluster-baseline.rvf \
  --dimension 128
```

### Real-World Example: Edge Device Fleet

**Scenario:** You manage 500 edge devices running FerroCrate. Train a centralized model from fleet-wide telemetry.

**Step 1: Enable automatic telemetry on all devices**

```bash
# Ansible playbook: deploy to all edge devices
- hosts: edge_devices
  tasks:
  - name: Enable FerroCrate telemetry
    lineinfile:
      path: /etc/ferrocrate/config.toml
      line: |
        [ai]
        telemetry = true
        auto_export = true
        export_interval = "24h"
        export_path = "/var/lib/ferrocrate/telemetry.jsonl"
```

**Step 2: Collect telemetry from all devices (nightly cron)**

```bash
#!/bin/bash
# collect-fleet-telemetry.sh (runs on central server)

for device in $(cat edge-devices.txt); do
  rsync -az edge@$device:/var/lib/ferrocrate/telemetry.jsonl \
    /data/fleet-telemetry/$device-$(date +%Y%m%d).jsonl &
done
wait

# Merge all device telemetry
cat /data/fleet-telemetry/*.jsonl > fleet-merged-$(date +%Y%m%d).jsonl
```

**Step 3: Train fleet-wide model**

```bash
# Train from 500 devices × 30 days = 15,000 device-days of data
ferrocrate ai-train \
  --input fleet-merged-20260214.jsonl \
  --output models/edge-fleet-predictor-v1.rvf \
  --dimension 256 \
  --model-type resource-prediction

# Verify model
ferrocrate ai-stats models/edge-fleet-predictor-v1.rvf
# Output:
# Vectors: 1,245,678
# Dimensions: 256
# Size: 47 MB
# Devices: 500
# Date range: 2026-01-15 to 2026-02-14
```

**Step 4: Deploy trained model back to all edge devices**

```bash
# Ansible playbook: deploy trained model
- hosts: edge_devices
  tasks:
  - name: Upload fleet-wide model
    copy:
      src: models/edge-fleet-predictor-v1.rvf
      dest: /var/lib/ferrocrate/models/resource-predictor.rvf

  - name: Restart FerroCrate
    systemd:
      name: ferrocrate
      state: restarted
```

**Result:** All 500 edge devices now benefit from fleet-wide learning. A device in Tokyo learns from crash patterns observed in Berlin.

### Automatic Training Pipeline (Recommended)

**Production setup:**

```toml
# /etc/ferrocrate/config.toml

[ai]
# Enable automatic learning from live containers (default: true)
auto_learn = true

# Export telemetry for batch training (default: false)
auto_export = false
export_interval = "24h"
export_path = "/var/lib/ferrocrate/telemetry.jsonl"

[ai.models]
# Automatically update models with online learning (default: true)
online_learning = true

# Batch retrain models weekly from exported telemetry (default: false)
batch_retrain = false
retrain_schedule = "0 2 * * SUN"  # Sunday 2 AM
retrain_min_samples = 1000  # Only retrain if we have 1000+ new samples

[ai.community]
# Download community model updates automatically (default: false)
auto_update_community_models = false
update_channel = "stable"  # stable, beta, edge
```

**Cron job for weekly batch retraining:**

```bash
#!/bin/bash
# /etc/cron.weekly/ferrocrate-ai-retrain

set -e

TELEMETRY_DIR="/var/lib/ferrocrate/telemetry"
MODEL_DIR="/var/lib/ferrocrate/models"

# Merge last week's telemetry
cat $TELEMETRY_DIR/telemetry-*.jsonl > /tmp/week-telemetry.jsonl

# Retrain each model type incrementally
for model_type in resource-prediction crash-prediction anomaly-detection; do
  echo "Retraining $model_type model..."

  ferrocrate ai-train \
    --input /tmp/week-telemetry.jsonl \
    --output $MODEL_DIR/$model_type.rvf \
    --model-type $model_type \
    --incremental  # Add to existing model, don't replace

  echo "✓ $model_type retrained"
done

# Cleanup
rm /tmp/week-telemetry.jsonl
find $TELEMETRY_DIR -name "telemetry-*.jsonl" -mtime +30 -delete

echo "✓ Weekly AI retraining complete"
```

### Data Privacy & Security

**Sensitive data handling:**

```rust
// Automatic PII scrubbing in telemetry
impl TelemetryExporter {
    fn scrub_sensitive_data(&self, entry: &mut VectorEntry) {
        if let Some(metadata) = &mut entry.metadata {
            // Remove environment variables (may contain secrets)
            metadata.as_object_mut().unwrap().remove("env");

            // Remove command args (may contain passwords)
            metadata.as_object_mut().unwrap().remove("cmd");

            // Remove volume paths (may reveal directory structure)
            metadata.as_object_mut().unwrap().remove("volumes");

            // Hash container IDs (preserve correlation without revealing IDs)
            if let Some(id) = metadata.get("id") {
                let hashed = blake3::hash(id.as_str().unwrap().as_bytes());
                metadata["id"] = serde_json::json!(hashed.to_hex().to_string());
            }
        }
    }
}
```

**Enable privacy mode:**

```bash
# Strict privacy: no telemetry export, only local learning
export FERROCRATE_AI_PRIVACY=strict

# Moderate privacy: export telemetry but scrub sensitive data
export FERROCRATE_AI_PRIVACY=moderate

# Community mode: share anonymized telemetry with community models
export FERROCRATE_AI_PRIVACY=community
```

---

## Training Workflows

### Workflow 1: Batch Training from Historical Data

**Step 1: Export container metrics**

```bash
# Export last 30 days of container metrics
ferrocrate ai-export --history 30d --format jsonl > training-data.jsonl
```

**Example training-data.jsonl:**
```jsonl
{"id":"container-1","metrics":{"cpu_mean":0.45,"cpu_max":0.89,"memory_mean":524288000,"restart_count":0},"metadata":{"image":"nginx:alpine","crashed":false}}
{"id":"container-2","metrics":{"cpu_mean":0.92,"cpu_max":1.0,"memory_mean":1073741824,"restart_count":3},"metadata":{"image":"postgres:14","crashed":true}}
```

**Step 2: Train model**

```bash
ferrocrate ai-train \
  --input training-data.jsonl \
  --output models/crash-predictor.rvf \
  --dimension 128 \
  --model-type crash-prediction
```

**Step 3: Deploy to edge devices**

```bash
# Copy trained model to edge device
scp models/crash-predictor.rvf edge-device:/etc/ferrocrate/models/

# On edge device, import model
ferrocrate ai-import \
  --input /etc/ferrocrate/models/crash-predictor.rvf \
  --name crash-predictor
```

### Workflow 2: Online Learning (Continuous Training)

```rust
// In ferro-mind resource predictor
pub fn on_container_stopped(&mut self, container: &Container) -> Result<()> {
    // Extract learning example
    let metrics = self.compute_metrics(container);
    let vector = self.extract_features(&metrics);

    // Add to persistent model
    let entry = VectorEntry {
        id: Some(container.id.into()),
        vector,
        metadata: Some(serde_json::json!({
            "image": container.image,
            "crashed": container.exit_code != 0,
            "oom_killed": container.oom_killed,
        })),
    };

    self.memory.insert(entry)?;

    Ok(())
}
```

### Workflow 3: Transfer Learning

```bash
# Download community base model
curl -O https://models.ferrocrate.io/community/base-resource-v1.rvf

# Branch it (copy-on-write, no data duplication)
ferrocrate ai-branch \
  base-resource-v1.rvf \
  my-custom-resource.rvf

# Add local training data incrementally
ferrocrate ai-train \
  --input local-data.jsonl \
  --output my-custom-resource.rvf \
  --incremental  # Add to existing, don't replace

# Result: my-custom-resource.rvf references base-resource-v1.rvf
# Only stores the delta (new patterns), saving disk space
```

---

## Testing Strategy

### Unit Tests

**Coverage Target:** 90%+

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_rvf_persistence_across_restarts() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test.rvf");

        // Session 1: Train and save
        {
            let mut memory = VectorMemory::persistent(&path, 128).unwrap();
            memory.insert(test_vector_entry()).unwrap();
            assert_eq!(memory.len(), 1);
        }

        // Session 2: Reload and verify
        {
            let memory = VectorMemory::persistent(&path, 128).unwrap();
            assert_eq!(memory.len(), 1);  // Should remember from session 1

            let results = memory.search(&test_query(), 1, DistanceMetric::Cosine);
            assert_eq!(results.len(), 1);
        }
    }

    #[test]
    fn test_model_training_pipeline() {
        let tmp = TempDir::new().unwrap();
        let data_file = tmp.path().join("train.jsonl");
        let model_file = tmp.path().join("model.rvf");

        // Create training data
        std::fs::write(&data_file, generate_test_jsonl()).unwrap();

        // Train
        let mut trainer = ModelTrainer::new(128, ModelType::ResourcePrediction);
        trainer.train_from_file(&data_file).unwrap();
        trainer.save(&model_file).unwrap();

        // Verify
        assert!(model_file.exists());
        assert!(model_file.metadata().unwrap().len() > 0);
    }
}
```

### Integration Tests

```bash
#!/bin/bash
# tests/integration/test_rvf_integration.sh

set -e

echo "Testing RVF integration..."

# Setup
export FERROCRATE_DATA_DIR=$(mktemp -d)
trap "rm -rf $FERROCRATE_DATA_DIR" EXIT

# Test 1: Train model
echo "Test 1: Training model..."
ferrocrate ai-train \
  --input tests/fixtures/training-data.jsonl \
  --output $FERROCRATE_DATA_DIR/test-model.rvf \
  --dimension 64 \
  --model-type crash-prediction

# Test 2: Verify model
echo "Test 2: Verifying model..."
ferrocrate ai-stats $FERROCRATE_DATA_DIR/test-model.rvf | grep "Vectors: 100"

# Test 3: Use model for prediction
echo "Test 3: Testing prediction..."
ferrocrate run --name test-container \
  --ai-model $FERROCRATE_DATA_DIR/test-model.rvf \
  alpine:latest sleep 10

# Test 4: Export and import
echo "Test 4: Export/import cycle..."
ferrocrate ai-export --model test-model --output /tmp/export.rvf
ferrocrate ai-import --input /tmp/export.rvf --name imported --force

echo "All tests passed!"
```

### Performance Benchmarks

```rust
#[bench]
fn bench_rvf_insert_1000(b: &mut Bencher) {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("bench.rvf");
    let mut store = RvfStore::create(&path, 128).unwrap();

    b.iter(|| {
        for i in 0..1000 {
            store.insert(generate_random_entry(i)).unwrap();
        }
    });
}

#[bench]
fn bench_rvf_query_10k(b: &mut Bencher) {
    let store = setup_store_with_10k_vectors();
    let query = generate_random_vector(128);

    b.iter(|| {
        store.search(&query, 10).unwrap();
    });
}
```

---

## Migration Path

### Backward Compatibility

**Flag-based feature selection:**

```toml
# Cargo.toml
[features]
default = ["rvf-persistence"]
rvf-persistence = ["dep:rvf-runtime"]
legacy-memory = []  # Old in-memory implementation
```

**Environment variable control:**

```bash
# Use RVF (default)
FERROCRATE_AI_BACKEND=rvf ferrocrate run myapp:latest

# Use legacy in-memory (backward compatible)
FERROCRATE_AI_BACKEND=legacy ferrocrate run myapp:latest

# Disable AI entirely
FERROCRATE_AI=0 ferrocrate run myapp:latest
```

### Migration Script

```bash
#!/bin/bash
# scripts/migrate-to-rvf.sh

echo "Migrating FerroCrate AI to RVF backend..."

# Backup current data
cp -r ~/.ferrocrate/ai-data ~/.ferrocrate/ai-data.backup

# Convert legacy data to RVF
ferrocrate ai-migrate \
  --source ~/.ferrocrate/ai-data \
  --target ~/.ferrocrate/models

# Verify migration
ferrocrate ai-stats ~/.ferrocrate/models/*.rvf

echo "Migration complete. Backup at: ~/.ferrocrate/ai-data.backup"
```

---

## Rollback Plan

### Rollback Trigger Conditions

1. **Performance regression >20%** in query latency
2. **Stability issues:** >5% crash rate increase
3. **Data loss:** Any corruption of trained models
4. **User feedback:** Negative impact on UX

### Rollback Procedure

**Step 1: Switch to legacy backend**

```bash
# Update config
ferrocrate config set ai.backend legacy

# Restart runtime
systemctl restart ferrocrate
```

**Step 2: Restore backup data**

```bash
# If RVF data is corrupted
rm -rf ~/.ferrocrate/models
cp -r ~/.ferrocrate/ai-data.backup ~/.ferrocrate/ai-data
```

**Step 3: Downgrade crate**

```toml
# Cargo.toml
[dependencies]
ferro-mind = { version = "0.1", default-features = false, features = ["legacy-memory"] }
```

### Monitoring & Alerts

```rust
// Monitoring hook in ferro-mind
pub fn report_rvf_health() {
    let metrics = RvfHealthMetrics {
        query_latency_p95: measure_query_latency(),
        insert_latency_p95: measure_insert_latency(),
        file_corruption_detected: check_file_integrity(),
        memory_usage_mb: get_memory_usage(),
    };

    if metrics.query_latency_p95 > LATENCY_THRESHOLD {
        log::warn!("RVF query latency high: {}ms", metrics.query_latency_p95);
    }

    if metrics.file_corruption_detected {
        log::error!("RVF file corruption detected! Switching to legacy backend.");
        switch_to_legacy_backend();
    }
}
```

---

## Success Criteria

### Phase 1 (Core Integration)
- ✅ RVF-backed VectorMemory passes all unit tests
- ✅ Backward compatibility maintained (legacy flag works)
- ✅ Benchmark: Query latency <10ms for 100k vectors
- ✅ Benchmark: Insert throughput >1000 vectors/sec
- ✅ No data loss on abnormal shutdown

### Phase 2 (CLI & Training)
- ✅ CLI commands documented and tested
- ✅ Training pipeline handles 1M+ examples
- ✅ Export/import cycle preserves 100% of data
- ✅ User documentation complete

### Phase 3 (Advanced Features)
- ✅ CoW branching reduces storage by 60%+
- ✅ Cryptographic lineage verifiable
- ✅ Image deduplication improves by 20%+
- ✅ Community marketplace functional

---

## Appendix: Code Examples

### Example 1: Simple Resource Predictor

```rust
use ferro_mind::ai::{ResourcePredictor, VectorMemory};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load persistent model
    let mut predictor = ResourcePredictor::new(PredictorConfig {
        data_dir: PathBuf::from("/var/lib/ferrocrate/models"),
        model_name: "resource-prediction.rvf".to_string(),
        dimensions: 128,
    })?;

    // Learn from completed containers
    for container in past_containers {
        predictor.learn_from_container(&container)?;
    }

    // Predict for new container
    let prediction = predictor.predict(&new_container_info);

    println!("Predicted memory: {} MB", prediction.memory_mb);
    println!("Confidence: {:.2}%", prediction.confidence * 100.0);

    Ok(())
}
```

### Example 2: Crash Predictor Training

```bash
# Generate training data
ferrocrate ps --all --format json \
  | jq -c '{id:.id, metrics:.stats, metadata:{crashed:(.exit_code != 0)}}' \
  > crash-training.jsonl

# Train model
ferrocrate ai-train \
  --input crash-training.jsonl \
  --output crash-predictor.rvf \
  --dimension 64 \
  --model-type crash-prediction

# Use model
ferrocrate run --ai-model crash-predictor.rvf myapp:latest
```

### Example 3: Community Model Sharing

```bash
# Publish model to community
ferrocrate ai-publish \
  --model my-optimized-resource.rvf \
  --name "edge-optimized-resource-predictor" \
  --description "Optimized for ARM edge devices" \
  --tags edge,arm64,resource-prediction

# Download community model
ferrocrate ai-download \
  --name edge-optimized-resource-predictor \
  --output ~/.ferrocrate/models/

# Use downloaded model
ferrocrate config set ai.resource_model edge-optimized-resource-predictor
```

---

## Timeline Summary

| Phase | Duration | Start | End | Dependencies |
|-------|----------|-------|-----|--------------|
| Phase 1 | 2 weeks | Week 1 | Week 2 | None |
| Phase 2 | 2 weeks | Week 3 | Week 4 | Phase 1 |
| Phase 3 | 3 weeks | Week 5 | Week 7 | Phase 2 |
| Testing | 1 week | Week 7 | Week 8 | Phase 3 |
| Documentation | Concurrent | Week 1 | Week 8 | All phases |

**Total Duration:** 8 weeks

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Performance regression | Medium | High | Extensive benchmarking, feature flag rollback |
| RVF API instability | Low | Medium | Vendor closely with rUv team |
| Data corruption | Low | Critical | Checksums, backup strategy, graceful degradation |
| User adoption slow | Medium | Low | Strong documentation, backward compatibility |
| Dependency bloat | Low | Medium | Feature flags, optional dependencies |

---

## References

- [RVF Documentation](https://github.com/ruvnet/ruvector/blob/main/crates/rvf/README.md)
- [FerroCrate Architecture](./architecture.md)
- [AI/ML Integration Guide](./ai-integration.md)
- [Performance Benchmarks](./benchmarks.md)

---

**Document Control**

- **Last Review:** 2026-02-14
- **Next Review:** 2026-03-14
- **Approval Required:** Engineering Lead, Product Owner
- **Status:** Draft → Review → Approved → In Progress
