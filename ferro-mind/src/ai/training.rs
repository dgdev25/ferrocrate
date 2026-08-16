//! Model Training Pipeline (Task 5.4)
//!
//! Provides offline and online training for AI models:
//! - Offline training via CLI command
//! - Online learning via background process (opt-in)
//! - Model versioning and rollback support

#[cfg(feature = "rvf-persistence")]
use crate::ruv::embeddings::{EmbeddingProvider, HashEmbedding};
#[cfg(feature = "rvf-persistence")]
use rvf_runtime::options::DistanceMetric as RvfDistanceMetric;
#[cfg(feature = "rvf-persistence")]
use rvf_runtime::{RvfOptions, RvfStore};
use serde::de::DeserializeOwned;
use serde_json::Value;
use sha2::{Digest, Sha256};
#[cfg(feature = "rvf-persistence")]
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, VecDeque};
use std::fs::{self, File};
#[cfg(feature = "rvf-persistence")]
use std::hash::{Hash, Hasher};
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Model types that can be trained
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModelType {
    /// Resource usage predictor (Task 5.1)
    ResourcePredictor,
    /// Anomaly detector (Task 5.2)
    AnomalyDetector,
    /// Adaptive restart policy (Task 5.3)
    RestartPolicy,
}

impl std::fmt::Display for ModelType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModelType::ResourcePredictor => write!(f, "resource-predictor"),
            ModelType::AnomalyDetector => write!(f, "anomaly-detector"),
            ModelType::RestartPolicy => write!(f, "restart-policy"),
        }
    }
}

impl std::str::FromStr for ModelType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Security: Limit input length to prevent DoS and log injection
        let truncated: String = s.chars().take(32).collect();
        // Remove control characters to prevent log injection
        let sanitized: String = truncated.chars().filter(|c| !c.is_control()).collect();

        match sanitized.as_str() {
            "resource-predictor" => Ok(ModelType::ResourcePredictor),
            "anomaly-detector" => Ok(ModelType::AnomalyDetector),
            "restart-policy" => Ok(ModelType::RestartPolicy),
            _ => Err(format!(
                "Unknown model type: '{}'. Valid: resource-predictor, anomaly-detector, restart-policy",
                sanitized
            )),
        }
    }
}

/// Model version metadata
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ModelVersion {
    /// Model type
    pub model_type: String,
    /// Version number (incremental)
    pub version: u32,
    /// When the model was trained
    pub trained_at: String,
    /// Number of training samples used
    pub samples_count: usize,
    /// Training loss (if applicable)
    pub loss: Option<f32>,
    /// Path to the model file
    pub path: PathBuf,
    /// SHA-256 digest of the exact artifact bytes selected by the router.
    /// Empty values are retained only for pre-digest metadata and cannot be
    /// returned by `resolve_active_model`.
    #[serde(default)]
    pub artifact_sha256: String,
    /// Whether this is the active model
    pub active: bool,
}

/// Training configuration
#[derive(Debug, Clone)]
pub struct TrainingConfig {
    /// Directory to store models
    pub models_dir: PathBuf,
    /// Directory containing training data
    pub data_dir: PathBuf,
    /// Enable online learning
    pub online_learning: bool,
    /// Interval for online learning updates
    pub online_interval: Duration,
    /// Maximum versions to keep
    pub max_versions: usize,
    /// Minimum samples required for training
    pub min_samples: usize,
    /// Maximum relative loss regression accepted when activating a candidate.
    pub max_loss_regression: f32,
    /// Explicit operator consent for durable training-data collection.
    pub data_collection_consent: bool,
}

impl Default for TrainingConfig {
    fn default() -> Self {
        Self {
            models_dir: dirs::data_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".ferrocrate")
                .join("models"),
            data_dir: dirs::data_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".ferrocrate")
                .join("metrics"),
            online_learning: false,
            online_interval: Duration::from_secs(300), // 5 minutes
            max_versions: 10,
            min_samples: 100,
            max_loss_regression: 0.25,
            data_collection_consent: std::env::var("FERROCRATE_AI_DATA_COLLECTION")
                .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "True"))
                .unwrap_or(false),
        }
    }
}

/// Training result
#[derive(Debug, Clone)]
pub struct TrainingResult {
    /// Model type trained
    pub model_type: ModelType,
    /// New version number
    pub version: u32,
    /// Number of samples used
    pub samples_used: usize,
    /// Training duration
    pub duration: Duration,
    /// Final loss (if applicable)
    pub loss: Option<f32>,
    /// Path to saved model
    pub model_path: PathBuf,
}

/// Summary stats for a model family.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ModelStats {
    pub model_type: String,
    pub versions: usize,
    pub total_samples: usize,
    pub active_version: Option<u32>,
    pub active_path: Option<PathBuf>,
    pub last_trained_at: Option<String>,
}

/// Immutable model selection returned to runtime consumers. The artifact is
/// rehashed during resolution so a replaced file cannot silently inherit an
/// authorized version number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutedModel {
    pub model_type: ModelType,
    pub version: u32,
    pub path: PathBuf,
    pub artifact_sha256: String,
}

/// Stats for a direct RVF file inspection.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RvfFileStats {
    pub path: PathBuf,
    pub dimensions: u16,
    pub total_vectors: u64,
    pub total_segments: u32,
    pub file_size: u64,
    pub epoch: u32,
    pub profile_id: u8,
    pub compaction_state: String,
    pub dead_space_ratio: f64,
    pub read_only: bool,
    pub file_id_hex: String,
    pub parent_id_hex: String,
    pub lineage_depth: u32,
}

/// Lineage metadata for a single RVF file.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RvfLineage {
    pub path: PathBuf,
    pub file_id_hex: String,
    pub parent_id_hex: String,
    pub lineage_depth: u32,
    pub is_root: bool,
}

/// Verification report for RVF lineage + storage invariants.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RvfVerificationReport {
    pub path: PathBuf,
    pub verified: bool,
    pub checks: Vec<String>,
    pub file_id_hex: String,
    pub parent_id_hex: String,
    pub lineage_depth: u32,
    pub is_root: bool,
    pub parent_path: Option<PathBuf>,
    pub parent_match: Option<bool>,
}

/// Marketplace metadata for a shared community model.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CommunityModel {
    pub name: String,
    pub description: String,
    pub tags: Vec<String>,
    pub artifact: PathBuf,
    pub size_bytes: u64,
    pub published_at: String,
    pub file_id_hex: String,
    pub lineage_depth: u32,
}

/// Error type for training operations
#[derive(Debug, thiserror::Error)]
pub enum TrainingError {
    #[error("AI features disabled. Set FERROCRATE_AI=1 to enable.")]
    AiDisabled,

    #[error("Insufficient training data: {0} samples, need at least {1}")]
    InsufficientData(usize, usize),

    #[error("Model type not found: {0}")]
    ModelNotFound(String),

    #[error("Data directory not found: {0}")]
    DataDirNotFound(PathBuf),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Training failed: {0}")]
    TrainingFailed(String),

    #[error("No active model for rollback")]
    NoActiveModel,

    #[error("invalid model version history: {0}")]
    InvalidVersionHistory(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("model loss regression exceeds activation gate: previous={previous:.6}, candidate={candidate:.6}")]
    LossRegression { previous: f32, candidate: f32 },

    #[error("training sample exceeds the {0}-byte limit")]
    SampleTooLarge(usize),

    #[error("training-data collection requires explicit operator consent")]
    DataCollectionDisabled,
}

impl From<String> for TrainingError {
    fn from(s: String) -> Self {
        TrainingError::ParseError(s)
    }
}

/// Training sample for resource predictor
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ResourceSample {
    pub cpu_percent: f32,
    pub memory_bytes: u64,
    pub pids_count: u64,
    pub timestamp_secs: u64,
}

/// Training sample for anomaly detector
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AnomalySample {
    pub features: Vec<f32>,
    pub is_anomaly: bool,
    pub container_id: String,
}

/// Training sample for restart policy
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RestartSample {
    pub exit_code: i32,
    pub uptime_secs: u64,
    pub restart_success: bool,
    pub container_id: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
struct OnlineLearningState {
    sample_counts: HashMap<String, usize>,
}

#[derive(Debug, Clone)]
struct TrainedModel {
    loss: f32,
    artifact: Value,
}

fn artifact_sha256(path: &Path) -> Result<String, TrainingError> {
    let bytes = fs::read(path)?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

/// Model training pipeline
pub struct TrainingPipeline {
    config: TrainingConfig,
    versions: HashMap<ModelType, VecDeque<ModelVersion>>,
    online_running: Arc<AtomicBool>,
    online_sample_cursor: HashMap<ModelType, usize>,
    online_retrain_delta: usize,
}

impl TrainingPipeline {
    /// Create a new training pipeline
    pub fn new(config: TrainingConfig) -> Result<Self, TrainingError> {
        let mut pipeline = Self {
            config,
            versions: HashMap::new(),
            online_running: Arc::new(AtomicBool::new(false)),
            online_sample_cursor: HashMap::new(),
            online_retrain_delta: 1,
        };
        pipeline.online_retrain_delta = (pipeline.config.min_samples / 2).max(1);
        pipeline.load_version_history()?;
        pipeline.load_online_state()?;
        Ok(pipeline)
    }

    /// Check if AI is enabled
    pub fn is_ai_enabled() -> bool {
        std::env::var("FERROCRATE_AI")
            .map(|v| v == "1" || v == "true")
            .unwrap_or(false)
    }

    /// Load version history from disk
    fn load_version_history(&mut self) -> Result<(), TrainingError> {
        for model_type in [
            ModelType::ResourcePredictor,
            ModelType::AnomalyDetector,
            ModelType::RestartPolicy,
        ] {
            let versions = self.load_versions_for_model(model_type)?;
            self.versions.insert(model_type, versions);
        }
        Ok(())
    }

    /// Load versions for a specific model type
    fn load_versions_for_model(
        &self,
        model_type: ModelType,
    ) -> Result<VecDeque<ModelVersion>, TrainingError> {
        let versions_file = self
            .config
            .models_dir
            .join(model_type.to_string())
            .join("versions.json");

        if versions_file.exists() {
            let file = File::open(&versions_file)?;
            let reader = BufReader::new(file);
            let versions: Vec<ModelVersion> = serde_json::from_reader(reader)?;
            let mut seen = std::collections::HashSet::new();
            let mut active = 0usize;
            for version in &versions {
                if version.model_type != model_type.to_string() {
                    return Err(TrainingError::InvalidVersionHistory(format!(
                        "{} contains {} metadata",
                        versions_file.display(),
                        version.model_type
                    )));
                }
                if version.version == 0 || !seen.insert(version.version) {
                    return Err(TrainingError::InvalidVersionHistory(format!(
                        "duplicate or zero version in {}",
                        versions_file.display()
                    )));
                }
                if version.active {
                    active += 1;
                    if !version.path.is_file() {
                        return Err(TrainingError::InvalidVersionHistory(format!(
                            "active artifact is missing: {}",
                            version.path.display()
                        )));
                    }
                }
            }
            if active > 1 {
                return Err(TrainingError::InvalidVersionHistory(format!(
                    "multiple active versions in {}",
                    versions_file.display()
                )));
            }
            Ok(versions.into_iter().collect())
        } else {
            Ok(VecDeque::new())
        }
    }

    /// Save version history to disk
    fn save_versions(&self, model_type: ModelType) -> Result<(), TrainingError> {
        if let Some(versions) = self.versions.get(&model_type) {
            let dir = self.config.models_dir.join(model_type.to_string());
            fs::create_dir_all(&dir)?;

            let versions_file = dir.join("versions.json");
            let temporary = dir.join("versions.json.tmp");
            let file = File::create(&temporary)?;
            let mut writer = BufWriter::new(file);
            serde_json::to_writer_pretty(&mut writer, versions)?;
            writer.flush()?;
            writer.get_ref().sync_all()?;
            fs::rename(&temporary, &versions_file)?;
            File::open(dir)?.sync_all()?;
        }
        Ok(())
    }

    fn online_state_path(&self) -> PathBuf {
        self.config.models_dir.join("online-learning-state.json")
    }

    fn load_online_state(&mut self) -> Result<(), TrainingError> {
        let path = self.online_state_path();
        if !path.exists() {
            return Ok(());
        }
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let state: OnlineLearningState = serde_json::from_reader(reader)?;
        for (model, count) in state.sample_counts {
            if let Ok(model_type) = model.parse::<ModelType>() {
                self.online_sample_cursor.insert(model_type, count);
            }
        }
        Ok(())
    }

    fn save_online_state(&self) -> Result<(), TrainingError> {
        let path = self.online_state_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut sample_counts = HashMap::new();
        for (model_type, count) in &self.online_sample_cursor {
            sample_counts.insert(model_type.to_string(), *count);
        }
        let state = OnlineLearningState { sample_counts };
        let file = File::create(path)?;
        serde_json::to_writer_pretty(BufWriter::new(file), &state)?;
        Ok(())
    }

    fn sample_count_for_model(&self, model_type: ModelType) -> Result<usize, TrainingError> {
        let data_dir = self.config.data_dir.join(model_type.to_string());
        if !data_dir.exists() {
            return Ok(0);
        }
        let mut total = 0usize;
        for entry in fs::read_dir(data_dir)? {
            let path = entry?.path();
            if path.extension().is_some_and(|e| e == "json") {
                total += 1;
            }
        }
        Ok(total)
    }

    /// Train a model from data directory
    pub fn train(&mut self, model_type: ModelType) -> Result<TrainingResult, TrainingError> {
        if !Self::is_ai_enabled() {
            return Err(TrainingError::AiDisabled);
        }

        let start = Instant::now();

        // Load training data
        let data_path = self.config.data_dir.join(model_type.to_string());
        if !data_path.exists() {
            return Err(TrainingError::DataDirNotFound(data_path));
        }

        let samples = self.load_training_data(&data_path)?;

        if samples.len() < self.config.min_samples {
            return Err(TrainingError::InsufficientData(
                samples.len(),
                self.config.min_samples,
            ));
        }

        // Perform training (simplified - in production would use ruv-fann/tract)
        let trained = self.train_model(model_type, &samples)?;

        // Create new version
        let version = self.get_next_version(model_type);
        let model_path = self
            .config
            .models_dir
            .join(model_type.to_string())
            .join(format!("model_v{}.bin", version));

        // Save model (placeholder - actual serialization depends on model type)
        self.save_model(&model_path, model_type, &trained)?;

        if let Some(previous) = self
            .get_active_version(model_type)
            .and_then(|version| version.loss)
        {
            let allowed = previous * (1.0 + self.config.max_loss_regression.max(0.0));
            if trained.loss > allowed {
                let _ = fs::remove_file(&model_path);
                return Err(TrainingError::LossRegression {
                    previous,
                    candidate: trained.loss,
                });
            }
        }

        // Update version history
        let model_version = ModelVersion {
            model_type: model_type.to_string(),
            version,
            trained_at: chrono::Utc::now().to_rfc3339(),
            samples_count: samples.len(),
            loss: Some(trained.loss),
            path: model_path.clone(),
            artifact_sha256: artifact_sha256(&model_path)?,
            active: true,
        };

        // Deactivate previous versions
        if let Some(versions) = self.versions.get_mut(&model_type) {
            for v in versions.iter_mut() {
                v.active = false;
            }
            versions.push_back(model_version);

            // Prune old versions
            while versions.len() > self.config.max_versions {
                // CQ-01: Safe to unwrap because we check len() > max_versions >= 1
                let removed = versions.pop_front().expect("versions should not be empty");
                let _ = fs::remove_file(&removed.path);
            }
        } else {
            self.versions
                .insert(model_type, VecDeque::from(vec![model_version]));
        }

        self.save_versions(model_type)?;

        Ok(TrainingResult {
            model_type,
            version,
            samples_used: samples.len(),
            duration: start.elapsed(),
            loss: Some(trained.loss),
            model_path,
        })
    }

    /// Load training data from directory
    fn load_training_data(&self, data_path: &Path) -> Result<Vec<Vec<u8>>, TrainingError> {
        let mut samples = Vec::new();

        if !data_path.exists() {
            return Ok(samples);
        }

        for entry in fs::read_dir(data_path)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().is_some_and(|e| e == "json") {
                let data = fs::read(&path)?;
                samples.push(data);
            }
        }

        Ok(samples)
    }

    /// Train model (lightweight implementation with real metrics)
    fn train_model(
        &self,
        model_type: ModelType,
        samples: &[Vec<u8>],
    ) -> Result<TrainedModel, TrainingError> {
        match model_type {
            ModelType::ResourcePredictor => train_resource_predictor(samples),
            ModelType::AnomalyDetector => train_anomaly_detector(samples),
            ModelType::RestartPolicy => train_restart_policy(samples),
        }
    }

    fn parse_samples<T: DeserializeOwned>(samples: &[Vec<u8>]) -> Result<Vec<T>, TrainingError> {
        let mut out = Vec::with_capacity(samples.len());
        for sample in samples {
            let parsed = serde_json::from_slice::<T>(sample)
                .map_err(|err| TrainingError::ParseError(format!("invalid sample json: {err}")))?;
            out.push(parsed);
        }
        Ok(out)
    }

    /// Save model to disk
    fn save_model(
        &self,
        path: &Path,
        model_type: ModelType,
        model: &TrainedModel,
    ) -> Result<(), TrainingError> {
        // CQ-01: Handle paths without parent directory
        let parent = path.parent().ok_or_else(|| {
            TrainingError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "path has no parent directory",
            ))
        })?;
        fs::create_dir_all(parent)?;

        let metadata = serde_json::json!({
            "model_type": model_type.to_string(),
            "created_at": chrono::Utc::now().to_rfc3339(),
            "loss": model.loss,
            "artifact": model.artifact,
        });

        let file = File::create(path)?;
        serde_json::to_writer(file, &metadata)?;

        Ok(())
    }

    /// Get next version number for a model
    fn get_next_version(&self, model_type: ModelType) -> u32 {
        self.versions
            .get(&model_type)
            .and_then(|v| v.back().map(|last| last.version + 1))
            .unwrap_or(1)
    }

    /// Rollback to previous model version
    pub fn rollback(&mut self, model_type: ModelType) -> Result<ModelVersion, TrainingError> {
        // First, find the index to rollback to
        let rollback_idx = {
            let versions = self
                .versions
                .get(&model_type)
                .ok_or(TrainingError::NoActiveModel)?;
            let active_idx = versions.iter().position(|v| v.active);

            match active_idx {
                Some(idx) if idx > 0 => Some(idx - 1),
                _ => None,
            }
        };

        // Now perform the mutation
        if let Some(target_idx) = rollback_idx {
            // CQ-01: Use expect with context instead of unwrap()
            let versions = self
                .versions
                .get_mut(&model_type)
                .expect("versions should exist (checked above)");

            if !versions[target_idx].path.is_file() {
                return Err(TrainingError::InvalidVersionHistory(format!(
                    "rollback artifact is missing: {}",
                    versions[target_idx].path.display()
                )));
            }

            // Deactivate all and activate target
            for v in versions.iter_mut() {
                v.active = false;
            }
            versions[target_idx].active = true;

            let result = versions[target_idx].clone();
            self.save_versions(model_type)?;

            return Ok(result);
        }

        Err(TrainingError::NoActiveModel)
    }

    /// Get active model version
    pub fn get_active_version(&self, model_type: ModelType) -> Option<&ModelVersion> {
        self.versions.get(&model_type)?.iter().find(|v| v.active)
    }

    /// Resolve the active model only when its persisted digest matches the
    /// current artifact. Callers receive a value that is safe to bind into a
    /// runtime decision or authorization fact; missing legacy digests fail
    /// closed until the model is retrained or explicitly imported again.
    pub fn resolve_active_model(
        &self,
        model_type: ModelType,
    ) -> Result<RoutedModel, TrainingError> {
        let active = self
            .get_active_version(model_type)
            .ok_or_else(|| TrainingError::ModelNotFound(model_type.to_string()))?;
        if active.artifact_sha256.is_empty() {
            return Err(TrainingError::InvalidVersionHistory(format!(
                "active model v{} has no artifact digest",
                active.version
            )));
        }
        let observed = artifact_sha256(&active.path)?;
        if observed != active.artifact_sha256 {
            return Err(TrainingError::InvalidVersionHistory(format!(
                "active model v{} artifact digest mismatch",
                active.version
            )));
        }
        Ok(RoutedModel {
            model_type,
            version: active.version,
            path: active.path.clone(),
            artifact_sha256: active.artifact_sha256.clone(),
        })
    }

    /// List all versions for a model
    pub fn list_versions(&self, model_type: ModelType) -> Vec<&ModelVersion> {
        self.versions
            .get(&model_type)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Start online learning background process
    pub fn start_online_learning(&mut self) -> Result<(), TrainingError> {
        if !self.config.online_learning {
            return Ok(());
        }

        self.online_running.store(true, Ordering::SeqCst);
        let _ = self.run_online_learning_cycle()?;
        Ok(())
    }

    /// Stop online learning
    pub fn stop_online_learning(&self) {
        self.online_running.store(false, Ordering::SeqCst);
    }

    /// Check if online learning is running
    pub fn is_online_learning(&self) -> bool {
        self.online_running.load(Ordering::SeqCst)
    }

    /// Run one online learning cycle and retrain models with enough new data.
    pub fn run_online_learning_cycle(&mut self) -> Result<Vec<TrainingResult>, TrainingError> {
        if !self.config.online_learning || !self.is_online_learning() {
            return Ok(Vec::new());
        }
        let mut trained = Vec::new();
        for model_type in [
            ModelType::ResourcePredictor,
            ModelType::AnomalyDetector,
            ModelType::RestartPolicy,
        ] {
            let current_samples = self.sample_count_for_model(model_type)?;
            let seen_samples = self
                .online_sample_cursor
                .get(&model_type)
                .copied()
                .unwrap_or(0);

            if current_samples < seen_samples {
                self.online_sample_cursor
                    .insert(model_type, current_samples);
                continue;
            }
            let new_samples = current_samples.saturating_sub(seen_samples);
            if current_samples >= self.config.min_samples
                && new_samples >= self.online_retrain_delta
            {
                match self.train(model_type) {
                    Ok(result) => {
                        trained.push(result);
                        self.online_sample_cursor
                            .insert(model_type, current_samples);
                    }
                    Err(TrainingError::InsufficientData(_, _)) | Err(TrainingError::AiDisabled) => {
                    }
                    Err(err) => return Err(err),
                }
            }
        }
        self.save_online_state()?;
        Ok(trained)
    }

    /// Record a training sample for later use
    pub fn record_sample(
        &mut self,
        model_type: ModelType,
        sample: &[u8],
    ) -> Result<(), TrainingError> {
        if !self.config.data_collection_consent {
            return Err(TrainingError::DataCollectionDisabled);
        }
        const MAX_SAMPLE_BYTES: usize = 1 << 20;
        if sample.len() > MAX_SAMPLE_BYTES {
            return Err(TrainingError::SampleTooLarge(MAX_SAMPLE_BYTES));
        }
        // Validate the concrete schema before the sample can become durable;
        // arbitrary JSON must not enter an online-learning corpus.
        match model_type {
            ModelType::ResourcePredictor => {
                Self::parse_samples::<ResourceSample>(&[sample.to_vec()])?;
            }
            ModelType::AnomalyDetector => {
                Self::parse_samples::<AnomalySample>(&[sample.to_vec()])?;
            }
            ModelType::RestartPolicy => {
                Self::parse_samples::<RestartSample>(&[sample.to_vec()])?;
            }
        };
        let data_dir = self.config.data_dir.join(model_type.to_string());
        fs::create_dir_all(&data_dir)?;

        let digest = format!("{:x}", Sha256::digest(sample));
        let filename = format!("sample_{digest}.json");
        let path = data_dir.join(filename);
        if !path.exists() {
            let temporary = data_dir.join(format!(".{digest}.tmp"));
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)?;
            use std::io::Write as _;
            file.write_all(sample)?;
            file.sync_all()?;
            fs::rename(&temporary, &path)?;
            File::open(&data_dir)?.sync_all()?;
        }
        if self.is_online_learning() && self.config.online_learning {
            let _ = self.run_online_learning_cycle()?;
        }

        Ok(())
    }

    /// Delete one content-addressed sample. Deletion is intentionally allowed
    /// even when collection consent is disabled so an operator can honor a
    /// retention or erasure request after turning collection off.
    pub fn delete_sample(
        &self,
        model_type: ModelType,
        digest: &str,
    ) -> Result<bool, TrainingError> {
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(TrainingError::ParseError(
                "sample digest must be exactly 64 hexadecimal characters".to_string(),
            ));
        }
        let path = self
            .config
            .data_dir
            .join(model_type.to_string())
            .join(format!("sample_{digest}.json"));
        match fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(TrainingError::Io(error)),
        }
    }

    /// Retain at most `max_samples` corpus files, removing the oldest by
    /// filesystem modification time with a path tie-breaker for deterministic
    /// behavior. Returns the number removed.
    pub fn prune_samples(
        &self,
        model_type: ModelType,
        max_samples: usize,
    ) -> Result<usize, TrainingError> {
        let data_dir = self.config.data_dir.join(model_type.to_string());
        let mut entries = fs::read_dir(&data_dir)
            .map_err(TrainingError::Io)?
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .is_some_and(|extension| extension == "json")
            })
            .map(|entry| {
                let path = entry.path();
                let modified = entry
                    .metadata()
                    .and_then(|metadata| metadata.modified())
                    .unwrap_or(std::time::UNIX_EPOCH);
                (modified, path)
            })
            .collect::<Vec<_>>();
        if entries.len() <= max_samples {
            return Ok(0);
        }
        entries.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
        let remove_count = entries.len() - max_samples;
        for (_, path) in entries.into_iter().take(remove_count) {
            fs::remove_file(path)?;
        }
        File::open(&data_dir)?.sync_all()?;
        Ok(remove_count)
    }
}

fn train_resource_predictor(samples: &[Vec<u8>]) -> Result<TrainedModel, TrainingError> {
    let parsed = TrainingPipeline::parse_samples::<ResourceSample>(samples)?;
    if parsed.is_empty() {
        return Err(TrainingError::InsufficientData(0, 1));
    }
    let max_mem = parsed
        .iter()
        .map(|s| s.memory_bytes)
        .max()
        .unwrap_or(1)
        .max(1) as f32;
    let max_pids = parsed
        .iter()
        .map(|s| s.pids_count)
        .max()
        .unwrap_or(1)
        .max(1) as f32;
    let mut mean_cpu = 0.0f32;
    let mut mean_mem = 0.0f32;
    let mut mean_pids = 0.0f32;
    for sample in &parsed {
        mean_cpu += (sample.cpu_percent / 100.0).clamp(0.0, 1.0);
        mean_mem += (sample.memory_bytes as f32 / max_mem).clamp(0.0, 1.0);
        mean_pids += (sample.pids_count as f32 / max_pids).clamp(0.0, 1.0);
    }
    let count = parsed.len() as f32;
    mean_cpu /= count;
    mean_mem /= count;
    mean_pids /= count;

    let mut mse = 0.0f32;
    for sample in &parsed {
        let cpu = (sample.cpu_percent / 100.0).clamp(0.0, 1.0);
        let mem = (sample.memory_bytes as f32 / max_mem).clamp(0.0, 1.0);
        let pids = (sample.pids_count as f32 / max_pids).clamp(0.0, 1.0);
        let err = (cpu - mean_cpu).powi(2) + (mem - mean_mem).powi(2) + (pids - mean_pids).powi(2);
        mse += err / 3.0;
    }
    let loss = mse / count;

    Ok(TrainedModel {
        loss,
        artifact: serde_json::json!({
            "feature_means": {
                "cpu_norm": mean_cpu,
                "mem_norm": mean_mem,
                "pids_norm": mean_pids
            },
            "feature_maxes": {
                "memory_bytes": max_mem,
                "pids_count": max_pids
            },
            "samples": parsed.len()
        }),
    })
}

fn train_anomaly_detector(samples: &[Vec<u8>]) -> Result<TrainedModel, TrainingError> {
    let parsed = TrainingPipeline::parse_samples::<AnomalySample>(samples)?;
    if parsed.is_empty() {
        return Err(TrainingError::InsufficientData(0, 1));
    }
    let normals: Vec<_> = parsed.iter().filter(|s| !s.is_anomaly).collect();
    if normals.is_empty() {
        return Err(TrainingError::TrainingFailed(
            "anomaly-detector requires at least one normal sample".to_string(),
        ));
    }
    let feature_len = normals[0].features.len();
    if feature_len == 0 {
        return Err(TrainingError::TrainingFailed(
            "anomaly-detector features cannot be empty".to_string(),
        ));
    }
    let mut centroid = vec![0.0f32; feature_len];
    for sample in &normals {
        if sample.features.len() != feature_len {
            return Err(TrainingError::TrainingFailed(
                "inconsistent feature lengths in anomaly samples".to_string(),
            ));
        }
        for (idx, value) in sample.features.iter().enumerate() {
            centroid[idx] += *value;
        }
    }
    let normal_count = normals.len() as f32;
    for value in &mut centroid {
        *value /= normal_count;
    }

    let mut normal_dist_sum = 0.0f32;
    for sample in &normals {
        normal_dist_sum += euclidean_distance(&centroid, &sample.features);
    }
    let normal_mean = normal_dist_sum / normal_count;

    let anomalies: Vec<_> = parsed.iter().filter(|s| s.is_anomaly).collect();
    let anomaly_mean = if anomalies.is_empty() {
        0.0
    } else {
        let mut sum = 0.0f32;
        for sample in &anomalies {
            if sample.features.len() != feature_len {
                return Err(TrainingError::TrainingFailed(
                    "inconsistent feature lengths in anomaly samples".to_string(),
                ));
            }
            sum += euclidean_distance(&centroid, &sample.features);
        }
        sum / anomalies.len() as f32
    };

    Ok(TrainedModel {
        loss: normal_mean,
        artifact: serde_json::json!({
            "centroid": centroid,
            "normal_mean_distance": normal_mean,
            "anomaly_mean_distance": anomaly_mean,
            "separation": anomaly_mean - normal_mean,
            "normal_samples": normals.len(),
            "anomaly_samples": anomalies.len()
        }),
    })
}

fn train_restart_policy(samples: &[Vec<u8>]) -> Result<TrainedModel, TrainingError> {
    let parsed = TrainingPipeline::parse_samples::<RestartSample>(samples)?;
    if parsed.is_empty() {
        return Err(TrainingError::InsufficientData(0, 1));
    }
    let mut success = 0usize;
    let mut accuracy_hits = 0usize;
    let mut uptime_success = 0u64;
    let mut uptime_failure = 0u64;
    let mut success_zero = 0usize;
    let mut total_zero = 0usize;
    let mut success_nonzero = 0usize;
    let mut total_nonzero = 0usize;
    for sample in &parsed {
        if sample.restart_success {
            success += 1;
            uptime_success = uptime_success.saturating_add(sample.uptime_secs);
        } else {
            uptime_failure = uptime_failure.saturating_add(sample.uptime_secs);
        }
        let predicted = sample.exit_code == 0;
        if predicted == sample.restart_success {
            accuracy_hits += 1;
        }
        if sample.exit_code == 0 {
            total_zero += 1;
            if sample.restart_success {
                success_zero += 1;
            }
        } else {
            total_nonzero += 1;
            if sample.restart_success {
                success_nonzero += 1;
            }
        }
    }
    let count = parsed.len() as f32;
    let success_rate = success as f32 / count;
    let accuracy = accuracy_hits as f32 / count;
    let avg_uptime_success = if success == 0 {
        0.0
    } else {
        uptime_success as f32 / success as f32
    };
    let failures = parsed.len().saturating_sub(success);
    let avg_uptime_failure = if failures == 0 {
        0.0
    } else {
        uptime_failure as f32 / failures as f32
    };

    Ok(TrainedModel {
        loss: 1.0 - accuracy,
        artifact: serde_json::json!({
            "success_rate": success_rate,
            "baseline_accuracy": accuracy,
            "avg_uptime_success": avg_uptime_success,
            "avg_uptime_failure": avg_uptime_failure,
            "exit_code_success": {
                "zero": {
                    "success": success_zero,
                    "total": total_zero
                },
                "nonzero": {
                    "success": success_nonzero,
                    "total": total_nonzero
                }
            },
            "samples": parsed.len()
        }),
    })
}

fn euclidean_distance(a: &[f32], b: &[f32]) -> f32 {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x - y) * (x - y))
        .sum::<f32>()
        .sqrt()
}

/// CLI command handler for training
pub fn handle_train_command(
    model_type: &str,
    data_dir: Option<&Path>,
    models_dir: Option<&Path>,
) -> Result<TrainingResult, TrainingError> {
    let model_type: ModelType = model_type.parse()?;

    let mut config = TrainingConfig::default();
    if let Some(dir) = data_dir {
        config.data_dir = dir.to_path_buf();
    }
    if let Some(dir) = models_dir {
        config.models_dir = dir.to_path_buf();
    }

    let mut pipeline = TrainingPipeline::new(config)?;
    pipeline.train(model_type)
}

/// Export active model version to a target file path.
pub fn handle_export_command(
    model_type: &str,
    output: &Path,
    models_dir: Option<&Path>,
) -> Result<PathBuf, TrainingError> {
    let model_type: ModelType = model_type.parse()?;
    let mut config = TrainingConfig::default();
    if let Some(dir) = models_dir {
        config.models_dir = dir.to_path_buf();
    }

    let pipeline = TrainingPipeline::new(config)?;
    let active = pipeline.resolve_active_model(model_type)?;

    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(&active.path, output)?;
    Ok(output.to_path_buf())
}

/// Import a model artifact as a new version.
pub fn handle_import_command(
    model_type: &str,
    input: &Path,
    models_dir: Option<&Path>,
) -> Result<ModelVersion, TrainingError> {
    let model_type: ModelType = model_type.parse()?;
    if !input.exists() {
        return Err(TrainingError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("input file not found: {}", input.display()),
        )));
    }

    let mut config = TrainingConfig::default();
    if let Some(dir) = models_dir {
        config.models_dir = dir.to_path_buf();
    }

    let mut pipeline = TrainingPipeline::new(config)?;
    let version = pipeline.get_next_version(model_type);
    let model_path = pipeline
        .config
        .models_dir
        .join(model_type.to_string())
        .join(format!("model_v{}.bin", version));
    if let Some(parent) = model_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(input, &model_path)?;

    if let Some(versions) = pipeline.versions.get_mut(&model_type) {
        for v in versions.iter_mut() {
            v.active = false;
        }
    }

    let imported_digest = artifact_sha256(&model_path)?;
    let imported = ModelVersion {
        model_type: model_type.to_string(),
        version,
        trained_at: chrono::Utc::now().to_rfc3339(),
        samples_count: 0,
        loss: None,
        path: model_path,
        artifact_sha256: imported_digest,
        active: true,
    };

    pipeline
        .versions
        .entry(model_type)
        .or_default()
        .push_back(imported.clone());
    pipeline.save_versions(model_type)?;

    Ok(imported)
}

/// Return version stats for a model family.
pub fn handle_stats_command(
    model_type: &str,
    models_dir: Option<&Path>,
) -> Result<ModelStats, TrainingError> {
    let model_type: ModelType = model_type.parse()?;
    let mut config = TrainingConfig::default();
    if let Some(dir) = models_dir {
        config.models_dir = dir.to_path_buf();
    }

    let pipeline = TrainingPipeline::new(config)?;
    let versions = pipeline.list_versions(model_type);
    let active = pipeline.get_active_version(model_type);

    Ok(ModelStats {
        model_type: model_type.to_string(),
        versions: versions.len(),
        total_samples: versions.iter().map(|v| v.samples_count).sum(),
        active_version: active.map(|v| v.version),
        active_path: active.map(|v| v.path.clone()),
        last_trained_at: versions.last().map(|v| v.trained_at.clone()),
    })
}

/// List models available in a local community marketplace index.
pub fn handle_community_list_command(
    marketplace_dir: &Path,
) -> Result<Vec<CommunityModel>, TrainingError> {
    let index = marketplace_dir.join("index.json");
    if !index.exists() {
        return Ok(Vec::new());
    }
    let file = File::open(index)?;
    let reader = BufReader::new(file);
    let entries: Vec<CommunityModel> = serde_json::from_reader(reader)?;
    Ok(entries)
}

/// Publish an RVF model into the local community marketplace.
pub fn handle_community_publish_command(
    input: &Path,
    name: &str,
    description: &str,
    tags: &[String],
    marketplace_dir: &Path,
) -> Result<PathBuf, TrainingError> {
    if !input.exists() {
        return Err(TrainingError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("input file not found: {}", input.display()),
        )));
    }
    let models_dir = marketplace_dir.join("models");
    fs::create_dir_all(&models_dir)?;
    let artifact = models_dir.join(format!("{name}.rvf"));
    fs::copy(input, &artifact)?;

    let mut entries = handle_community_list_command(marketplace_dir)?;
    entries.retain(|entry| entry.name != name);

    #[cfg(feature = "rvf-persistence")]
    let (file_id_hex, lineage_depth) = {
        let store = RvfStore::open_readonly(&artifact)
            .map_err(|err| TrainingError::TrainingFailed(err.to_string()))?;
        (bytes_to_hex(store.file_id()), store.lineage_depth())
    };
    #[cfg(not(feature = "rvf-persistence"))]
    let (file_id_hex, lineage_depth) = (String::new(), 0);

    let size_bytes = fs::metadata(&artifact)?.len();
    entries.push(CommunityModel {
        name: name.to_string(),
        description: description.to_string(),
        tags: tags.to_vec(),
        artifact: artifact.clone(),
        size_bytes,
        published_at: chrono::Utc::now().to_rfc3339(),
        file_id_hex,
        lineage_depth,
    });
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    let index = marketplace_dir.join("index.json");
    let file = File::create(index)?;
    serde_json::to_writer_pretty(BufWriter::new(file), &entries)?;
    Ok(artifact)
}

/// Download (copy) a model from the local community marketplace.
pub fn handle_community_download_command(
    name: &str,
    output: &Path,
    marketplace_dir: &Path,
) -> Result<PathBuf, TrainingError> {
    let entries = handle_community_list_command(marketplace_dir)?;
    let entry = entries
        .into_iter()
        .find(|entry| entry.name == name)
        .ok_or_else(|| TrainingError::ModelNotFound(name.to_string()))?;
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(entry.artifact, output)?;
    Ok(output.to_path_buf())
}

#[cfg(feature = "rvf-persistence")]
pub fn handle_rvf_stats_command(path: &Path) -> Result<RvfFileStats, TrainingError> {
    let store = RvfStore::open_readonly(path)
        .map_err(|err| TrainingError::TrainingFailed(err.to_string()))?;
    let status = store.status();
    Ok(RvfFileStats {
        path: path.to_path_buf(),
        dimensions: store.dimension(),
        total_vectors: status.total_vectors,
        total_segments: status.total_segments,
        file_size: status.file_size,
        epoch: status.current_epoch,
        profile_id: status.profile_id,
        compaction_state: format!("{:?}", status.compaction_state),
        dead_space_ratio: status.dead_space_ratio,
        read_only: status.read_only,
        file_id_hex: bytes_to_hex(store.file_id()),
        parent_id_hex: bytes_to_hex(store.parent_id()),
        lineage_depth: store.lineage_depth(),
    })
}

#[cfg(feature = "rvf-persistence")]
pub fn handle_rvf_branch_command(source: &Path, target: &Path) -> Result<PathBuf, TrainingError> {
    if !source.exists() {
        return Err(TrainingError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("source file not found: {}", source.display()),
        )));
    }
    if target.exists() {
        return Err(TrainingError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("target already exists: {}", target.display()),
        )));
    }
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }

    let store = RvfStore::open_readonly(source)
        .map_err(|err| TrainingError::TrainingFailed(err.to_string()))?;
    let child = store
        .branch(target)
        .map_err(|err| TrainingError::TrainingFailed(err.to_string()))?;
    child
        .close()
        .map_err(|err| TrainingError::TrainingFailed(err.to_string()))?;
    Ok(target.to_path_buf())
}

#[cfg(feature = "rvf-persistence")]
pub fn handle_rvf_lineage_command(path: &Path) -> Result<RvfLineage, TrainingError> {
    let store = RvfStore::open_readonly(path)
        .map_err(|err| TrainingError::TrainingFailed(err.to_string()))?;
    let parent = bytes_to_hex(store.parent_id());
    let is_root = parent.chars().all(|ch| ch == '0');
    Ok(RvfLineage {
        path: path.to_path_buf(),
        file_id_hex: bytes_to_hex(store.file_id()),
        parent_id_hex: parent,
        lineage_depth: store.lineage_depth(),
        is_root,
    })
}

#[cfg(feature = "rvf-persistence")]
pub fn handle_rvf_verify_command(
    path: &Path,
    parent_path: Option<&Path>,
) -> Result<RvfVerificationReport, TrainingError> {
    let store = RvfStore::open_readonly(path)
        .map_err(|err| TrainingError::TrainingFailed(err.to_string()))?;
    let status = store.status();
    let file_id = store.file_id();
    let parent_id = store.parent_id();
    let lineage_depth = store.lineage_depth();

    let file_id_hex = bytes_to_hex(file_id);
    let parent_id_hex = bytes_to_hex(parent_id);
    let is_root = parent_id.iter().all(|byte| *byte == 0);

    let mut verified = true;
    let mut checks = Vec::new();

    if file_id.iter().all(|byte| *byte == 0) {
        verified = false;
        checks.push("fail:file_id_non_zero".to_string());
    } else {
        checks.push("ok:file_id_non_zero".to_string());
    }

    if is_root {
        if lineage_depth != 0 {
            verified = false;
            checks.push("fail:root_depth_zero".to_string());
        } else {
            checks.push("ok:root_depth_zero".to_string());
        }
    } else {
        if lineage_depth == 0 {
            verified = false;
            checks.push("fail:non_root_depth_positive".to_string());
        } else {
            checks.push("ok:non_root_depth_positive".to_string());
        }
        if parent_id.iter().all(|byte| *byte == 0) {
            verified = false;
            checks.push("fail:non_root_parent_non_zero".to_string());
        } else {
            checks.push("ok:non_root_parent_non_zero".to_string());
        }
    }

    if !(0.0..=1.0).contains(&status.dead_space_ratio) {
        verified = false;
        checks.push("fail:dead_space_ratio_range".to_string());
    } else {
        checks.push("ok:dead_space_ratio_range".to_string());
    }

    let mut parent_match = None;
    let parent_path_out = parent_path.map(|p| p.to_path_buf());
    if let Some(parent_path) = parent_path {
        let parent_store = RvfStore::open_readonly(parent_path)
            .map_err(|err| TrainingError::TrainingFailed(err.to_string()))?;
        let parent_file_id = parent_store.file_id();
        let ids_match = parent_file_id == parent_id;
        parent_match = Some(ids_match);
        if !ids_match {
            verified = false;
            checks.push("fail:parent_file_id_matches".to_string());
        } else {
            checks.push("ok:parent_file_id_matches".to_string());
        }

        let expected_depth = parent_store.lineage_depth().saturating_add(1);
        if lineage_depth != expected_depth {
            verified = false;
            checks.push("fail:lineage_depth_parent_plus_one".to_string());
        } else {
            checks.push("ok:lineage_depth_parent_plus_one".to_string());
        }
    }

    Ok(RvfVerificationReport {
        path: path.to_path_buf(),
        verified,
        checks,
        file_id_hex,
        parent_id_hex,
        lineage_depth,
        is_root,
        parent_path: parent_path_out,
        parent_match,
    })
}

#[cfg(feature = "rvf-persistence")]
fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{:02x}", byte);
    }
    out
}

/// Export model family data as a real RVF vector store artifact.
#[cfg(feature = "rvf-persistence")]
pub fn handle_export_rvf_command(
    model_type: &str,
    output: &Path,
    data_dir: Option<&Path>,
    models_dir: Option<&Path>,
) -> Result<PathBuf, TrainingError> {
    let model_type: ModelType = model_type.parse()?;
    let mut config = TrainingConfig::default();
    if let Some(dir) = models_dir {
        config.models_dir = dir.to_path_buf();
    }
    if let Some(dir) = data_dir {
        config.data_dir = dir.to_path_buf();
    }

    let pipeline = TrainingPipeline::new(config.clone())?;
    let active = pipeline
        .get_active_version(model_type)
        .ok_or_else(|| TrainingError::ModelNotFound(model_type.to_string()))?;

    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    if output.exists() {
        fs::remove_file(output)?;
    }

    let mut store = RvfStore::create(
        output,
        RvfOptions {
            dimension: 384,
            metric: RvfDistanceMetric::Cosine,
            ..Default::default()
        },
    )
    .map_err(|err| TrainingError::TrainingFailed(err.to_string()))?;

    let embedder = HashEmbedding::new(384);
    let mut vectors: Vec<Vec<f32>> = Vec::new();
    let mut ids: Vec<u64> = Vec::new();

    let model_payload = fs::read_to_string(&active.path).unwrap_or_else(|_| {
        serde_json::json!({
            "model_type": active.model_type,
            "version": active.version,
            "trained_at": active.trained_at,
            "samples_count": active.samples_count,
            "loss": active.loss
        })
        .to_string()
    });
    let vec = embedder
        .embed(&model_payload)
        .map_err(|err| TrainingError::TrainingFailed(err.to_string()))?;
    vectors.push(vec);
    ids.push(hash_to_u64(&format!(
        "model:{}:{}",
        active.model_type, active.version
    )));

    let sample_dir = config.data_dir.join(model_type.to_string());
    if sample_dir.exists() {
        for entry in fs::read_dir(&sample_dir)? {
            let path = entry?.path();
            if path.extension().is_none_or(|ext| ext != "json") {
                continue;
            }
            let sample = fs::read_to_string(&path)?;
            let emb = embedder
                .embed(&sample)
                .map_err(|err| TrainingError::TrainingFailed(err.to_string()))?;
            vectors.push(emb);
            ids.push(hash_to_u64(&path.to_string_lossy()));
        }
    }

    if vectors.is_empty() {
        return Err(TrainingError::TrainingFailed(
            "no vectors available for RVF export".to_string(),
        ));
    }

    let refs: Vec<&[f32]> = vectors.iter().map(|v| v.as_slice()).collect();
    store
        .ingest_batch(&refs, &ids, None)
        .map_err(|err| TrainingError::TrainingFailed(err.to_string()))?;
    store
        .close()
        .map_err(|err| TrainingError::TrainingFailed(err.to_string()))?;
    Ok(output.to_path_buf())
}

#[cfg(not(feature = "rvf-persistence"))]
pub fn handle_rvf_branch_command(_source: &Path, _target: &Path) -> Result<PathBuf, TrainingError> {
    Err(TrainingError::TrainingFailed(
        "rvf-persistence feature is not enabled".to_string(),
    ))
}

#[cfg(not(feature = "rvf-persistence"))]
pub fn handle_rvf_lineage_command(_path: &Path) -> Result<RvfLineage, TrainingError> {
    Err(TrainingError::TrainingFailed(
        "rvf-persistence feature is not enabled".to_string(),
    ))
}

#[cfg(not(feature = "rvf-persistence"))]
pub fn handle_rvf_verify_command(
    _path: &Path,
    _parent_path: Option<&Path>,
) -> Result<RvfVerificationReport, TrainingError> {
    Err(TrainingError::TrainingFailed(
        "rvf-persistence feature is not enabled".to_string(),
    ))
}

#[cfg(feature = "rvf-persistence")]
fn hash_to_u64(value: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish().max(1)
}

/// Export RVF fallback when feature is disabled.
#[cfg(not(feature = "rvf-persistence"))]
pub fn handle_export_rvf_command(
    _model_type: &str,
    _output: &Path,
    _data_dir: Option<&Path>,
    _models_dir: Option<&Path>,
) -> Result<PathBuf, TrainingError> {
    Err(TrainingError::TrainingFailed(
        "rvf-persistence feature is not enabled".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::Mutex;

    static AI_ENV_LOCK: Mutex<()> = Mutex::new(());

    fn setup_test_env() -> (tempfile::TempDir, TrainingConfig) {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let config = TrainingConfig {
            models_dir: temp_dir.path().join("models"),
            data_dir: temp_dir.path().join("data"),
            online_learning: false,
            online_interval: Duration::from_secs(60),
            max_versions: 5,
            min_samples: 3, // Low for testing
            max_loss_regression: 0.25,
            data_collection_consent: true,
        };

        // Create sample data
        for model_type in ["resource-predictor", "anomaly-detector", "restart-policy"] {
            let data_dir = config.data_dir.join(model_type);
            fs::create_dir_all(&data_dir).unwrap();

            for i in 0..5 {
                let sample = match model_type {
                    "resource-predictor" => serde_json::json!({
                        "cpu_percent": 10.0 + i as f32,
                        "memory_bytes": 1024 + (i as u64 * 128),
                        "pids_count": 20 + i as u64,
                        "timestamp_secs": 1_700_000_000 + i as u64
                    }),
                    "anomaly-detector" => serde_json::json!({
                        "features": [i as f32, (i * 2) as f32, 1.0],
                        "is_anomaly": i == 4,
                        "container_id": format!("container-{i}")
                    }),
                    "restart-policy" => serde_json::json!({
                        "exit_code": if i % 2 == 0 { 0 } else { 1 },
                        "uptime_secs": 30 + i as u64,
                        "restart_success": i % 3 != 0,
                        "container_id": format!("container-{i}")
                    }),
                    _ => serde_json::json!({"sample": i}),
                };
                fs::write(
                    data_dir.join(format!("sample_{}.json", i)),
                    sample.to_string(),
                )
                .unwrap();
            }
        }

        (temp_dir, config)
    }

    #[test]
    fn model_type_parsing() {
        assert!(matches!(
            "resource-predictor".parse::<ModelType>(),
            Ok(ModelType::ResourcePredictor)
        ));
        assert!(matches!(
            "anomaly-detector".parse::<ModelType>(),
            Ok(ModelType::AnomalyDetector)
        ));
        assert!(matches!(
            "restart-policy".parse::<ModelType>(),
            Ok(ModelType::RestartPolicy)
        ));
        assert!("invalid".parse::<ModelType>().is_err());
    }

    #[test]
    fn pipeline_creation() {
        let (_temp, config) = setup_test_env();
        let pipeline = TrainingPipeline::new(config);
        assert!(pipeline.is_ok());
    }

    #[test]
    fn rejects_missing_active_artifact_in_version_history() {
        let (_temp, config) = setup_test_env();
        let dir = config
            .models_dir
            .join(ModelType::ResourcePredictor.to_string());
        fs::create_dir_all(&dir).expect("model directory");
        let metadata = serde_json::json!([{
            "model_type": "resource-predictor",
            "version": 1,
            "trained_at": "2026-01-01T00:00:00Z",
            "samples_count": 3,
            "loss": 0.1,
            "path": dir.join("missing.bin"),
            "active": true
        }]);
        fs::write(
            dir.join("versions.json"),
            serde_json::to_vec(&metadata).expect("metadata"),
        )
        .expect("write metadata");

        let error = match TrainingPipeline::new(config) {
            Err(error) => error,
            Ok(_) => panic!("missing artifact must fail closed"),
        };
        assert!(matches!(error, TrainingError::InvalidVersionHistory(_)));
    }

    #[test]
    fn rejects_multiple_active_versions() {
        let (_temp, config) = setup_test_env();
        let dir = config
            .models_dir
            .join(ModelType::ResourcePredictor.to_string());
        fs::create_dir_all(&dir).expect("model directory");
        for version in [1, 2] {
            fs::write(dir.join(format!("model_v{version}.bin")), b"model").expect("artifact");
        }
        let metadata = (1..=2)
            .map(|version| {
                serde_json::json!({
                    "model_type": "resource-predictor",
                    "version": version,
                    "trained_at": "2026-01-01T00:00:00Z",
                    "samples_count": 3,
                    "loss": 0.1,
                    "path": dir.join(format!("model_v{version}.bin")),
                    "active": true
                })
            })
            .collect::<Vec<_>>();
        fs::write(
            dir.join("versions.json"),
            serde_json::to_vec(&metadata).expect("metadata"),
        )
        .expect("write metadata");

        let error = match TrainingPipeline::new(config) {
            Err(error) => error,
            Ok(_) => panic!("ambiguous active model"),
        };
        assert!(matches!(error, TrainingError::InvalidVersionHistory(_)));
    }

    #[test]
    fn active_model_router_rejects_tampered_artifact() {
        let (_temp, config) = setup_test_env();
        let dir = config
            .models_dir
            .join(ModelType::ResourcePredictor.to_string());
        fs::create_dir_all(&dir).expect("model directory");
        let artifact = dir.join("model_v1.bin");
        fs::write(&artifact, b"trusted-model").expect("artifact");
        let digest = format!("sha256:{:x}", Sha256::digest(b"trusted-model"));
        let metadata = serde_json::json!([{
            "model_type": "resource-predictor",
            "version": 1,
            "trained_at": "2026-01-01T00:00:00Z",
            "samples_count": 3,
            "loss": 0.1,
            "path": artifact,
            "artifact_sha256": digest,
            "active": true
        }]);
        fs::write(
            dir.join("versions.json"),
            serde_json::to_vec(&metadata).expect("metadata"),
        )
        .expect("write metadata");

        let pipeline = TrainingPipeline::new(config).expect("pipeline");
        let routed = pipeline
            .resolve_active_model(ModelType::ResourcePredictor)
            .expect("matching artifact digest");
        assert_eq!(routed.version, 1);
        fs::write(&routed.path, b"tampered-model").expect("tamper artifact");
        let error = pipeline
            .resolve_active_model(ModelType::ResourcePredictor)
            .expect_err("tampered artifact must fail closed");
        assert!(error.to_string().contains("digest mismatch"));
    }

    #[test]
    fn active_model_router_rejects_legacy_metadata_without_digest() {
        let (_temp, config) = setup_test_env();
        let dir = config
            .models_dir
            .join(ModelType::ResourcePredictor.to_string());
        fs::create_dir_all(&dir).expect("model directory");
        let artifact = dir.join("model_v1.bin");
        fs::write(&artifact, b"legacy-model").expect("artifact");
        let metadata = serde_json::json!([{
            "model_type": "resource-predictor",
            "version": 1,
            "trained_at": "2026-01-01T00:00:00Z",
            "samples_count": 3,
            "loss": 0.1,
            "path": artifact,
            "active": true
        }]);
        fs::write(
            dir.join("versions.json"),
            serde_json::to_vec(&metadata).expect("metadata"),
        )
        .expect("write metadata");

        let pipeline = TrainingPipeline::new(config).expect("pipeline");
        let error = pipeline
            .resolve_active_model(ModelType::ResourcePredictor)
            .expect_err("legacy metadata must not route an unbound artifact");
        assert!(error.to_string().contains("no artifact digest"));
    }

    #[test]
    fn train_with_ai_disabled() {
        let _guard = AI_ENV_LOCK.lock().expect("lock env");
        let (_temp, config) = setup_test_env();
        unsafe {
            std::env::remove_var("FERROCRATE_AI");
        }

        let mut pipeline = TrainingPipeline::new(config).unwrap();
        let result = pipeline.train(ModelType::ResourcePredictor);

        // Should fail if AI is disabled
        if !std::env::var("FERROCRATE_AI")
            .unwrap_or_default()
            .starts_with("1")
        {
            assert!(matches!(result, Err(TrainingError::AiDisabled)));
        }
    }

    #[test]
    fn train_with_sufficient_data() {
        let _guard = AI_ENV_LOCK.lock().expect("lock env");
        let (_temp, config) = setup_test_env();

        // Skip test if AI is not enabled
        if !TrainingPipeline::is_ai_enabled() {
            eprintln!("Skipping train_with_sufficient_data test - FERROCRATE_AI not set");
            return;
        }

        let mut pipeline = TrainingPipeline::new(config).unwrap();
        let result = pipeline.train(ModelType::ResourcePredictor);

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.model_type, ModelType::ResourcePredictor);
        assert_eq!(result.version, 1);
        assert!(result.samples_used >= 3);
    }

    #[test]
    fn version_increments_on_retrain() {
        let _guard = AI_ENV_LOCK.lock().expect("lock env");
        let (_temp, config) = setup_test_env();

        // Skip test if AI is not enabled
        if !TrainingPipeline::is_ai_enabled() {
            eprintln!("Skipping version_increments test - FERROCRATE_AI not set");
            return;
        }

        let mut pipeline = TrainingPipeline::new(config).unwrap();

        let r1 = pipeline.train(ModelType::ResourcePredictor).unwrap();
        assert_eq!(r1.version, 1);

        let r2 = pipeline.train(ModelType::ResourcePredictor).unwrap();
        assert_eq!(r2.version, 2);
    }

    #[test]
    fn loss_regression_gate_keeps_previous_active_version() {
        let _guard = AI_ENV_LOCK.lock().expect("AI env lock");
        let (_temp, mut config) = setup_test_env();
        config.max_loss_regression = 0.0;
        let previous_ai = std::env::var("FERROCRATE_AI").ok();
        unsafe {
            std::env::set_var("FERROCRATE_AI", "1");
        }
        let sample_dir = config.data_dir.join("resource-predictor");
        fs::remove_dir_all(&sample_dir).expect("clear fixture samples");
        fs::create_dir_all(&sample_dir).expect("sample directory");
        let mut pipeline = TrainingPipeline::new(config.clone()).expect("pipeline");
        let stable = serde_json::json!({
            "cpu_percent": 10.0,
            "memory_bytes": 1024,
            "pids_count": 2,
            "timestamp_secs": 1
        });
        for timestamp in 1..=3 {
            let mut sample = stable.clone();
            sample["timestamp_secs"] = serde_json::json!(timestamp);
            pipeline
                .record_sample(ModelType::ResourcePredictor, sample.to_string().as_bytes())
                .expect("stable sample");
        }
        pipeline
            .train(ModelType::ResourcePredictor)
            .expect("first model");
        assert_eq!(
            pipeline
                .get_active_version(ModelType::ResourcePredictor)
                .expect("active model")
                .version,
            1
        );

        fs::remove_dir_all(&sample_dir).expect("replace corpus");
        fs::create_dir_all(&sample_dir).expect("sample directory");
        for (index, cpu) in [0.0, 50.0, 100.0].into_iter().enumerate() {
            let sample = serde_json::json!({
                "cpu_percent": cpu,
                "memory_bytes": 1024 + index as u64,
                "pids_count": 2 + index as u64,
                "timestamp_secs": 2 + index as u64
            });
            pipeline
                .record_sample(ModelType::ResourcePredictor, sample.to_string().as_bytes())
                .expect("regression sample");
        }
        let error = pipeline
            .train(ModelType::ResourcePredictor)
            .expect_err("loss regression must not activate");
        assert!(matches!(error, TrainingError::LossRegression { .. }));
        assert_eq!(
            pipeline
                .get_active_version(ModelType::ResourcePredictor)
                .expect("previous model remains active")
                .version,
            1
        );
        match previous_ai {
            Some(value) => unsafe { std::env::set_var("FERROCRATE_AI", value) },
            None => unsafe { std::env::remove_var("FERROCRATE_AI") },
        }
    }

    #[test]
    fn rollback_to_previous_version() {
        let _guard = AI_ENV_LOCK.lock().expect("lock env");
        let (_temp, config) = setup_test_env();

        // Skip test if AI is not enabled
        if !TrainingPipeline::is_ai_enabled() {
            eprintln!("Skipping rollback test - FERROCRATE_AI not set");
            return;
        }

        let mut pipeline = TrainingPipeline::new(config).unwrap();

        pipeline.train(ModelType::ResourcePredictor).unwrap();
        pipeline.train(ModelType::ResourcePredictor).unwrap();

        let active = pipeline
            .get_active_version(ModelType::ResourcePredictor)
            .unwrap();
        assert_eq!(active.version, 2);

        let rolled_back = pipeline.rollback(ModelType::ResourcePredictor).unwrap();
        assert_eq!(rolled_back.version, 1);

        let active = pipeline
            .get_active_version(ModelType::ResourcePredictor)
            .unwrap();
        assert_eq!(active.version, 1);
    }

    #[test]
    fn version_pruning() {
        let _guard = AI_ENV_LOCK.lock().expect("lock env");
        let (_temp, mut config) = setup_test_env();
        config.max_versions = 2;

        // Skip test if AI is not enabled
        if !TrainingPipeline::is_ai_enabled() {
            eprintln!("Skipping version_pruning test - FERROCRATE_AI not set");
            return;
        }

        let mut pipeline = TrainingPipeline::new(config).unwrap();

        // Train 3 times
        pipeline.train(ModelType::ResourcePredictor).unwrap();
        pipeline.train(ModelType::ResourcePredictor).unwrap();
        pipeline.train(ModelType::ResourcePredictor).unwrap();

        let versions = pipeline.list_versions(ModelType::ResourcePredictor);
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].version, 2);
        assert_eq!(versions[1].version, 3);
    }

    #[test]
    fn online_learning_state() {
        let _guard = AI_ENV_LOCK.lock().expect("lock env");
        let (_temp, mut config) = setup_test_env();
        config.online_learning = true;

        let mut pipeline = TrainingPipeline::new(config).unwrap();
        assert!(!pipeline.is_online_learning());
        pipeline.start_online_learning().unwrap();
        assert!(pipeline.is_online_learning());
        pipeline.stop_online_learning();
        assert!(!pipeline.is_online_learning());
    }

    #[test]
    fn training_samples_are_schema_validated_content_addressed_and_deduplicated() {
        let (_temp, config) = setup_test_env();
        let mut pipeline = TrainingPipeline::new(config.clone()).expect("pipeline");
        let sample_dir = config.data_dir.join("resource-predictor");
        fs::remove_dir_all(&sample_dir).expect("clear fixture samples");
        fs::create_dir_all(&sample_dir).expect("sample directory");
        let sample = serde_json::json!({
            "cpu_percent": 12.5,
            "memory_bytes": 4096,
            "pids_count": 3,
            "timestamp_secs": 1_700_000_000u64
        });
        let bytes = sample.to_string().into_bytes();
        pipeline
            .record_sample(ModelType::ResourcePredictor, &bytes)
            .expect("record sample");
        pipeline
            .record_sample(ModelType::ResourcePredictor, &bytes)
            .expect("duplicate sample is idempotent");
        let entries = fs::read_dir(&sample_dir)
            .expect("sample directory")
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 1);
        assert!(entries[0]
            .file_name()
            .to_string_lossy()
            .starts_with("sample_"));

        let error = pipeline
            .record_sample(ModelType::ResourcePredictor, br#"{"not":"a sample"}"#)
            .expect_err("invalid sample schema must fail closed");
        assert!(matches!(error, TrainingError::ParseError(_)));
    }

    #[test]
    fn training_samples_reject_oversized_payloads_before_writing() {
        let (_temp, config) = setup_test_env();
        let mut pipeline = TrainingPipeline::new(config.clone()).expect("pipeline");
        let sample_dir = config.data_dir.join("resource-predictor");
        fs::remove_dir_all(&sample_dir).expect("clear fixture samples");
        fs::create_dir_all(&sample_dir).expect("sample directory");
        let mut sample = serde_json::json!({
            "cpu_percent": 1.0,
            "memory_bytes": 1,
            "pids_count": 1,
            "timestamp_secs": 1
        })
        .to_string()
        .into_bytes();
        sample.resize((1 << 20) + 1, b'x');
        let error = pipeline
            .record_sample(ModelType::ResourcePredictor, &sample)
            .expect_err("oversized sample must fail closed");
        assert!(matches!(error, TrainingError::SampleTooLarge(size) if size == (1 << 20)));
        assert_eq!(
            fs::read_dir(&sample_dir).expect("sample directory").count(),
            0
        );
    }

    #[test]
    fn training_collection_requires_explicit_consent() {
        let (_temp, mut config) = setup_test_env();
        config.data_collection_consent = false;
        let mut pipeline = TrainingPipeline::new(config.clone()).expect("pipeline");
        let sample = serde_json::json!({
            "cpu_percent": 1.0,
            "memory_bytes": 1,
            "pids_count": 1,
            "timestamp_secs": 1
        });
        let error = pipeline
            .record_sample(ModelType::ResourcePredictor, sample.to_string().as_bytes())
            .expect_err("collection without consent must fail closed");
        assert!(matches!(error, TrainingError::DataCollectionDisabled));
        assert_eq!(
            fs::read_dir(config.data_dir.join("resource-predictor"))
                .expect("sample directory")
                .count(),
            5
        );
    }

    #[test]
    fn sample_deletion_and_pruning_remain_available_after_consent_revocation() {
        let (_temp, config) = setup_test_env();
        let mut pipeline = TrainingPipeline::new(config.clone()).expect("pipeline");
        let sample_dir = config.data_dir.join("resource-predictor");
        fs::remove_dir_all(&sample_dir).expect("clear fixture samples");
        fs::create_dir_all(&sample_dir).expect("sample directory");
        let mut digests = Vec::new();
        for timestamp in 1..=3 {
            let sample = serde_json::json!({
                "cpu_percent": timestamp as f32,
                "memory_bytes": 1024,
                "pids_count": 2,
                "timestamp_secs": timestamp
            });
            let bytes = sample.to_string().into_bytes();
            digests.push(format!("{:x}", Sha256::digest(&bytes)));
            pipeline
                .record_sample(ModelType::ResourcePredictor, &bytes)
                .expect("record sample");
        }
        let removed = pipeline
            .delete_sample(ModelType::ResourcePredictor, &digests[0])
            .expect("delete sample");
        assert!(removed);
        assert!(!pipeline
            .delete_sample(ModelType::ResourcePredictor, &digests[0])
            .expect("idempotent delete"));
        assert!(pipeline
            .delete_sample(ModelType::ResourcePredictor, "not-a-digest")
            .is_err());
        assert_eq!(
            pipeline
                .prune_samples(ModelType::ResourcePredictor, 1)
                .expect("prune samples"),
            1
        );
        assert_eq!(
            fs::read_dir(&sample_dir).expect("sample directory").count(),
            1
        );
        // Deletion remains available after consent is revoked.
        pipeline.config.data_collection_consent = false;
        let remaining = fs::read_dir(&sample_dir)
            .expect("sample directory")
            .next()
            .expect("remaining sample")
            .expect("directory entry")
            .file_name()
            .to_string_lossy()
            .trim_start_matches("sample_")
            .trim_end_matches(".json")
            .to_string();
        assert!(pipeline
            .delete_sample(ModelType::ResourcePredictor, &remaining)
            .expect("delete after consent revocation"));
    }

    #[test]
    fn online_learning_trains_on_new_samples() {
        let _guard = AI_ENV_LOCK.lock().expect("lock env");
        let (_temp, mut config) = setup_test_env();
        config.online_learning = true;
        config.min_samples = 3;

        let previous_ai = std::env::var("FERROCRATE_AI").ok();
        unsafe {
            std::env::set_var("FERROCRATE_AI", "1");
        }
        let mut pipeline = TrainingPipeline::new(config).unwrap();
        pipeline.start_online_learning().unwrap();

        for i in 0..4 {
            let sample = serde_json::json!({
                "cpu_percent": 10.0 + i as f32,
                "memory_bytes": 1024 + (i as u64 * 16),
                "pids_count": 20 + i as u64,
                "timestamp_secs": 1_700_000_000 + i as u64
            });
            pipeline
                .record_sample(ModelType::ResourcePredictor, sample.to_string().as_bytes())
                .unwrap();
        }

        let versions = pipeline.list_versions(ModelType::ResourcePredictor);
        assert!(!versions.is_empty());
        assert!(versions.iter().any(|version| version.active));

        match previous_ai {
            Some(value) => unsafe {
                std::env::set_var("FERROCRATE_AI", value);
            },
            None => unsafe {
                std::env::remove_var("FERROCRATE_AI");
            },
        }
    }

    #[cfg(feature = "rvf-persistence")]
    #[test]
    fn community_publish_and_download_roundtrip() {
        let temp = tempfile::TempDir::new().unwrap();
        let market = temp.path().join("community");
        let source = temp.path().join("source.rvf");

        // Create minimal RVF artifact.
        {
            let mut store = RvfStore::create(
                &source,
                RvfOptions {
                    dimension: 3,
                    metric: RvfDistanceMetric::Cosine,
                    ..Default::default()
                },
            )
            .unwrap();
            let vectors: Vec<&[f32]> = vec![&[1.0, 0.0, 0.0]];
            let ids: Vec<u64> = vec![1];
            store.ingest_batch(&vectors, &ids, None).unwrap();
            store.close().unwrap();
        }

        let out = handle_community_publish_command(
            &source,
            "demo",
            "demo model",
            &["test".to_string()],
            &market,
        )
        .unwrap();
        assert!(out.exists());

        let list = handle_community_list_command(&market).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "demo");

        let downloaded = temp.path().join("downloaded.rvf");
        handle_community_download_command("demo", &downloaded, &market).unwrap();
        assert!(downloaded.exists());
    }

    #[cfg(feature = "rvf-persistence")]
    #[test]
    fn rvf_verify_accepts_parent_chain() {
        let temp = tempfile::TempDir::new().unwrap();
        let parent_path = temp.path().join("parent.rvf");
        let child_path = temp.path().join("child.rvf");

        {
            let mut store = RvfStore::create(
                &parent_path,
                RvfOptions {
                    dimension: 3,
                    metric: RvfDistanceMetric::Cosine,
                    ..Default::default()
                },
            )
            .unwrap();
            let vectors: Vec<&[f32]> = vec![&[1.0, 0.0, 0.0]];
            let ids: Vec<u64> = vec![1];
            store.ingest_batch(&vectors, &ids, None).unwrap();
            store.close().unwrap();
        }

        handle_rvf_branch_command(&parent_path, &child_path).unwrap();
        let report = handle_rvf_verify_command(&child_path, Some(&parent_path)).unwrap();
        assert!(report.verified);
        assert_eq!(report.parent_match, Some(true));
    }
}

/// Quantization helpers for compressing trained RVF model stores.
///
/// Uses `rvf-quant` scalar quantization (int8) to reduce store memory
/// footprint by ~4x with minimal accuracy loss for typical embedding ranges.
#[cfg(feature = "rvf-persistence")]
pub mod quantize {
    use rvf_quant::ScalarQuantizer;

    /// Quantization method for model compression.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Method {
        /// Scalar int8 quantization — 4x compression, minimal accuracy loss.
        /// Recommended for most use cases.
        Scalar8bit,
    }

    /// Summary returned after training a quantizer over an in-memory vector set.
    #[derive(Debug)]
    pub struct QuantSummary {
        /// The trained scalar quantizer (encode/decode vectors with it).
        pub quantizer: ScalarQuantizer,
        /// Number of training vectors used.
        pub training_vectors: usize,
        /// Vector dimensionality.
        pub dim: usize,
        /// Bytes in the original f32 vectors.
        pub original_bytes: usize,
        /// Bytes in the quantized representation.
        pub encoded_bytes: usize,
        /// Maximum absolute reconstruction error across the training set.
        pub max_abs_error: f32,
    }

    impl QuantSummary {
        /// Compression ratio of the measured encoded vectors.
        pub fn compression_ratio(&self) -> f32 {
            if self.encoded_bytes == 0 {
                return 0.0;
            }
            self.original_bytes as f32 / self.encoded_bytes as f32
        }
    }

    /// Train a scalar quantizer over a slice of f32 vectors.
    ///
    /// Typical use: collect vectors from `RvfStore` via your query path,
    /// then call this to get a quantizer you can use to encode future inserts.
    ///
    /// # Arguments
    /// * `vectors` - Training data. Must be non-empty, all same length.
    /// * `_method` - Reserved for future method variants; currently only Scalar8bit exists.
    ///
    /// # Errors
    /// Returns `Err` if `vectors` is empty.
    pub fn train_quantizer(vectors: &[Vec<f32>], _method: Method) -> Result<QuantSummary, String> {
        if vectors.is_empty() {
            return Err("cannot train quantizer: no vectors provided".to_string());
        }
        let dim = vectors[0].len();
        if dim == 0 {
            return Err("cannot train quantizer: zero-dimensional vectors".to_string());
        }
        if vectors.iter().any(|vector| vector.len() != dim) {
            return Err("cannot train quantizer: vector dimensions differ".to_string());
        }

        let refs: Vec<&[f32]> = vectors.iter().map(|v| v.as_slice()).collect();
        let quantizer = ScalarQuantizer::train(&refs);
        let original_bytes = vectors
            .len()
            .checked_mul(dim)
            .and_then(|count| count.checked_mul(std::mem::size_of::<f32>()))
            .ok_or_else(|| "quantizer input size overflows usize".to_string())?;
        let mut encoded_bytes = 0usize;
        let mut max_abs_error = 0.0f32;
        for vector in vectors {
            let encoded = quantizer.encode_vec(vector);
            encoded_bytes = encoded_bytes
                .checked_add(encoded.len())
                .ok_or_else(|| "quantizer encoded size overflows usize".to_string())?;
            let decoded = quantizer.decode_vec(&encoded);
            for (original, reconstructed) in vector.iter().zip(decoded.iter()) {
                max_abs_error = max_abs_error.max((original - reconstructed).abs());
            }
        }

        Ok(QuantSummary {
            training_vectors: vectors.len(),
            dim,
            quantizer,
            original_bytes,
            encoded_bytes,
            max_abs_error,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn train_scalar_quantizer_roundtrip() {
            let vectors: Vec<Vec<f32>> = (0..20)
                .map(|i| (0..8).map(|d| ((i * 7 + d * 3) as f32) / 50.0).collect())
                .collect();

            let summary = train_quantizer(&vectors, Method::Scalar8bit).expect("train");
            assert_eq!(summary.training_vectors, 20);
            assert_eq!(summary.dim, 8);
            assert!(summary.compression_ratio() >= 3.0);
            assert!(summary.max_abs_error < 0.05);

            // Verify encode/decode roundtrip is within 4x quantization error.
            let encoded = summary.quantizer.encode_vec(&vectors[0]);
            let decoded = summary.quantizer.decode_vec(&encoded);
            for (orig, recon) in vectors[0].iter().zip(decoded.iter()) {
                assert!((orig - recon).abs() < 0.05, "roundtrip error too large");
            }
        }

        #[test]
        fn train_quantizer_rejects_empty() {
            let err = train_quantizer(&[], Method::Scalar8bit).unwrap_err();
            assert!(err.contains("no vectors provided"));
        }

        #[test]
        fn train_quantizer_rejects_mismatched_dimensions() {
            let err =
                train_quantizer(&[vec![1.0, 2.0], vec![3.0]], Method::Scalar8bit).unwrap_err();
            assert!(err.contains("dimensions differ"));
        }
    }
}
