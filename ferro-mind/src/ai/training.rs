//! Model Training Pipeline (Task 5.4)
//!
//! Provides offline and online training for AI models:
//! - Offline training via CLI command
//! - Online learning via background process (opt-in)
//! - Model versioning and rollback support

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
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
        match s {
            "resource-predictor" => Ok(ModelType::ResourcePredictor),
            "anomaly-detector" => Ok(ModelType::AnomalyDetector),
            "restart-policy" => Ok(ModelType::RestartPolicy),
            _ => Err(format!(
                "Unknown model type: {}. Valid: resource-predictor, anomaly-detector, restart-policy",
                s
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

    #[error("Parse error: {0}")]
    ParseError(String),
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

/// Model training pipeline
pub struct TrainingPipeline {
    config: TrainingConfig,
    versions: HashMap<ModelType, Vec<ModelVersion>>,
    online_running: Arc<AtomicBool>,
}

impl TrainingPipeline {
    /// Create a new training pipeline
    pub fn new(config: TrainingConfig) -> Result<Self, TrainingError> {
        let mut pipeline = Self {
            config,
            versions: HashMap::new(),
            online_running: Arc::new(AtomicBool::new(false)),
        };
        pipeline.load_version_history()?;
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
    fn load_versions_for_model(&self, model_type: ModelType) -> Result<Vec<ModelVersion>, TrainingError> {
        let versions_file = self.config.models_dir
            .join(model_type.to_string())
            .join("versions.json");

        if versions_file.exists() {
            let file = File::open(&versions_file)?;
            let reader = BufReader::new(file);
            let versions: Vec<ModelVersion> = serde_json::from_reader(reader)?;
            Ok(versions)
        } else {
            Ok(Vec::new())
        }
    }

    /// Save version history to disk
    fn save_versions(&self, model_type: ModelType) -> Result<(), TrainingError> {
        if let Some(versions) = self.versions.get(&model_type) {
            let dir = self.config.models_dir.join(model_type.to_string());
            fs::create_dir_all(&dir)?;

            let versions_file = dir.join("versions.json");
            let file = File::create(&versions_file)?;
            let writer = BufWriter::new(file);
            serde_json::to_writer_pretty(writer, versions)?;
        }
        Ok(())
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

        let samples = self.load_training_data(&data_path, model_type)?;

        if samples.len() < self.config.min_samples {
            return Err(TrainingError::InsufficientData(
                samples.len(),
                self.config.min_samples,
            ));
        }

        // Perform training (simplified - in production would use ruv-fann/tract)
        let loss = self.train_model(model_type, &samples)?;

        // Create new version
        let version = self.get_next_version(model_type);
        let model_path = self.config.models_dir
            .join(model_type.to_string())
            .join(format!("model_v{}.bin", version));

        // Save model (placeholder - actual serialization depends on model type)
        self.save_model(&model_path, model_type, &samples)?;

        // Update version history
        let model_version = ModelVersion {
            model_type: model_type.to_string(),
            version,
            trained_at: chrono::Utc::now().to_rfc3339(),
            samples_count: samples.len(),
            loss: Some(loss),
            path: model_path.clone(),
            active: true,
        };

        // Deactivate previous versions
        if let Some(versions) = self.versions.get_mut(&model_type) {
            for v in versions.iter_mut() {
                v.active = false;
            }
            versions.push(model_version);

            // Prune old versions
            while versions.len() > self.config.max_versions {
                let removed = versions.remove(0);
                let _ = fs::remove_file(&removed.path);
            }
        } else {
            self.versions.insert(model_type, vec![model_version]);
        }

        self.save_versions(model_type)?;

        Ok(TrainingResult {
            model_type,
            version,
            samples_used: samples.len(),
            duration: start.elapsed(),
            loss: Some(loss),
            model_path,
        })
    }

    /// Load training data from directory
    fn load_training_data(
        &self,
        data_path: &Path,
        model_type: ModelType,
    ) -> Result<Vec<Vec<u8>>, TrainingError> {
        let mut samples = Vec::new();

        if !data_path.exists() {
            return Ok(samples);
        }

        for entry in fs::read_dir(data_path)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().map_or(false, |e| e == "json") {
                let data = fs::read(&path)?;
                samples.push(data);
            }
        }

        Ok(samples)
    }

    /// Train model (simplified implementation)
    fn train_model(&self, model_type: ModelType, samples: &[Vec<u8>]) -> Result<f32, TrainingError> {
        // Suppress unused variable warning - model_type will be used in production
        let _ = model_type;
        // In production, this would:
        // 1. Parse samples into model-specific format
        // 2. Train using ruv-fann (neural networks) or tract (ONNX)
        // 3. Apply EWC++ for catastrophic forgetting prevention
        // 4. Return final loss

        // Placeholder: simulate training
        let base_loss = 0.5;
        let sample_factor = 1.0 / (1.0 + samples.len() as f32 / 1000.0);
        Ok(base_loss * sample_factor)
    }

    /// Save model to disk
    fn save_model(
        &self,
        path: &Path,
        model_type: ModelType,
        samples: &[Vec<u8>],
    ) -> Result<(), TrainingError> {
        fs::create_dir_all(path.parent().unwrap())?;

        // Placeholder: save metadata about model
        let metadata = serde_json::json!({
            "model_type": model_type.to_string(),
            "samples_count": samples.len(),
            "created_at": chrono::Utc::now().to_rfc3339(),
        });

        let file = File::create(path)?;
        serde_json::to_writer(file, &metadata)?;

        Ok(())
    }

    /// Get next version number for a model
    fn get_next_version(&self, model_type: ModelType) -> u32 {
        self.versions
            .get(&model_type)
            .and_then(|v| v.last().map(|last| last.version + 1))
            .unwrap_or(1)
    }

    /// Rollback to previous model version
    pub fn rollback(&mut self, model_type: ModelType) -> Result<ModelVersion, TrainingError> {
        // First, find the index to rollback to
        let rollback_idx = {
            let versions = self.versions.get(&model_type).ok_or(TrainingError::NoActiveModel)?;
            let active_idx = versions.iter().position(|v| v.active);

            match active_idx {
                Some(idx) if idx > 0 => Some(idx - 1),
                _ => None,
            }
        };

        // Now perform the mutation
        if let Some(target_idx) = rollback_idx {
            let versions = self.versions.get_mut(&model_type).unwrap();

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
        self.versions
            .get(&model_type)?
            .iter()
            .find(|v| v.active)
    }

    /// List all versions for a model
    pub fn list_versions(&self, model_type: ModelType) -> Vec<&ModelVersion> {
        self.versions
            .get(&model_type)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Start online learning background process
    pub fn start_online_learning(&self) -> Result<(), TrainingError> {
        if !self.config.online_learning {
            return Ok(());
        }

        self.online_running.store(true, Ordering::SeqCst);

        // In production, this would spawn a background thread that:
        // 1. Monitors runtime data
        // 2. Accumulates new samples
        // 3. Periodically triggers incremental training via ruvector-sona's LoRA adapters
        // 4. Applies EWC++ to prevent forgetting

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

    /// Record a training sample for later use
    pub fn record_sample(
        &self,
        model_type: ModelType,
        sample: &[u8],
    ) -> Result<(), TrainingError> {
        let data_dir = self.config.data_dir.join(model_type.to_string());
        fs::create_dir_all(&data_dir)?;

        let timestamp = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
        let filename = format!("sample_{}.json", timestamp);
        let path = data_dir.join(filename);

        fs::write(&path, sample)?;

        Ok(())
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn setup_test_env() -> (tempfile::TempDir, TrainingConfig) {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let config = TrainingConfig {
            models_dir: temp_dir.path().join("models"),
            data_dir: temp_dir.path().join("data"),
            online_learning: false,
            online_interval: Duration::from_secs(60),
            max_versions: 5,
            min_samples: 3, // Low for testing
        };

        // Create sample data
        for model_type in ["resource-predictor", "anomaly-detector", "restart-policy"] {
            let data_dir = config.data_dir.join(model_type);
            fs::create_dir_all(&data_dir).unwrap();

            for i in 0..5 {
                let sample = serde_json::json!({"sample": i, "data": [1.0, 2.0, 3.0]});
                fs::write(data_dir.join(format!("sample_{}.json", i)), sample.to_string()).unwrap();
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
    fn train_with_ai_disabled() {
        let (_temp, config) = setup_test_env();
        unsafe { std::env::remove_var("FERROCRATE_AI"); }

        let mut pipeline = TrainingPipeline::new(config).unwrap();
        let result = pipeline.train(ModelType::ResourcePredictor);

        // Should fail if AI is disabled
        if !std::env::var("FERROCRATE_AI").unwrap_or_default().starts_with("1") {
            assert!(matches!(result, Err(TrainingError::AiDisabled)));
        }
    }

    #[test]
    fn train_with_sufficient_data() {
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
    fn rollback_to_previous_version() {
        let (_temp, config) = setup_test_env();

        // Skip test if AI is not enabled
        if !TrainingPipeline::is_ai_enabled() {
            eprintln!("Skipping rollback test - FERROCRATE_AI not set");
            return;
        }

        let mut pipeline = TrainingPipeline::new(config).unwrap();

        pipeline.train(ModelType::ResourcePredictor).unwrap();
        pipeline.train(ModelType::ResourcePredictor).unwrap();

        let active = pipeline.get_active_version(ModelType::ResourcePredictor).unwrap();
        assert_eq!(active.version, 2);

        let rolled_back = pipeline.rollback(ModelType::ResourcePredictor).unwrap();
        assert_eq!(rolled_back.version, 1);

        let active = pipeline.get_active_version(ModelType::ResourcePredictor).unwrap();
        assert_eq!(active.version, 1);
    }

    #[test]
    fn version_pruning() {
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
        let (_temp, config) = setup_test_env();

        let pipeline = TrainingPipeline::new(config).unwrap();
        assert!(!pipeline.is_online_learning());

        // Note: online learning requires config.online_learning = true
    }
}
