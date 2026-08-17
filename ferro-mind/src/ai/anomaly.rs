//! Anomaly Detection with Neural Networks via ruv-fann
//!
//! Provides z-score based anomaly detection with optional neural network
//! enhancement for more sophisticated pattern recognition.
//!
//! Task 5.2: Runtime Anomaly Detection Integration

use ruv_fann::training::{IncrementalBackprop, TrainingAlgorithm, TrainingData};
use ruv_fann::{Network, NetworkBuilder};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::time::Instant;

/// Anomaly score with threshold comparison
#[derive(Debug, Clone, Copy)]
pub struct AnomalyScore {
    pub score: f32,
    pub threshold: f32,
}

impl AnomalyScore {
    pub fn is_anomalous(&self) -> bool {
        self.score > self.threshold
    }
}

/// Calculate z-score for basic anomaly detection
pub fn zscore(current: f32, mean: f32, stddev: f32, threshold: f32) -> AnomalyScore {
    let score = if stddev > 0.0 {
        (current - mean) / stddev
    } else {
        0.0
    };
    AnomalyScore { score, threshold }
}

/// Neural network-based anomaly detector
///
/// Uses a feedforward neural network trained on normal behavior patterns
/// to detect anomalies in container metrics (CPU, memory, I/O).
pub struct NeuralAnomalyDetector {
    network: Option<Network<f32>>,
    input_size: usize,
    threshold: f32,
    trained: bool,
    centroid: Option<Vec<f32>>,
    centroid_threshold: Option<f32>,
    /// Mean of the normal training window used as a deterministic guardrail
    /// around the stochastic neural reconstruction score.
    baseline_centroid: Option<Vec<f32>>,
}

// Manual Debug implementation since Network<f32> doesn't derive Debug
impl std::fmt::Debug for NeuralAnomalyDetector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NeuralAnomalyDetector")
            .field("network", &self.network.as_ref().map(|_| "<network>"))
            .field("input_size", &self.input_size)
            .field("threshold", &self.threshold)
            .field("trained", &self.trained)
            .field("centroid", &self.centroid.as_ref().map(Vec::len))
            .field(
                "baseline_centroid",
                &self.baseline_centroid.as_ref().map(Vec::len),
            )
            .finish()
    }
}

impl Default for NeuralAnomalyDetector {
    fn default() -> Self {
        Self::new(5, 0.5) // 5 inputs: cpu, mem, io_read, io_write, network
    }
}

impl NeuralAnomalyDetector {
    /// Create a new neural anomaly detector
    ///
    /// # Arguments
    /// * `input_size` - Number of input features (e.g., 5 for cpu/mem/io/network metrics)
    /// * `threshold` - Reconstruction error threshold for anomaly classification
    pub fn new(input_size: usize, threshold: f32) -> Self {
        Self {
            network: None,
            input_size,
            threshold,
            trained: false,
            centroid: None,
            centroid_threshold: None,
            baseline_centroid: None,
        }
    }

    /// Load the centroid artifact produced by the anomaly training pipeline.
    ///
    /// The current training artifact intentionally stores a portable centroid
    /// rather than serialized neural weights. This loader validates the
    /// envelope and numeric bounds, allowing runtime distance scoring while
    /// preserving the neural learner for freshly baselined containers.
    pub fn from_model_artifact(path: &std::path::Path) -> Result<Self, String> {
        const MAX_ARTIFACT_BYTES: u64 = 1 << 20;
        if std::fs::metadata(path)
            .map_err(|error| error.to_string())?
            .len()
            > MAX_ARTIFACT_BYTES
        {
            return Err("anomaly model artifact exceeds 1 MiB".to_string());
        }
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).map_err(|error| error.to_string())?)
                .map_err(|error| format!("invalid anomaly model artifact: {error}"))?;
        if value.get("model_type").and_then(serde_json::Value::as_str) != Some("anomaly-detector") {
            return Err("anomaly model artifact has an unexpected model_type".to_string());
        }
        let artifact = value
            .get("artifact")
            .ok_or_else(|| "anomaly model artifact is missing artifact data".to_string())?;
        let centroid = artifact
            .get("centroid")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| "anomaly model artifact is missing centroid".to_string())?
            .iter()
            .map(|value| {
                let value = value
                    .as_f64()
                    .ok_or_else(|| "anomaly centroid contains a non-number".to_string())?
                    as f32;
                if !value.is_finite() || !(0.0..=1.0).contains(&value) {
                    return Err("anomaly centroid value is outside 0..=1".to_string());
                }
                Ok(value)
            })
            .collect::<Result<Vec<_>, String>>()?;
        if centroid.is_empty() || centroid.len() > 64 {
            return Err("anomaly centroid dimension is unsupported".to_string());
        }
        let normal_mean = artifact
            .get("normal_mean_distance")
            .and_then(serde_json::Value::as_f64)
            .ok_or_else(|| "anomaly normal distance is invalid".to_string())?
            as f32;
        let anomaly_mean = artifact
            .get("anomaly_mean_distance")
            .and_then(serde_json::Value::as_f64)
            .ok_or_else(|| "anomaly distance is invalid".to_string())?
            as f32;
        if !normal_mean.is_finite() || !anomaly_mean.is_finite() || normal_mean < 0.0 {
            return Err("anomaly distance statistics are invalid".to_string());
        }
        let threshold = if anomaly_mean > normal_mean {
            (normal_mean + anomaly_mean) / 2.0
        } else {
            (normal_mean * 3.0).max(f32::EPSILON)
        };
        let mut detector = Self::new(centroid.len(), threshold);
        detector.centroid = Some(centroid);
        detector.centroid_threshold = Some(threshold);
        Ok(detector)
    }

    /// Initialize the neural network with an autoencoder architecture
    ///
    /// Architecture: input -> hidden (compressed) -> output (reconstructed)
    fn init_network(&mut self) {
        let hidden_size = self.input_size.div_ceil(2); // Compression layer

        self.network = Some(
            NetworkBuilder::new()
                .input_layer(self.input_size)
                .hidden_layer(hidden_size)
                .output_layer(self.input_size) // Autoencoder: reconstruct input
                .build(),
        );
    }

    /// Train the network on normal behavior patterns
    ///
    /// # Arguments
    /// * `normal_samples` - Training data of normal behavior (features normalized to 0-1)
    /// * `epochs` - Number of training epochs
    ///
    /// # Returns
    /// Training success status
    pub fn train(&mut self, normal_samples: &[Vec<f32>], epochs: usize) -> bool {
        if normal_samples.is_empty() {
            return false;
        }

        self.centroid = None;
        self.centroid_threshold = None;
        self.baseline_centroid = None;
        self.init_network();

        let Some(ref mut network) = self.network else {
            return false;
        };

        // Build training data (autoencoder: input = expected output)
        let mut inputs = Vec::new();
        let mut outputs = Vec::new();

        for sample in normal_samples {
            if sample.len() == self.input_size {
                inputs.push(sample.clone());
                outputs.push(sample.clone()); // Autoencoder reconstructs input
            }
        }

        if inputs.is_empty() {
            return false;
        }

        // Keep a deterministic distance baseline alongside the neural model.
        // ruv-fann initializes weights stochastically, so using this bounded
        // distance as a floor prevents identical normal/anomalous inputs from
        // producing an unstable ordering across runs.
        let mut baseline = vec![0.0f32; self.input_size];
        for sample in &inputs {
            for (index, value) in sample.iter().enumerate() {
                baseline[index] += *value;
            }
        }
        for value in &mut baseline {
            *value /= inputs.len() as f32;
        }
        self.baseline_centroid = Some(baseline);

        let training_data = TrainingData { inputs, outputs };

        // Train with incremental backpropagation
        let mut trainer = IncrementalBackprop::new(0.001);

        for _ in 0..epochs {
            let result = trainer.train_epoch(network, &training_data);
            if result.is_err() {
                return false;
            }
        }

        self.trained = true;
        true
    }

    /// Detect anomaly by measuring reconstruction error
    ///
    /// For autoencoders trained on normal data, anomalies will have
    /// high reconstruction error (the network can't reconstruct them well).
    ///
    /// # Arguments
    /// * `features` - Normalized feature vector (same size as input_size)
    ///
    /// # Returns
    /// AnomalyScore with reconstruction error as score
    pub fn detect(&mut self, features: &[f32]) -> AnomalyScore {
        if let Some(centroid) = self.centroid.as_ref() {
            if features.len() != centroid.len() {
                return AnomalyScore {
                    score: 0.0,
                    threshold: self.centroid_threshold.unwrap_or(self.threshold),
                };
            }
            let distance = features
                .iter()
                .zip(centroid)
                .map(|(feature, expected)| (feature - expected).powi(2))
                .sum::<f32>()
                .sqrt();
            return AnomalyScore {
                score: distance,
                threshold: self.centroid_threshold.unwrap_or(self.threshold),
            };
        }
        if !self.trained || features.len() != self.input_size {
            return AnomalyScore {
                score: 0.0,
                threshold: self.threshold,
            };
        }

        let Some(ref mut network) = self.network else {
            return AnomalyScore {
                score: 0.0,
                threshold: self.threshold,
            };
        };

        // Run the autoencoder
        // Handle both Vec<T> and Result<Vec<T>, E> return types depending on version
        let outputs: Vec<f32> = match network.run(features) {
            Ok(v) => v,
            Err(_) => {
                return AnomalyScore {
                    score: f32::MAX,
                    threshold: self.threshold,
                }
            }
        };

        // Calculate reconstruction error (MSE)
        let mut error_sum = 0.0f32;
        for i in 0..features.len().min(outputs.len()) {
            let diff = features[i] - outputs[i];
            error_sum += diff * diff;
        }
        let error = error_sum / features.len() as f32;

        let baseline_distance = self
            .baseline_centroid
            .as_ref()
            .map(|centroid| {
                features
                    .iter()
                    .zip(centroid)
                    .map(|(feature, expected)| (feature - expected).powi(2))
                    .sum::<f32>()
                    .sqrt()
            })
            .unwrap_or(0.0);

        AnomalyScore {
            score: error.max(baseline_distance),
            threshold: self.threshold,
        }
    }

    /// Check if the detector has been trained
    pub fn is_trained(&self) -> bool {
        self.trained || self.centroid.is_some()
    }

    /// Number of normalized features accepted by this detector.
    pub fn input_size(&self) -> usize {
        self.input_size
    }

    /// Update the anomaly threshold
    pub fn set_threshold(&mut self, threshold: f32) {
        self.threshold = threshold;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AnomalyTrainingSnapshot {
    schema: u32,
    container_id: String,
    samples: Vec<Vec<f32>>,
}

/// Persist bounded normal-behavior samples used to warm the runtime detector.
pub fn save_training_snapshot(
    path: &std::path::Path,
    container_id: &str,
    samples: &[Vec<f32>],
) -> Result<(), String> {
    const MAX_BYTES: usize = 64 * 1024;
    if samples.len() > 64 || samples.iter().any(|sample| {
        sample.is_empty()
            || sample.len() > 16
            || sample
                .iter()
                .any(|value| !value.is_finite() || !(0.0..=1.0).contains(value))
    }) {
        return Err("anomaly training snapshot sample bounds are invalid".to_string());
    }
    let snapshot = AnomalyTrainingSnapshot {
        schema: 1,
        container_id: container_id.to_string(),
        samples: samples.to_vec(),
    };
    let bytes = serde_json::to_vec(&snapshot).map_err(|error| error.to_string())?;
    if bytes.len() > MAX_BYTES {
        return Err("anomaly training snapshot exceeds 64 KiB".to_string());
    }
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let temp = parent.join(format!(
        ".{}.tmp-{}-{}",
        path.file_name().and_then(|name| name.to_str()).unwrap_or("anomaly"),
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let result = (|| {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|error| error.to_string())?;
        file.write_all(&bytes).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        std::fs::rename(&temp, path).map_err(|error| error.to_string())?;
        if let Ok(directory) = std::fs::File::open(parent) {
            let _ = directory.sync_all();
        }
        Ok::<(), String>(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

/// Restore warm-up samples only when the snapshot belongs to this container.
pub fn load_training_snapshot(
    path: &std::path::Path,
    expected_container_id: &str,
) -> Result<Vec<Vec<f32>>, String> {
    const MAX_BYTES: u64 = 64 * 1024;
    let metadata = std::fs::metadata(path).map_err(|error| error.to_string())?;
    if metadata.len() > MAX_BYTES {
        return Err("anomaly training snapshot exceeds 64 KiB".to_string());
    }
    let snapshot: AnomalyTrainingSnapshot = serde_json::from_slice(
        &std::fs::read(path).map_err(|error| error.to_string())?,
    )
    .map_err(|error| format!("invalid anomaly training snapshot: {error}"))?;
    if snapshot.schema != 1 {
        return Err("unsupported anomaly training snapshot schema".to_string());
    }
    if snapshot.container_id != expected_container_id {
        return Err("anomaly training snapshot container identity mismatch".to_string());
    }
    if snapshot.samples.len() > 64
        || snapshot.samples.iter().any(|sample| {
            sample.is_empty()
                || sample.len() > 16
                || sample
                    .iter()
                    .any(|value| !value.is_finite() || !(0.0..=1.0).contains(value))
        })
    {
        return Err("anomaly training snapshot sample bounds are invalid".to_string());
    }
    Ok(snapshot.samples)
}

/// Container metrics for anomaly detection
#[derive(Debug, Clone, Copy, Default)]
pub struct ContainerMetrics {
    pub cpu_percent: f32,
    pub memory_percent: f32,
    pub io_read_bytes: u64,
    pub io_write_bytes: u64,
    pub network_bytes: u64,
}

impl ContainerMetrics {
    /// Convert to normalized feature vector for neural network
    pub fn to_features(&self, max_io: u64, max_network: u64) -> Vec<f32> {
        vec![
            self.cpu_percent / 100.0,
            self.memory_percent / 100.0,
            if max_io > 0 {
                (self.io_read_bytes + self.io_write_bytes) as f32 / max_io as f32
            } else {
                0.0
            },
            if max_network > 0 {
                self.network_bytes as f32 / max_network as f32
            } else {
                0.0
            },
            // Derived feature: cpu to memory ratio (anomalous if very high or low)
            if self.memory_percent > 0.0 {
                (self.cpu_percent / self.memory_percent).min(10.0) / 10.0
            } else {
                0.0
            },
        ]
    }
}

// ============================================================================
// Task 5.2: Runtime Anomaly Detection
// ============================================================================

/// Phases of anomaly detection lifecycle
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionPhase {
    /// Collecting baseline data (no anomalies reported)
    Learning,
    /// Baseline established, detecting anomalies
    Active,
}

/// Per-container anomaly detection state
#[derive(Debug)]
pub struct ContainerAnomalyState {
    /// Container ID
    pub container_id: String,
    /// Current detection phase
    pub phase: DetectionPhase,
    /// Start time for learning phase timeout
    pub learning_start: Instant,
    /// Learning phase duration (default 10 minutes)
    pub learning_duration_secs: u64,
    /// Historical samples for baseline calculation
    baseline_samples: VecDeque<BaselineSample>,
    /// Maximum samples to keep for baseline
    max_baseline_samples: usize,
    /// Statistical baseline (mean, stddev per metric)
    baseline_means: [f32; 4], // cpu, memory, io, network
    baseline_stddevs: [f32; 4],
    /// Z-score threshold for single-metric anomalies
    zscore_threshold: f32,
    /// Neural detector for multi-variate anomalies
    neural_detector: NeuralAnomalyDetector,
    /// Last anomaly score (for tracking)
    last_score: Option<AnomalyScore>,
}

/// A sample used for building baseline statistics
#[derive(Debug, Clone, Copy)]
struct BaselineSample {
    cpu_percent: f32,
    memory_percent: f32,
    io_normalized: f32,
    network_normalized: f32,
}

impl ContainerAnomalyState {
    /// Create a new anomaly detection state for a container
    pub fn new(container_id: &str) -> Self {
        Self {
            container_id: container_id.to_string(),
            phase: DetectionPhase::Learning,
            learning_start: Instant::now(),
            learning_duration_secs: 600, // 10 minutes default
            baseline_samples: VecDeque::with_capacity(200),
            max_baseline_samples: 200,
            baseline_means: [0.0; 4],
            baseline_stddevs: [0.0; 4],
            zscore_threshold: 3.0, // Standard z-score threshold
            neural_detector: NeuralAnomalyDetector::new(4, 0.3),
            last_score: None,
        }
    }

    /// Set custom learning phase duration
    pub fn with_learning_duration(mut self, secs: u64) -> Self {
        self.learning_duration_secs = secs;
        self
    }

    /// Set custom z-score threshold
    pub fn with_zscore_threshold(mut self, threshold: f32) -> Self {
        self.zscore_threshold = threshold;
        self
    }

    /// Record a sample and check for anomalies
    ///
    /// Returns Some(AnomalyEvent) if an anomaly is detected, None otherwise.
    pub fn record_and_detect(
        &mut self,
        metrics: &ContainerMetrics,
        max_io: u64,
        max_network: u64,
    ) -> Option<AnomalyEvent> {
        // Normalize metrics
        let sample = BaselineSample {
            cpu_percent: metrics.cpu_percent,
            memory_percent: metrics.memory_percent,
            io_normalized: if max_io > 0 {
                (metrics.io_read_bytes + metrics.io_write_bytes) as f32 / max_io as f32
            } else {
                0.0
            },
            network_normalized: if max_network > 0 {
                metrics.network_bytes as f32 / max_network as f32
            } else {
                0.0
            },
        };

        // Check if we should transition from learning to active
        if self.phase == DetectionPhase::Learning {
            let elapsed = self.learning_start.elapsed().as_secs();
            if elapsed >= self.learning_duration_secs {
                self.transition_to_active();
            }
        }

        match self.phase {
            DetectionPhase::Learning => {
                // Just collect samples, no anomaly detection
                self.add_baseline_sample(sample);
                None
            }
            DetectionPhase::Active => {
                // Check for anomalies using both z-score and neural network
                self.detect_anomaly(&sample)
            }
        }
    }

    /// Add a sample to the baseline
    fn add_baseline_sample(&mut self, sample: BaselineSample) {
        self.baseline_samples.push_back(sample);
        if self.baseline_samples.len() > self.max_baseline_samples {
            self.baseline_samples.pop_front();
        }
    }

    /// Transition from learning to active phase
    fn transition_to_active(&mut self) {
        // Calculate baseline statistics
        self.calculate_baseline_stats();

        // Train neural detector on baseline samples
        let training_samples: Vec<Vec<f32>> = self
            .baseline_samples
            .iter()
            .map(|s| {
                vec![
                    s.cpu_percent / 100.0,
                    s.memory_percent / 100.0,
                    s.io_normalized,
                    s.network_normalized,
                ]
            })
            .collect();

        if training_samples.len() >= 10 {
            self.neural_detector.train(&training_samples, 50);
        }

        self.phase = DetectionPhase::Active;
    }

    /// Calculate mean and stddev for baseline metrics
    fn calculate_baseline_stats(&mut self) {
        if self.baseline_samples.is_empty() {
            return;
        }

        let n = self.baseline_samples.len() as f32;

        // Calculate means
        let sum_cpu: f32 = self.baseline_samples.iter().map(|s| s.cpu_percent).sum();
        let sum_mem: f32 = self.baseline_samples.iter().map(|s| s.memory_percent).sum();
        let sum_io: f32 = self.baseline_samples.iter().map(|s| s.io_normalized).sum();
        let sum_net: f32 = self
            .baseline_samples
            .iter()
            .map(|s| s.network_normalized)
            .sum();

        self.baseline_means = [sum_cpu / n, sum_mem / n, sum_io / n, sum_net / n];

        // Calculate stddevs
        let var_cpu: f32 = self
            .baseline_samples
            .iter()
            .map(|s| (s.cpu_percent - self.baseline_means[0]).powi(2))
            .sum::<f32>()
            / n;
        let var_mem: f32 = self
            .baseline_samples
            .iter()
            .map(|s| (s.memory_percent - self.baseline_means[1]).powi(2))
            .sum::<f32>()
            / n;
        let var_io: f32 = self
            .baseline_samples
            .iter()
            .map(|s| (s.io_normalized - self.baseline_means[2]).powi(2))
            .sum::<f32>()
            / n;
        let var_net: f32 = self
            .baseline_samples
            .iter()
            .map(|s| (s.network_normalized - self.baseline_means[3]).powi(2))
            .sum::<f32>()
            / n;

        self.baseline_stddevs = [
            var_cpu.sqrt(),
            var_mem.sqrt(),
            var_io.sqrt(),
            var_net.sqrt(),
        ];
    }

    /// Detect anomalies using z-score and neural network
    fn detect_anomaly(&mut self, sample: &BaselineSample) -> Option<AnomalyEvent> {
        let values = [
            sample.cpu_percent,
            sample.memory_percent,
            sample.io_normalized,
            sample.network_normalized,
        ];
        let metric_names = ["cpu", "memory", "io", "network"];
        let mut strongest_metric_idx = 0usize;
        let mut strongest_z_ratio = 0.0f32;

        // Check z-score for each metric
        for (i, &value) in values.iter().enumerate() {
            let score = zscore(
                value,
                self.baseline_means[i],
                self.baseline_stddevs[i],
                self.zscore_threshold,
            );
            let z_ratio = score.score.abs() / self.zscore_threshold.max(0.001);
            if z_ratio > strongest_z_ratio {
                strongest_z_ratio = z_ratio;
                strongest_metric_idx = i;
            }
            if score.is_anomalous() {
                return Some(AnomalyEvent {
                    container_id: self.container_id.clone(),
                    metric: metric_names[i].to_string(),
                    current_value: value,
                    baseline_mean: self.baseline_means[i],
                    baseline_stddev: self.baseline_stddevs[i],
                    zscore: score.score,
                    detection_method: DetectionMethod::Zscore,
                    confidence: 0.8, // Reasonable confidence for z-score
                });
            }
        }

        // Check neural network for multi-variate anomalies
        let features = vec![
            sample.cpu_percent / 100.0,
            sample.memory_percent / 100.0,
            sample.io_normalized,
            sample.network_normalized,
        ];
        let neural_score = self.neural_detector.detect(&features);
        self.last_score = Some(neural_score);
        let neural_ratio = neural_score.score / neural_score.threshold.max(0.001);
        let hybrid_ratio = (strongest_z_ratio + neural_ratio) / 2.0;

        if hybrid_ratio > 1.0 {
            return Some(AnomalyEvent {
                container_id: self.container_id.clone(),
                metric: format!(
                    "hybrid({}+multi-variate)",
                    metric_names[strongest_metric_idx]
                ),
                current_value: hybrid_ratio,
                baseline_mean: self.baseline_means[strongest_metric_idx],
                baseline_stddev: self.baseline_stddevs[strongest_metric_idx],
                zscore: strongest_z_ratio,
                detection_method: DetectionMethod::Hybrid,
                confidence: (0.65 + (hybrid_ratio / 10.0)).min(0.95),
            });
        }

        if neural_score.is_anomalous() {
            return Some(AnomalyEvent {
                container_id: self.container_id.clone(),
                metric: "multi-variate".to_string(),
                current_value: neural_score.score,
                baseline_mean: 0.0,
                baseline_stddev: 0.0,
                zscore: neural_score.score / neural_score.threshold.max(0.001),
                detection_method: DetectionMethod::NeuralNetwork,
                confidence: 0.6 + (neural_score.score / neural_score.threshold / 10.0).min(0.3),
            });
        }

        None
    }

    /// Get the current detection phase
    pub fn get_phase(&self) -> DetectionPhase {
        self.phase
    }

    /// Get baseline statistics (for debugging/monitoring)
    pub fn get_baseline(&self) -> ([f32; 4], [f32; 4]) {
        (self.baseline_means, self.baseline_stddevs)
    }
}

/// Method used to detect an anomaly
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionMethod {
    Zscore,
    NeuralNetwork,
    Hybrid,
}

/// Anomaly event for logging and alerts
#[derive(Debug, Clone)]
pub struct AnomalyEvent {
    /// Container that triggered the anomaly
    pub container_id: String,
    /// Metric that was anomalous (or "multi-variate")
    pub metric: String,
    /// Current value of the metric
    pub current_value: f32,
    /// Baseline mean for the metric
    pub baseline_mean: f32,
    /// Baseline stddev for the metric
    pub baseline_stddev: f32,
    /// Z-score of the current value
    pub zscore: f32,
    /// Method used to detect
    pub detection_method: DetectionMethod,
    /// Confidence level (0.0 - 1.0)
    pub confidence: f32,
}

impl AnomalyEvent {
    /// Format for logging
    pub fn to_log_string(&self) -> String {
        format!(
            "[ai-anomaly] container {}: {} anomaly detected (value={:.2}, baseline={:.2}±{:.2}, zscore={:.2}, method={:?}, confidence={:.0}%)",
            self.container_id,
            self.metric,
            self.current_value,
            self.baseline_mean,
            self.baseline_stddev,
            self.zscore,
            self.detection_method,
            self.confidence * 100.0
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zscore_detects_anomaly() {
        // Z-score of 2.0 with threshold 3.0 is NOT anomalous
        let normal = zscore(2.0, 0.0, 1.0, 3.0);
        assert!(!normal.is_anomalous());

        // Z-score of 5.0 with threshold 3.0 IS anomalous
        let anomalous = zscore(5.0, 0.0, 1.0, 3.0);
        assert!(anomalous.is_anomalous());
    }

    #[test]
    fn neural_detector_creation() {
        let detector = NeuralAnomalyDetector::new(5, 0.1);
        assert!(!detector.is_trained());
    }

    #[test]
    fn loads_trained_anomaly_artifact_and_scores_distance() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("model.json");
        std::fs::write(
            &path,
            serde_json::json!({
                "model_type": "anomaly-detector",
                "artifact": {
                    "centroid": [0.1, 0.2, 0.1],
                    "normal_mean_distance": 0.02,
                    "anomaly_mean_distance": 1.2
                }
            })
            .to_string(),
        )
        .expect("artifact");

        let mut detector = NeuralAnomalyDetector::from_model_artifact(&path).expect("load model");
        assert!(detector.is_trained());
        let normal = detector.detect(&[0.1, 0.2, 0.1]);
        let anomaly = detector.detect(&[0.9, 0.9, 0.9]);
        assert!(!normal.is_anomalous());
        assert!(anomaly.is_anomalous());
    }

    #[test]
    fn neural_detector_training() {
        let mut detector = NeuralAnomalyDetector::new(3, 0.5);

        // Create some normal training samples
        let normal_samples: Vec<Vec<f32>> = vec![
            vec![0.1, 0.2, 0.1],
            vec![0.15, 0.25, 0.12],
            vec![0.12, 0.22, 0.11],
            vec![0.11, 0.21, 0.09],
        ];

        let trained = detector.train(&normal_samples, 100);
        assert!(trained);
        assert!(detector.is_trained());
    }

    #[test]
    fn neural_detector_anomaly_detection() {
        let mut detector = NeuralAnomalyDetector::new(3, 0.1);

        // Train on normal patterns
        let normal_samples: Vec<Vec<f32>> = vec![
            vec![0.1, 0.2, 0.1],
            vec![0.15, 0.25, 0.12],
            vec![0.12, 0.22, 0.11],
        ];
        detector.train(&normal_samples, 50);

        // Test on normal data (should have low reconstruction error)
        let normal_result = detector.detect(&[0.12, 0.21, 0.10]);

        // Test on anomalous data (should have higher reconstruction error)
        let anomaly_result = detector.detect(&[0.9, 0.95, 0.92]);

        // Anomalous data should have higher reconstruction error
        assert!(anomaly_result.score > normal_result.score);
    }

    #[test]
    fn anomaly_training_snapshot_round_trips_and_rejects_identity_forks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("anomaly.json");
        let samples = vec![vec![0.1, 0.2, 0.3], vec![0.2, 0.3, 0.4]];
        save_training_snapshot(&path, "container-a", &samples).expect("save");
        let restored = load_training_snapshot(&path, "container-a").expect("load");
        assert_eq!(restored, samples);
        assert!(load_training_snapshot(&path, "container-b").is_err());
    }

    #[test]
    fn container_metrics_to_features() {
        let metrics = ContainerMetrics {
            cpu_percent: 50.0,
            memory_percent: 25.0,
            io_read_bytes: 1000,
            io_write_bytes: 500,
            network_bytes: 2000,
        };

        let features = metrics.to_features(2000, 4000);

        assert_eq!(features.len(), 5);
        assert!((features[0] - 0.5).abs() < 0.01); // cpu
        assert!((features[1] - 0.25).abs() < 0.01); // memory
        assert!((features[2] - 0.75).abs() < 0.01); // io
        assert!((features[3] - 0.5).abs() < 0.01); // network
    }

    // Task 5.2 Tests

    #[test]
    fn anomaly_state_starts_in_learning_phase() {
        let state = ContainerAnomalyState::new("test-container");
        assert_eq!(state.get_phase(), DetectionPhase::Learning);
    }

    #[test]
    fn learning_phase_no_anomalies() {
        let mut state = ContainerAnomalyState::new("test").with_learning_duration(0); // Immediate transition

        // Even with immediate transition, first call should collect sample
        let metrics = ContainerMetrics {
            cpu_percent: 50.0,
            ..Default::default()
        };

        // Should transition after this call since learning_duration is 0
        let _ = state.record_and_detect(&metrics, 1000, 1000);
        assert_eq!(state.get_phase(), DetectionPhase::Active);
    }

    #[test]
    fn anomaly_event_formatting() {
        let event = AnomalyEvent {
            container_id: "abc123".to_string(),
            metric: "cpu".to_string(),
            current_value: 95.0,
            baseline_mean: 30.0,
            baseline_stddev: 10.0,
            zscore: 6.5,
            detection_method: DetectionMethod::Zscore,
            confidence: 0.85,
        };

        let log = event.to_log_string();
        assert!(log.contains("abc123"));
        assert!(log.contains("cpu"));
        assert!(log.contains("95"));
        assert!(log.contains("Zscore"));
    }

    #[test]
    fn anomaly_event_formatting_supports_hybrid_method() {
        let event = AnomalyEvent {
            container_id: "abc123".to_string(),
            metric: "hybrid(cpu+multi-variate)".to_string(),
            current_value: 1.2,
            baseline_mean: 0.4,
            baseline_stddev: 0.1,
            zscore: 3.5,
            detection_method: DetectionMethod::Hybrid,
            confidence: 0.9,
        };
        let log = event.to_log_string();
        assert!(log.contains("Hybrid"));
        assert!(log.contains("hybrid(cpu+multi-variate)"));
    }
}
