//! Resource prediction and OOM prevention (Task 5.1)
//!
//! This module provides predictive OOM prevention by:
//! 1. Collecting cgroup v2 metrics (memory.current, cpu.stat, pids.current)
//! 2. Analyzing memory growth trends
//! 3. Predicting when memory will exceed limits

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use ruv_fann::{Network, NetworkBuilder};
use ruv_fann::training::{IncrementalBackprop, TrainingAlgorithm, TrainingData};
#[cfg(feature = "rvf-persistence")]
use std::path::Path;

#[cfg(feature = "rvf-persistence")]
use crate::ai::learning::vector_memory::VectorMemory;
#[cfg(feature = "rvf-persistence")]
use crate::ruv::types::{DistanceMetric, VectorEntry, VectorId};

/// A single resource sample from cgroup v2 metrics.
#[derive(Debug, Clone, Copy)]
pub struct ResourceSample {
    /// CPU usage percentage (0.0 - 100.0)
    pub cpu_percent: f32,
    /// Current memory usage in bytes
    pub memory_bytes: u64,
    /// Current process count
    pub pids_count: u64,
    /// Timestamp when sample was collected
    pub timestamp: Instant,
}

/// Predicted resource values.
#[derive(Debug, Clone, Copy)]
pub struct ResourcePrediction {
    /// Predicted CPU percentage
    pub cpu_percent: f32,
    /// Predicted memory usage in bytes
    pub memory_bytes: u64,
    /// Memory growth rate in bytes per second
    pub memory_growth_rate: f64,
}

/// OOM prediction result.
#[derive(Debug, Clone, Copy)]
pub struct OomPrediction {
    /// Estimated time until OOM
    pub time_to_oom: Duration,
    /// Current memory usage
    pub current_memory: u64,
    /// Memory limit
    pub memory_limit: u64,
    /// Predicted peak memory at OOM time
    pub predicted_peak: u64,
    /// Confidence level (0.0 - 1.0)
    pub confidence: f32,
}

/// Resource predictor with trend analysis.
pub struct ResourcePredictor {
    /// Window of recent samples
    window: VecDeque<ResourceSample>,
    /// Maximum samples to keep
    max_len: usize,
    /// Memory limit for OOM prediction (0 = no limit)
    memory_limit: u64,
    /// Minimum samples needed for prediction
    min_samples: usize,
    /// Optional persistent similarity memory for cross-session learning
    #[cfg(feature = "rvf-persistence")]
    memory: Option<VectorMemory>,
    /// Feed-forward network trained on sequential resource samples.
    neural_network: Option<Network<f32>>,
    neural_trained: bool,
    neural_last_train_len: usize,
    neural_memory_scale: f32,
    neural_pids_scale: f32,
}

impl Default for ResourcePredictor {
    fn default() -> Self {
        Self::new(60) // Default: 60 samples at 30s intervals = 30 minutes of history
    }
}

impl ResourcePredictor {
    /// Create a new predictor with specified window size.
    ///
    /// At 30-second sampling intervals, a window of 60 samples provides
    /// 30 minutes of history for trend analysis.
    pub fn new(max_len: usize) -> Self {
        Self {
            window: VecDeque::new(),
            max_len: max_len.max(3), // Need at least 3 samples for trend
            memory_limit: 0,
            min_samples: 3,
            #[cfg(feature = "rvf-persistence")]
            memory: None,
            neural_network: None,
            neural_trained: false,
            neural_last_train_len: 0,
            neural_memory_scale: 1.0,
            neural_pids_scale: 1.0,
        }
    }

    /// Create a predictor with RVF-backed persistence in `data_dir`.
    #[cfg(feature = "rvf-persistence")]
    pub fn persistent(max_len: usize, data_dir: &Path) -> Result<Self, String> {
        let mut predictor = Self::new(max_len);
        let memory_path = data_dir.join("resource-patterns.rvf");
        predictor.memory = Some(VectorMemory::with_backend(&memory_path, 3)?);
        Ok(predictor)
    }

    /// Set the memory limit for OOM prediction.
    pub fn with_memory_limit(mut self, limit: u64) -> Self {
        self.memory_limit = limit;
        self
    }

    /// Add a new sample to the prediction window.
    pub fn push(&mut self, sample: ResourceSample) {
        self.window.push_back(sample);
        if self.window.len() > self.max_len {
            self.window.pop_front();
        }
        self.maybe_train_neural_model();

        #[cfg(feature = "rvf-persistence")]
        if let Some(memory) = self.memory.as_mut() {
            let mut metadata = HashMap::new();
            metadata.insert("cpu_percent".to_string(), serde_json::json!(sample.cpu_percent));
            metadata.insert("memory_bytes".to_string(), serde_json::json!(sample.memory_bytes));
            metadata.insert("pids_count".to_string(), serde_json::json!(sample.pids_count));
            let id = format!("sample-{:?}", sample.timestamp);
            memory.insert(VectorEntry {
                id: Some(VectorId::from(id)),
                vector: Self::sample_vector(&sample),
                metadata: Some(metadata),
            });
        }
    }

    /// Get the number of samples collected.
    pub fn sample_count(&self) -> usize {
        self.window.len()
    }

    /// Clear all samples.
    pub fn clear(&mut self) {
        self.window.clear();
    }

    /// Predict average resource usage.
    pub fn predict(&mut self) -> Option<ResourcePrediction> {
        if self.window.len() < self.min_samples {
            return None;
        }

        let mut cpu = 0.0f32;
        let mut mem = 0u64;
        let mut growth_rates = Vec::new();

        for (i, sample) in self.window.iter().enumerate() {
            cpu += sample.cpu_percent;
            mem = mem.saturating_add(sample.memory_bytes);

            // Calculate growth rate between consecutive samples
            if i > 0 {
                let prev = &self.window[i - 1];
                let time_diff = sample.timestamp.duration_since(prev.timestamp).as_secs_f64();
                if time_diff > 0.0 {
                    let mem_diff = sample.memory_bytes.saturating_sub(prev.memory_bytes) as f64;
                    growth_rates.push(mem_diff / time_diff);
                }
            }
        }

        let count = self.window.len() as f32;
        let avg_cpu = cpu / count;
        let avg_mem = mem / self.window.len() as u64;

        // Calculate average growth rate (bytes/second)
        let avg_growth_rate = if growth_rates.is_empty() {
            0.0
        } else {
            growth_rates.iter().sum::<f64>() / growth_rates.len() as f64
        };

        let mut prediction = ResourcePrediction {
            cpu_percent: avg_cpu,
            memory_bytes: avg_mem,
            memory_growth_rate: avg_growth_rate,
        };

        #[cfg(feature = "rvf-persistence")]
        if let Some(memory) = self.memory.as_ref() {
            if let Some(latest) = self.window.back() {
                let neighbors = memory.search(&Self::sample_vector(latest), 3, DistanceMetric::Cosine);
                if !neighbors.is_empty() {
                    let mut mem_sum = prediction.memory_bytes as f64;
                    let mut cpu_sum = prediction.cpu_percent as f64;
                    let mut count = 1.0;
                    for neighbor in neighbors {
                        let Some(meta) = neighbor.metadata else { continue };
                        let Some(mem) = meta.get("memory_bytes").and_then(|v| v.as_u64()) else { continue };
                        let Some(cpu) = meta.get("cpu_percent").and_then(|v| v.as_f64()) else { continue };
                        mem_sum += mem as f64;
                        cpu_sum += cpu;
                        count += 1.0;
                    }
                    prediction.memory_bytes = (mem_sum / count) as u64;
                    prediction.cpu_percent = (cpu_sum / count) as f32;
                }
            }
        }

        if self.neural_trained {
            if let Some(latest) = self.window.back().copied() {
                if let Some(neural) = self.predict_with_neural(latest) {
                    prediction.cpu_percent = (prediction.cpu_percent * 0.35) + (neural.0 * 0.65);
                    prediction.memory_bytes =
                        ((prediction.memory_bytes as f64 * 0.35) + (neural.1 as f64 * 0.65)) as u64;
                }
            }
        }

        Some(prediction)
    }

    /// Predict when OOM will occur based on current memory growth trend.
    ///
    /// Returns `Some(OomPrediction)` if OOM is predicted within the horizon,
    /// or `None` if no OOM risk detected or insufficient data.
    pub fn predict_oom(&self, horizon: Duration) -> Option<OomPrediction> {
        // No limit set = no OOM prediction possible
        if self.memory_limit == 0 {
            return None;
        }

        // Need enough samples for trend analysis
        if self.window.len() < self.min_samples {
            return None;
        }

        let latest = self.window.back()?;
        let current_memory = latest.memory_bytes;

        // Already at or over limit
        if current_memory >= self.memory_limit {
            return Some(OomPrediction {
                time_to_oom: Duration::ZERO,
                current_memory,
                memory_limit: self.memory_limit,
                predicted_peak: current_memory,
                confidence: 1.0,
            });
        }

        // Calculate growth rate using linear regression on recent samples
        let growth_rate = self.calculate_memory_growth_rate();

        // No growth = no OOM risk
        if growth_rate <= 0.0 {
            return None;
        }

        let remaining = self.memory_limit.saturating_sub(current_memory);
        let seconds_to_oom = remaining as f64 / growth_rate;
        let time_to_oom = Duration::from_secs_f64(seconds_to_oom);

        // OOM beyond horizon = no alert
        if time_to_oom > horizon {
            return None;
        }

        // Calculate confidence based on sample count and consistency
        let confidence = self.calculate_confidence();

        Some(OomPrediction {
            time_to_oom,
            current_memory,
            memory_limit: self.memory_limit,
            predicted_peak: self.memory_limit,
            confidence,
        })
    }

    /// Calculate memory growth rate using linear regression.
    fn calculate_memory_growth_rate(&self) -> f64 {
        if self.window.len() < 2 {
            return 0.0;
        }

        // CQ-01: Safe to unwrap because we check len() >= 2 above
        let first = self.window.front().expect("window should have first element");
        let last = self.window.back().expect("window should have last element");

        let time_diff = last.timestamp.duration_since(first.timestamp).as_secs_f64();
        if time_diff <= 0.0 {
            return 0.0;
        }

        let mem_diff = last.memory_bytes.saturating_sub(first.memory_bytes) as f64;
        mem_diff / time_diff
    }

    /// Calculate prediction confidence based on sample consistency.
    fn calculate_confidence(&self) -> f32 {
        if self.window.len() < self.min_samples {
            return 0.0;
        }

        // More samples = higher confidence
        let sample_factor = (self.window.len() as f32 / self.max_len as f32).min(1.0);

        // Calculate variance in growth rate
        let growth_rates: Vec<f64> = self
            .window
            .iter()
            .collect::<Vec<_>>()
            .windows(2)
            .filter_map(|w| {
                let time_diff = w[1].timestamp.duration_since(w[0].timestamp).as_secs_f64();
                if time_diff > 0.0 {
                    let mem_diff = w[1].memory_bytes.saturating_sub(w[0].memory_bytes) as f64;
                    Some(mem_diff / time_diff)
                } else {
                    None
                }
            })
            .collect();

        if growth_rates.len() < 2 {
            return 0.3 * sample_factor;
        }

        // Calculate coefficient of variation (lower = more consistent = higher confidence)
        let mean = growth_rates.iter().sum::<f64>() / growth_rates.len() as f64;
        if mean.abs() < 1e-10 {
            return 0.5 * sample_factor;
        }

        let variance: f64 = growth_rates.iter().map(|x| (x - mean).powi(2)).sum::<f64>()
            / growth_rates.len() as f64;
        let std_dev = variance.sqrt();
        let cv = std_dev / mean.abs();

        // CV < 0.5 = high consistency, CV > 2.0 = low consistency
        let consistency_factor = if cv < 0.5 {
            1.0
        } else if cv > 2.0 {
            0.3
        } else {
            1.0 - (cv - 0.5) / 1.5 * 0.7
        };

        sample_factor * consistency_factor as f32
    }

    /// Get the latest memory sample.
    pub fn latest_memory(&self) -> Option<u64> {
        self.window.back().map(|s| s.memory_bytes)
    }

    /// Get the memory limit.
    pub fn get_memory_limit(&self) -> u64 {
        self.memory_limit
    }

    /// Set the memory limit at runtime.
    pub fn set_memory_limit(&mut self, limit: u64) {
        self.memory_limit = limit;
    }

    fn sample_vector(sample: &ResourceSample) -> Vec<f32> {
        vec![
            sample.cpu_percent / 100.0,
            sample.memory_bytes as f32,
            sample.pids_count as f32,
        ]
    }

    fn maybe_train_neural_model(&mut self) {
        const MIN_SEQUENTIAL_SAMPLES: usize = 16;
        const RETRAIN_INTERVAL: usize = 8;
        const TRAIN_EPOCHS: usize = 30;

        if self.window.len() < MIN_SEQUENTIAL_SAMPLES {
            return;
        }
        if self.window.len().saturating_sub(self.neural_last_train_len) < RETRAIN_INTERVAL {
            return;
        }

        let memory_scale = self
            .window
            .iter()
            .map(|s| s.memory_bytes)
            .max()
            .unwrap_or(1) as f32;
        let pids_scale = self.window.iter().map(|s| s.pids_count).max().unwrap_or(1) as f32;
        if memory_scale <= 0.0 || pids_scale <= 0.0 {
            return;
        }

        let samples = self.window.iter().copied().collect::<Vec<_>>();
        let mut inputs = Vec::with_capacity(samples.len().saturating_sub(1));
        let mut outputs = Vec::with_capacity(samples.len().saturating_sub(1));
        for pair in samples.windows(2) {
            let current = pair[0];
            let next = pair[1];
            inputs.push(vec![
                (current.cpu_percent / 100.0).clamp(0.0, 1.0),
                (current.memory_bytes as f32 / memory_scale).clamp(0.0, 1.0),
                (current.pids_count as f32 / pids_scale).clamp(0.0, 1.0),
            ]);
            outputs.push(vec![
                (next.cpu_percent / 100.0).clamp(0.0, 1.0),
                (next.memory_bytes as f32 / memory_scale).clamp(0.0, 1.0),
                (next.pids_count as f32 / pids_scale).clamp(0.0, 1.0),
            ]);
        }

        if inputs.len() < 8 {
            return;
        }

        let mut network = NetworkBuilder::new()
            .input_layer(3)
            .hidden_layer(8)
            .output_layer(3)
            .build();
        let training_data = TrainingData { inputs, outputs };
        let mut trainer = IncrementalBackprop::new(0.01);
        for _ in 0..TRAIN_EPOCHS {
            if trainer.train_epoch(&mut network, &training_data).is_err() {
                return;
            }
        }

        self.neural_network = Some(network);
        self.neural_trained = true;
        self.neural_last_train_len = self.window.len();
        self.neural_memory_scale = memory_scale.max(1.0);
        self.neural_pids_scale = pids_scale.max(1.0);
    }

    fn predict_with_neural(&mut self, latest: ResourceSample) -> Option<(f32, u64)> {
        let network = self.neural_network.as_mut()?;
        let output = network
            .run(&[
                (latest.cpu_percent / 100.0).clamp(0.0, 1.0),
                (latest.memory_bytes as f32 / self.neural_memory_scale).clamp(0.0, 1.0),
                (latest.pids_count as f32 / self.neural_pids_scale).clamp(0.0, 1.0),
            ])
            .ok()?;
        if output.len() < 2 {
            return None;
        }
        let cpu = (output[0].clamp(0.0, 1.0) * 100.0).clamp(0.0, 100.0);
        let memory = (output[1].clamp(0.0, 1.0) * self.neural_memory_scale)
            .round()
            .max(0.0) as u64;
        Some((cpu, memory))
    }

    pub fn has_neural_model(&self) -> bool {
        self.neural_trained && self.neural_network.is_some()
    }
}

/// Cgroup v2 metrics read from `/sys/fs/cgroup/<cgroup>/`.
#[derive(Debug, Clone, Copy, Default)]
pub struct CgroupMetrics {
    /// Current memory usage (memory.current)
    pub memory_current: u64,
    /// Memory limit (memory.max), 0 = no limit / max
    pub memory_max: u64,
    /// Current process count (pids.current)
    pub pids_current: u64,
    /// CPU usage in microseconds (cpu.stat usage_usec)
    pub cpu_usage_usec: u64,
}

/// Read cgroup v2 metrics from the cgroup filesystem.
///
/// This is a helper function that can be called from ferro-core.
pub fn read_cgroup_metrics(cgroup_path: &std::path::Path) -> std::io::Result<CgroupMetrics> {
    use std::fs;

    let mut metrics = CgroupMetrics::default();

    // Read memory.current
    let memory_current_path = cgroup_path.join("memory.current");
    if memory_current_path.exists() {
        if let Ok(content) = fs::read_to_string(&memory_current_path) {
            metrics.memory_current = content.trim().parse().unwrap_or(0);
        }
    }

    // Read memory.max
    let memory_max_path = cgroup_path.join("memory.max");
    if memory_max_path.exists() {
        if let Ok(content) = fs::read_to_string(&memory_max_path) {
            let trimmed = content.trim();
            if trimmed != "max" {
                metrics.memory_max = trimmed.parse().unwrap_or(0);
            }
        }
    }

    // Read pids.current
    let pids_path = cgroup_path.join("pids.current");
    if pids_path.exists() {
        if let Ok(content) = fs::read_to_string(&pids_path) {
            metrics.pids_current = content.trim().parse().unwrap_or(0);
        }
    }

    // Read cpu.stat for usage_usec
    let cpu_stat_path = cgroup_path.join("cpu.stat");
    if cpu_stat_path.exists() {
        if let Ok(content) = fs::read_to_string(&cpu_stat_path) {
            for line in content.lines() {
                if line.starts_with("usage_usec ") {
                    if let Some(value) = line.split_whitespace().nth(1) {
                        metrics.cpu_usage_usec = value.parse().unwrap_or(0);
                    }
                    break;
                }
            }
        }
    }

    Ok(metrics)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sample(memory: u64, delay_ms: u64) -> ResourceSample {
        std::thread::sleep(Duration::from_millis(delay_ms));
        ResourceSample {
            cpu_percent: 10.0,
            memory_bytes: memory,
            pids_count: 1,
            timestamp: Instant::now(),
        }
    }

    #[test]
    fn predictor_starts_empty() {
        let mut p = ResourcePredictor::new(10);
        assert_eq!(p.sample_count(), 0);
        assert!(p.predict().is_none());
    }

    #[test]
    fn predictor_needs_min_samples() {
        let mut p = ResourcePredictor::new(10);
        p.push(make_sample(1000, 1));
        p.push(make_sample(2000, 1));
        assert!(p.predict().is_none()); // Only 2 samples
    }

    #[test]
    fn predictor_averages_samples() {
        let mut p = ResourcePredictor::new(10);
        for i in 0..5 {
            p.push(ResourceSample {
                cpu_percent: 20.0 + i as f32,
                memory_bytes: 1000 + i * 100,
                pids_count: 1,
                timestamp: Instant::now(),
            });
        }
        let pred = p.predict().expect("should have prediction");
        // Average of 20,21,22,23,24 = 22
        assert!((pred.cpu_percent - 22.0).abs() < 0.1);
    }

    #[test]
    fn predictor_trains_neural_model_for_stable_sequences() {
        let base = Instant::now();
        let mut p = ResourcePredictor::new(64);
        for i in 0..24 {
            p.push(ResourceSample {
                cpu_percent: 20.0 + (i as f32 * 0.2),
                memory_bytes: 100_000 + i as u64 * 2_000,
                pids_count: 4 + (i as u64 % 2),
                timestamp: base + Duration::from_secs(i as u64),
            });
        }
        assert!(p.has_neural_model());
        let pred = p.predict().expect("predict");
        assert!(pred.memory_bytes > 0);
        assert!(pred.cpu_percent > 0.0);
    }

    #[test]
    fn no_oom_prediction_without_limit() {
        let mut p = ResourcePredictor::new(10);
        for i in 0..5 {
            p.push(make_sample(1000 + i * 100, 1));
        }
        assert!(p.predict_oom(Duration::from_secs(3600)).is_none());
    }

    #[test]
    fn predicts_oom_with_growth() {
        let mut p = ResourcePredictor::new(10).with_memory_limit(100_000);

        // Simulate linear growth from 10KB to 50KB over ~1 second
        // Growth rate: 40KB/s, remaining: 50KB, time to OOM: ~1.25s
        for i in 0..5 {
            p.push(ResourceSample {
                cpu_percent: 10.0,
                memory_bytes: 10_000 + i * 10_000,
                pids_count: 1,
                timestamp: Instant::now() + Duration::from_millis(i * 250),
            });
        }

        let pred = p.predict_oom(Duration::from_secs(300)).expect("should predict OOM");
        assert!(pred.time_to_oom < Duration::from_secs(10));
        assert!(pred.confidence > 0.0);
    }

    #[test]
    fn no_oom_if_memory_stable() {
        let mut p = ResourcePredictor::new(10).with_memory_limit(100_000);

        // Memory stays constant at 50KB
        for _ in 0..5 {
            p.push(ResourceSample {
                cpu_percent: 10.0,
                memory_bytes: 50_000,
                pids_count: 1,
                timestamp: Instant::now(),
            });
        }

        assert!(p.predict_oom(Duration::from_secs(3600)).is_none());
    }

    #[test]
    fn oom_beyond_horizon_not_reported() {
        let mut p = ResourcePredictor::new(10).with_memory_limit(1_000_000_000); // 1GB

        // Very slow growth
        for i in 0..5 {
            p.push(ResourceSample {
                cpu_percent: 10.0,
                memory_bytes: 1000 + i,
                pids_count: 1,
                timestamp: Instant::now() + Duration::from_millis(i * 250),
            });
        }

        // OOM would take days/weeks at this rate
        assert!(p.predict_oom(Duration::from_secs(300)).is_none());
    }

    #[test]
    fn already_at_limit_zero_time() {
        let mut p = ResourcePredictor::new(10).with_memory_limit(1000);

        for _ in 0..3 {
            p.push(ResourceSample {
                cpu_percent: 10.0,
                memory_bytes: 1000,
                pids_count: 1,
                timestamp: Instant::now(),
            });
        }

        let pred = p.predict_oom(Duration::from_secs(300)).expect("should predict OOM");
        assert_eq!(pred.time_to_oom, Duration::ZERO);
        assert_eq!(pred.confidence, 1.0);
    }
}
