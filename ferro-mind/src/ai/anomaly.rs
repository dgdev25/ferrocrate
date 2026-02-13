//! Anomaly Detection with Neural Networks via ruv-fann
//!
//! Provides z-score based anomaly detection with optional neural network
//! enhancement for more sophisticated pattern recognition.

use ruv_fann::{Network, NetworkBuilder};
use ruv_fann::training::{TrainingData, IncrementalBackprop, TrainingAlgorithm};

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
    let score = if stddev > 0.0 { (current - mean) / stddev } else { 0.0 };
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
}

impl Default for NeuralAnomalyDetector {
    fn default() -> Self {
        Self::new(5, 0.5)  // 5 inputs: cpu, mem, io_read, io_write, network
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
        }
    }

    /// Initialize the neural network with an autoencoder architecture
    ///
    /// Architecture: input -> hidden (compressed) -> output (reconstructed)
    fn init_network(&mut self) {
        let hidden_size = (self.input_size + 1) / 2;  // Compression layer

        self.network = Some(
            NetworkBuilder::new()
                .input_layer(self.input_size)
                .hidden_layer(hidden_size)
                .output_layer(self.input_size)  // Autoencoder: reconstruct input
                .build()
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
                outputs.push(sample.clone());  // Autoencoder reconstructs input
            }
        }

        if inputs.is_empty() {
            return false;
        }

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
        if !self.trained || features.len() != self.input_size {
            return AnomalyScore { score: 0.0, threshold: self.threshold };
        }

        let Some(ref mut network) = self.network else {
            return AnomalyScore { score: 0.0, threshold: self.threshold };
        };

        // Run the autoencoder
        // Handle both Vec<T> and Result<Vec<T>, E> return types depending on version
        let outputs: Vec<f32> = match network.run(features) {
            Ok(v) => v,
            Err(_) => return AnomalyScore { score: f32::MAX, threshold: self.threshold },
        };

        // Calculate reconstruction error (MSE)
        let mut error_sum = 0.0f32;
        for i in 0..features.len().min(outputs.len()) {
            let diff = features[i] - outputs[i];
            error_sum += diff * diff;
        }
        let error = error_sum / features.len() as f32;

        AnomalyScore {
            score: error,
            threshold: self.threshold,
        }
    }

    /// Check if the detector has been trained
    pub fn is_trained(&self) -> bool {
        self.trained
    }

    /// Update the anomaly threshold
    pub fn set_threshold(&mut self, threshold: f32) {
        self.threshold = threshold;
    }
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
            if max_io > 0 { (self.io_read_bytes + self.io_write_bytes) as f32 / max_io as f32 } else { 0.0 },
            if max_network > 0 { self.network_bytes as f32 / max_network as f32 } else { 0.0 },
            // Derived feature: cpu to memory ratio (anomalous if very high or low)
            if self.memory_percent > 0.0 {
                (self.cpu_percent / self.memory_percent).min(10.0) / 10.0
            } else {
                0.0
            },
        ]
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
        assert!((features[0] - 0.5).abs() < 0.01);  // cpu
        assert!((features[1] - 0.25).abs() < 0.01); // memory
        assert!((features[2] - 0.75).abs() < 0.01); // io
        assert!((features[3] - 0.5).abs() < 0.01);  // network
    }
}
