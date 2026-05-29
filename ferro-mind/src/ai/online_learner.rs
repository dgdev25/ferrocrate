//! Online learning scheduler for incremental model updates.
//!
//! Monitors the telemetry directory and triggers model retraining
//! when enough new samples have accumulated.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;
use tracing::{info, warn};

use super::anomaly::NeuralAnomalyDetector;
use super::collector::TelemetryEvent;

/// Configuration for the online learning scheduler.
#[derive(Debug, Clone)]
pub struct OnlineLearnerConfig {
    /// Directory containing telemetry .jsonl files
    pub telemetry_dir: PathBuf,
    /// Directory for model .rvf files and the telemetry archive
    pub models_dir: PathBuf,
    /// Minimum number of new events required to trigger retraining
    pub min_events_to_retrain: usize,
    /// How often to check for new data
    pub check_interval: Duration,
}

impl Default for OnlineLearnerConfig {
    fn default() -> Self {
        Self {
            telemetry_dir: PathBuf::from("/var/lib/ferrocrate/ai/telemetry"),
            models_dir: PathBuf::from("/var/lib/ferrocrate/ai/models"),
            min_events_to_retrain: 100,
            check_interval: Duration::from_secs(300), // 5 minutes
        }
    }
}

/// Count non-empty lines across all `.jsonl` files in `telemetry_dir`.
///
/// Returns 0 if the directory cannot be read.
pub fn count_new_samples(telemetry_dir: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(telemetry_dir) else {
        return 0;
    };

    entries
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "jsonl")
                .unwrap_or(false)
        })
        .map(|e| {
            std::fs::read_to_string(e.path())
                .unwrap_or_default()
                .lines()
                .filter(|l| !l.trim().is_empty())
                .count()
        })
        .sum()
}

/// Start the online learning scheduler in a background thread.
///
/// Returns immediately; retraining happens in the background. The spawned
/// thread runs for the lifetime of the process.
pub fn start_online_learner(config: OnlineLearnerConfig) {
    thread::Builder::new()
        .name("ferrocrate-online-learner".to_string())
        .spawn(move || {
            run_online_learner(&config);
        })
        .expect("failed to spawn online learner thread");
}

fn run_online_learner(config: &OnlineLearnerConfig) {
    loop {
        thread::sleep(config.check_interval);

        let sample_count = count_new_samples(&config.telemetry_dir);

        if sample_count >= config.min_events_to_retrain {
            info!(
                samples = sample_count,
                "online learner: new samples found, triggering incremental retrain"
            );

            match run_incremental_retrain(config) {
                Ok(()) => {
                    info!("online learner: retrain complete");
                    archive_telemetry(&config.telemetry_dir, &config.models_dir);
                }
                Err(e) => {
                    warn!(error = %e, "online learner: retrain failed, keeping previous model");
                }
            }
        }
    }
}

/// Read all JSONL telemetry files and run incremental training on a new
/// `NeuralAnomalyDetector` using healthy/stopped events.
///
/// # Errors
/// Returns an error string when the directory is unreadable, there are
/// insufficient healthy samples, or the neural training step fails.
fn run_incremental_retrain(config: &OnlineLearnerConfig) -> Result<(), String> {
    let mut healthy_samples: Vec<Vec<f32>> = Vec::new();

    let entries = std::fs::read_dir(&config.telemetry_dir).map_err(|e| e.to_string())?;

    for entry in entries.filter_map(|e| e.ok()) {
        if entry
            .path()
            .extension()
            .map(|e| e != "jsonl")
            .unwrap_or(true)
        {
            continue;
        }

        let file = std::fs::File::open(entry.path()).map_err(|e| e.to_string())?;
        let reader = BufReader::new(file);

        for line in reader.lines().map_while(|l| l.ok()) {
            if let Ok(event) = serde_json::from_str::<TelemetryEvent>(&line) {
                // Only train on events that represent normal / healthy behaviour.
                if matches!(
                    event,
                    TelemetryEvent::ContainerHealthy { .. }
                        | TelemetryEvent::ContainerStopped { .. }
                ) {
                    let features = event.to_feature_vector();
                    if features.len() == 4 {
                        // Drop the label (index 3); feed the first 3 features.
                        healthy_samples.push(features[..3].to_vec());
                    }
                }
            }
        }
    }

    if healthy_samples.len() < 10 {
        return Err(format!(
            "insufficient healthy samples for training: {} (need ≥10)",
            healthy_samples.len()
        ));
    }

    let mut detector = NeuralAnomalyDetector::new(3, 0.5);
    let trained = detector.train(&healthy_samples, 100);

    if !trained {
        return Err("neural training returned false".to_string());
    }

    info!(
        healthy_samples = healthy_samples.len(),
        "online learner: trained anomaly detector"
    );

    Ok(())
}

/// Move processed `.jsonl` files into `<models_dir>/telemetry-archive/`.
fn archive_telemetry(telemetry_dir: &Path, models_dir: &Path) {
    let archive_dir = models_dir.join("telemetry-archive");
    let _ = std::fs::create_dir_all(&archive_dir);

    let Ok(entries) = std::fs::read_dir(telemetry_dir) else {
        return;
    };

    for entry in entries.filter_map(|e| e.ok()) {
        if entry
            .path()
            .extension()
            .map(|e| e == "jsonl")
            .unwrap_or(false)
        {
            let dest = archive_dir.join(entry.file_name());
            let _ = std::fs::rename(entry.path(), dest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_count_samples_empty_dir() {
        let tmp = TempDir::new().unwrap();
        assert_eq!(count_new_samples(tmp.path()), 0);
    }

    #[test]
    fn test_count_samples_with_jsonl() {
        let tmp = TempDir::new().unwrap();
        fs::write(
            tmp.path().join("telemetry-1.jsonl"),
            "{\"ContainerStopped\":{}}\n{\"ContainerHealthy\":{}}\n",
        )
        .unwrap();
        fs::write(
            tmp.path().join("telemetry-2.jsonl"),
            "{\"ContainerCrashed\":{}}\n",
        )
        .unwrap();
        // Non-jsonl file should be ignored.
        fs::write(tmp.path().join("model.rvf"), "binary").unwrap();

        assert_eq!(count_new_samples(tmp.path()), 3);
    }

    #[test]
    fn test_config_default() {
        let config = OnlineLearnerConfig::default();
        assert_eq!(config.min_events_to_retrain, 100);
        assert_eq!(config.check_interval, Duration::from_secs(300));
    }

    #[test]
    fn test_count_samples_nonexistent_dir() {
        let path = Path::new("/nonexistent/path/that/does/not/exist");
        assert_eq!(count_new_samples(path), 0);
    }

    #[test]
    fn test_count_samples_empty_lines_ignored() {
        let tmp = TempDir::new().unwrap();
        // File with blank lines — only non-empty lines should be counted.
        fs::write(
            tmp.path().join("telemetry-sparse.jsonl"),
            "\n{\"ContainerStopped\":{}}\n\n",
        )
        .unwrap();
        assert_eq!(count_new_samples(tmp.path()), 1);
    }
}
