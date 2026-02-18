//! Async telemetry collection for AI training data.
//!
//! Collects container lifecycle events and writes them to .rvf files
//! for training resource prediction and anomaly detection models.

use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Events emitted by the container runtime for AI training
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TelemetryEvent {
    /// Container stopped normally (exit code 0)
    ContainerStopped {
        container_id: String,
        image: String,
        cpu_mean_percent: f32,
        memory_peak_bytes: u64,
        uptime_secs: u64,
    },
    /// Container was OOM-killed (exit code 137)
    OomKilled {
        container_id: String,
        image: String,
        memory_at_kill_bytes: u64,
        memory_limit_bytes: u64,
        uptime_secs: u64,
    },
    /// Container crashed (non-zero, non-OOM exit)
    ContainerCrashed {
        container_id: String,
        image: String,
        exit_code: i32,
        restart_count: u32,
        uptime_secs: u64,
    },
    /// Container passed health check after extended uptime (>= 1 hour)
    ContainerHealthy {
        container_id: String,
        image: String,
        cpu_percent: f32,
        memory_bytes: u64,
        uptime_secs: u64,
    },
}

impl TelemetryEvent {
    /// Serialize to a JSONL line for batch retraining
    pub fn to_jsonl(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Extract a feature vector for vector similarity storage.
    ///
    /// All values are normalized to [0.0, 1.0]. The fourth element is a
    /// class label: 0.0 = healthy, 0.8 = crash, 1.0 = OOM.
    pub fn to_feature_vector(&self) -> Vec<f32> {
        match self {
            TelemetryEvent::ContainerStopped {
                cpu_mean_percent,
                memory_peak_bytes,
                uptime_secs,
                ..
            } => vec![
                *cpu_mean_percent / 100.0,
                (*memory_peak_bytes as f32) / (4.0 * 1024.0 * 1024.0 * 1024.0), // normalize to 4 GiB
                (*uptime_secs as f32) / 86400.0, // normalize to 1 day
                0.0, // label: healthy
            ],
            TelemetryEvent::OomKilled {
                memory_at_kill_bytes,
                memory_limit_bytes,
                uptime_secs,
                ..
            } => {
                let mem_ratio = if *memory_limit_bytes > 0 {
                    *memory_at_kill_bytes as f32 / *memory_limit_bytes as f32
                } else {
                    1.0
                };
                vec![
                    1.0, // high cpu implied by OOM
                    mem_ratio,
                    (*uptime_secs as f32) / 86400.0,
                    1.0, // label: oom
                ]
            }
            TelemetryEvent::ContainerCrashed {
                exit_code,
                restart_count,
                uptime_secs,
                ..
            } => vec![
                (*exit_code as f32 / 255.0).clamp(0.0, 1.0),
                (*restart_count as f32 / 10.0).clamp(0.0, 1.0),
                (*uptime_secs as f32) / 86400.0,
                0.8, // label: crash
            ],
            TelemetryEvent::ContainerHealthy {
                cpu_percent,
                memory_bytes,
                uptime_secs,
                ..
            } => vec![
                *cpu_percent / 100.0,
                (*memory_bytes as f32) / (4.0 * 1024.0 * 1024.0 * 1024.0),
                (*uptime_secs as f32) / 86400.0,
                0.0, // label: healthy
            ],
        }
    }
}

/// Handle for sending telemetry events to the background collector.
///
/// Cheap to clone; backed by an `mpsc::Sender`.
#[derive(Clone)]
pub struct TelemetrySender(Sender<TelemetryEvent>);

impl TelemetrySender {
    /// Send an event. Silently ignores send errors (collector may have shut down).
    pub fn send(&self, event: TelemetryEvent) {
        let _ = self.0.send(event);
    }
}

/// Background telemetry collector that persists events to disk as JSONL files.
pub struct TelemetryCollector {
    data_dir: PathBuf,
    buffer: Vec<TelemetryEvent>,
    flush_threshold: usize,
}

impl TelemetryCollector {
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            buffer: Vec::with_capacity(256),
            flush_threshold: 64,
        }
    }

    /// Start the collector in a background thread. Returns a sender for events.
    pub fn start(data_dir: PathBuf) -> TelemetrySender {
        let (tx, rx) = mpsc::channel::<TelemetryEvent>();

        thread::Builder::new()
            .name("ferrocrate-ai-collector".to_string())
            .spawn(move || {
                let mut collector = TelemetryCollector::new(data_dir);
                collector.run(rx);
            })
            .expect("failed to spawn AI telemetry collector thread");

        TelemetrySender(tx)
    }

    fn run(&mut self, rx: Receiver<TelemetryEvent>) {
        if let Err(e) = std::fs::create_dir_all(&self.data_dir) {
            eprintln!(
                "[ai-collector] failed to create data dir {:?}: {e}",
                self.data_dir
            );
            return;
        }

        loop {
            match rx.recv_timeout(Duration::from_secs(30)) {
                Ok(event) => {
                    self.buffer.push(event);
                    if self.buffer.len() >= self.flush_threshold {
                        self.flush_to_jsonl();
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if !self.buffer.is_empty() {
                        self.flush_to_jsonl();
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    // All senders dropped — flush remaining and exit.
                    if !self.buffer.is_empty() {
                        self.flush_to_jsonl();
                    }
                    break;
                }
            }
        }
    }

    fn flush_to_jsonl(&mut self) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let path = self.data_dir.join(format!("telemetry-{timestamp}.jsonl"));

        let content: String = self
            .buffer
            .iter()
            .map(|e| e.to_jsonl())
            .collect::<Vec<_>>()
            .join("\n");

        if let Err(e) = std::fs::write(&path, content) {
            eprintln!(
                "[ai-collector] failed to write telemetry to {:?}: {e}",
                path
            );
        } else {
            self.buffer.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_telemetry_event_serialization() {
        let event = TelemetryEvent::ContainerStopped {
            container_id: "abc123".to_string(),
            image: "nginx:alpine".to_string(),
            cpu_mean_percent: 15.5,
            memory_peak_bytes: 52_428_800,
            uptime_secs: 3600,
        };
        let line = event.to_jsonl();
        assert!(!line.is_empty());
        assert!(line.contains("abc123"));
    }

    #[test]
    fn test_feature_vector_dimensions() {
        let event = TelemetryEvent::ContainerHealthy {
            container_id: "test".to_string(),
            image: "test:latest".to_string(),
            cpu_percent: 25.0,
            memory_bytes: 1_000_000,
            uptime_secs: 7200,
        };
        let vec = event.to_feature_vector();
        assert_eq!(vec.len(), 4);
        assert!(vec.iter().all(|&v| v >= 0.0 && v <= 1.0));
    }

    #[test]
    fn test_collector_starts_and_receives() {
        let tmp = TempDir::new().unwrap();
        let sender = TelemetryCollector::start(tmp.path().to_path_buf());

        sender.send(TelemetryEvent::ContainerStopped {
            container_id: "test-container".to_string(),
            image: "alpine:latest".to_string(),
            cpu_mean_percent: 5.0,
            memory_peak_bytes: 10_000_000,
            uptime_secs: 100,
        });

        // Give collector time to process
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Drop sender to signal shutdown
        drop(sender);

        // Give time to flush
        std::thread::sleep(std::time::Duration::from_millis(200));

        // Check that a telemetry file was written
        let entries: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert!(!entries.is_empty(), "expected telemetry file to be written");
    }

    #[test]
    fn test_oom_killed_feature_vector() {
        let event = TelemetryEvent::OomKilled {
            container_id: "oom-test".to_string(),
            image: "leaky:app".to_string(),
            memory_at_kill_bytes: 900_000_000,
            memory_limit_bytes: 1_000_000_000,
            uptime_secs: 1800,
        };
        let vec = event.to_feature_vector();
        assert_eq!(vec.len(), 4);
        assert!((vec[1] - 0.9).abs() < 0.01, "mem ratio should be ~0.9");
        assert_eq!(vec[3], 1.0, "OOM label should be 1.0");
    }
}
