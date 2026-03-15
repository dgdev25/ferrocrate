//! Test metrics collection for performance analysis and reporting.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// A single metric measurement
#[derive(Debug, Clone)]
pub struct Metric {
    pub name: String,
    pub value: f64,
    pub unit: String,
    pub timestamp: Instant,
    pub tags: HashMap<String, String>,
}

impl Metric {
    pub fn new(name: impl Into<String>, value: f64, unit: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value,
            unit: unit.into(),
            timestamp: Instant::now(),
            tags: HashMap::new(),
        }
    }

    pub fn with_tag(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.tags.insert(key.into(), value.into());
        self
    }
}

/// Metrics collector for aggregating test metrics
#[derive(Debug, Clone, Default)]
pub struct MetricsCollector {
    metrics: Vec<Metric>,
    timers: HashMap<String, Instant>,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Start a timer
    pub fn start_timer(&mut self, name: impl Into<String>) {
        self.timers.insert(name.into(), Instant::now());
    }

    /// End a timer and record duration
    pub fn end_timer(&mut self, name: &str) -> Option<Duration> {
        let start = self.timers.remove(name)?;
        let duration = start.elapsed();
        self.metrics.push(Metric::new(
            format!("{}.duration_ms", name),
            duration.as_millis() as f64,
            "ms",
        ).with_tag("timer", name));
        Some(duration)
    }

    /// Record a metric
    pub fn record(&mut self, metric: Metric) {
        self.metrics.push(metric);
    }

    /// Get all metrics
    pub fn all(&self) -> &[Metric] {
        &self.metrics
    }

    /// Get metrics by name prefix
    pub fn by_prefix(&self, prefix: &str) -> Vec<&Metric> {
        self.metrics
            .iter()
            .filter(|m| m.name.starts_with(prefix))
            .collect()
    }

    /// Calculate statistics for numeric metrics
    pub fn stats(&self, name: &str) -> Option<MetricStats> {
        let values: Vec<f64> = self.metrics
            .iter()
            .filter(|m| m.name == name)
            .map(|m| m.value)
            .collect();

        if values.is_empty() {
            return None;
        }

        let count = values.len() as f64;
        let sum: f64 = values.iter().sum();
        let mean = sum / count;
        let min = values.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = values.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

        let variance = if count > 1.0 {
            values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (count - 1.0)
        } else {
            0.0
        };
        let std_dev = variance.sqrt();

        Some(MetricStats {
            count: count as usize,
            sum,
            mean,
            min,
            max,
            std_dev,
        })
    }
}

/// Statistics for a set of metrics
#[derive(Debug, Clone, Copy)]
pub struct MetricStats {
    pub count: usize,
    pub sum: f64,
    pub mean: f64,
    pub min: f64,
    pub max: f64,
    pub std_dev: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_collector_timer() {
        let mut collector = MetricsCollector::new();
        collector.start_timer("test_op");

        std::thread::sleep(std::time::Duration::from_millis(10));

        let duration = collector.end_timer("test_op").expect("timer");
        assert!(duration.as_millis() >= 10);

        let stats = collector.stats("test_op.duration_ms").expect("stats");
        assert_eq!(stats.count, 1);
    }

    #[test]
    fn test_metrics_with_tags() {
        let mut collector = MetricsCollector::new();
        collector.record(
            Metric::new("container.startup_time", 150.0, "ms")
                .with_tag("container", "web")
                .with_tag("priority", "P0"),
        );

        let metrics = collector.all();
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].tags.get("container"), Some(&"web".to_string()));
    }
}
