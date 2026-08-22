//! Adaptive Restart with Learning (Task 5.3)
//!
//! Records restart outcomes and learns patterns for intelligent restart decisions.
//! Uses exponential backoff with learned adjustments based on failure patterns.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::VecDeque;
use std::time::Instant;

/// Signal indicating why a restart decision is needed
#[derive(Debug, Clone, Copy)]
pub struct RestartSignal {
    /// Exit code of the crashed process
    pub exit_code: i32,
    /// Number of recent failures (for backoff calculation)
    pub recent_failures: u32,
    /// Container uptime before crash (for pattern detection)
    pub uptime_secs: u64,
}

/// Decision on whether to restart
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartDecision {
    /// Restart the container
    Restart,
    /// Do not restart (too many failures, permanent error, etc.)
    DoNotRestart,
    /// Restart after a delay (backoff)
    RestartAfterDelay { delay_secs: u64 },
}

/// Outcome of a restart attempt
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartOutcome {
    /// Container survived for the observation period after restart
    Success,
    /// Container crashed again within the observation period
    Failure,
}

/// Pattern detected from restart history
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CrashPattern {
    /// No pattern detected yet (insufficient data)
    Unknown,
    /// Crashes consistently after a certain uptime (e.g., memory leak)
    TimeBased { typical_uptime_secs: u64 },
    /// Crashes randomly (no discernible pattern)
    Random,
    /// Crashes immediately on startup (configuration/error)
    ImmediateFailure,
    /// Crashes under memory pressure
    MemoryPressure,
}

/// Record of a restart event
#[derive(Debug, Clone)]
struct RestartRecord {
    /// When the restart occurred
    timestamp: Instant,
    /// Exit code that triggered the restart
    exit_code: i32,
    /// Uptime before crash
    uptime_before_crash_secs: u64,
    /// Outcome of the restart (if known)
    outcome: Option<RestartOutcome>,
    /// Time from restart to outcome
    time_to_outcome_secs: Option<u64>,
}

/// Per-container restart learning state
#[derive(Debug, Clone)]
pub struct AdaptiveRestartPolicy {
    /// Container ID
    pub container_id: String,
    /// Maximum restart attempts before giving up
    max_retries: u32,
    /// Base delay for exponential backoff (seconds)
    base_backoff_secs: u64,
    /// Maximum backoff delay (seconds)
    max_backoff_secs: u64,
    /// Time window to observe restart success (seconds)
    observation_window_secs: u64,
    /// History of restart events
    restart_history: VecDeque<RestartRecord>,
    /// Detected crash pattern
    detected_pattern: CrashPattern,
    /// Pattern confidence (0.0 - 1.0)
    pattern_confidence: f32,
    /// Learned adjustment factor for backoff (multiplier)
    backoff_adjustment: f32,
    /// Learned logistic model weights for restart success probability.
    decision_weights: [f32; 5],
    decision_bias: f32,
    decision_learning_rate: f32,
    last_decision_features: Option<[f32; 5]>,
}

impl AdaptiveRestartPolicy {
    /// Create a new adaptive restart policy for a container
    pub fn new(container_id: &str) -> Self {
        Self {
            container_id: container_id.to_string(),
            max_retries: 5,
            base_backoff_secs: 1,
            max_backoff_secs: 300,        // 5 minutes max
            observation_window_secs: 300, // 5 minutes to observe success
            restart_history: VecDeque::with_capacity(50),
            detected_pattern: CrashPattern::Unknown,
            pattern_confidence: 0.0,
            backoff_adjustment: 1.0,
            decision_weights: [0.35, -0.5, -0.2, 0.4, 0.25],
            decision_bias: 0.1,
            decision_learning_rate: 0.08,
            last_decision_features: None,
        }
    }

    /// Load the portable restart-policy artifact produced by the training
    /// pipeline. The learned success prior only adjusts the policy's bounded
    /// probability estimate; retry ceilings and clean-exit safety rules remain
    /// owned by this policy implementation.
    pub fn from_model_artifact(path: &std::path::Path, container_id: &str) -> Result<Self, String> {
        const MAX_ARTIFACT_BYTES: u64 = 1 << 20;
        if std::fs::metadata(path)
            .map_err(|error| error.to_string())?
            .len()
            > MAX_ARTIFACT_BYTES
        {
            return Err("restart model artifact exceeds 1 MiB".to_string());
        }
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).map_err(|error| error.to_string())?)
                .map_err(|error| format!("invalid restart model artifact: {error}"))?;
        if value.get("model_type").and_then(serde_json::Value::as_str) != Some("restart-policy") {
            return Err("restart model artifact has an unexpected model_type".to_string());
        }
        let artifact = value
            .get("artifact")
            .ok_or_else(|| "restart model artifact is missing artifact data".to_string())?;
        let success_rate = artifact
            .get("success_rate")
            .and_then(serde_json::Value::as_f64)
            .ok_or_else(|| "restart success rate is invalid".to_string())?
            as f32;
        let accuracy = artifact
            .get("baseline_accuracy")
            .and_then(serde_json::Value::as_f64)
            .ok_or_else(|| "restart baseline accuracy is invalid".to_string())?
            as f32;
        for key in ["avg_uptime_success", "avg_uptime_failure"] {
            let uptime = artifact
                .get(key)
                .and_then(serde_json::Value::as_f64)
                .ok_or_else(|| format!("restart {key} is invalid"))?;
            if !uptime.is_finite() || uptime < 0.0 {
                return Err(format!("restart {key} is outside supported bounds"));
            }
        }
        if !success_rate.is_finite()
            || !accuracy.is_finite()
            || !(0.0..=1.0).contains(&success_rate)
            || !(0.0..=1.0).contains(&accuracy)
        {
            return Err("restart model statistics are outside 0..=1".to_string());
        }
        let mut policy = Self::new(container_id);
        let prior = success_rate.clamp(0.01, 0.99);
        policy.decision_bias = (prior / (1.0 - prior)).ln();
        policy.decision_learning_rate = (0.08 * accuracy.max(0.25)).clamp(0.02, 0.08);
        Ok(policy)
    }

    /// Set custom max retries
    pub fn with_max_retries(mut self, max: u32) -> Self {
        self.max_retries = max;
        self
    }

    /// Set custom backoff parameters
    pub fn with_backoff(mut self, base_secs: u64, max_secs: u64) -> Self {
        self.base_backoff_secs = base_secs;
        self.max_backoff_secs = max_secs;
        self
    }

    /// Make a restart decision based on signal and learned patterns
    pub fn decide(&mut self, signal: &RestartSignal) -> RestartDecision {
        // Exit code 0 means clean exit - don't restart
        if signal.exit_code == 0 {
            return RestartDecision::DoNotRestart;
        }

        // Too many recent failures - give up
        if signal.recent_failures >= self.max_retries {
            return RestartDecision::DoNotRestart;
        }

        // Immediate failure pattern detected - don't keep retrying
        if self.detected_pattern == CrashPattern::ImmediateFailure && self.pattern_confidence > 0.7
        {
            return RestartDecision::DoNotRestart;
        }

        // Calculate exponential backoff with learned adjustment
        let backoff = self.calculate_backoff(signal.recent_failures);
        let features = self.build_decision_features(signal);
        let success_probability = self.predict_success_probability(features);
        self.last_decision_features = Some(features);

        // Learned model: if expected restart success is very low, avoid restart loops.
        if signal.recent_failures >= 2 && success_probability < 0.20 {
            return RestartDecision::DoNotRestart;
        }
        // If confidence is weak, back off more aggressively.
        if signal.recent_failures > 0 && success_probability < 0.45 {
            return RestartDecision::RestartAfterDelay {
                delay_secs: (backoff.saturating_mul(2)).min(self.max_backoff_secs),
            };
        }

        // Time-based pattern - proactive restart suggestion (logged but not enforced)
        if let CrashPattern::TimeBased {
            typical_uptime_secs,
        } = self.detected_pattern
        {
            if self.pattern_confidence > 0.5 && signal.uptime_secs > 0 {
                // Container crashed near its typical failure time
                if signal.uptime_secs >= typical_uptime_secs.saturating_sub(600) {
                    // Could suggest proactive restart before crash, but for now just adjust backoff
                    return RestartDecision::RestartAfterDelay {
                        delay_secs: backoff / 2,
                    };
                }
            }
        }

        // First failure - restart immediately
        if signal.recent_failures == 0 {
            return RestartDecision::Restart;
        }

        // Subsequent failures - backoff
        RestartDecision::RestartAfterDelay {
            delay_secs: backoff,
        }
    }

    /// Calculate exponential backoff with learned adjustment
    fn calculate_backoff(&self, failures: u32) -> u64 {
        if failures == 0 {
            return 0;
        }

        // Standard exponential backoff: base * 2^(failures-1)
        let multiplier = 1u64 << (failures - 1).min(10);
        let base_backoff = self.base_backoff_secs.saturating_mul(multiplier);

        // Apply learned adjustment
        let adjusted =
            (base_backoff as f64 * self.backoff_adjustment as f64).min(u64::MAX as f64) as u64;

        // Cap at maximum
        adjusted.min(self.max_backoff_secs)
    }

    /// Record a restart event
    pub fn record_restart(&mut self, exit_code: i32, uptime_before_crash_secs: u64) {
        self.restart_history.push_back(RestartRecord {
            timestamp: Instant::now(),
            exit_code,
            uptime_before_crash_secs,
            outcome: None,
            time_to_outcome_secs: None,
        });

        // Keep history bounded
        if self.restart_history.len() > 50 {
            self.restart_history.pop_front();
        }

        // Update pattern detection
        self.detect_patterns();
    }

    /// Record the outcome of a restart
    pub fn record_outcome(&mut self, outcome: RestartOutcome) {
        if let Some(last) = self.restart_history.back_mut() {
            let elapsed = last.timestamp.elapsed().as_secs();
            last.outcome = Some(outcome);
            last.time_to_outcome_secs = Some(elapsed);

            if let Some(features) = self.last_decision_features.take() {
                self.update_decision_model(features, outcome);
            }

            // Adjust backoff based on outcome
            match outcome {
                RestartOutcome::Success => {
                    // Success - can reduce backoff slightly
                    self.backoff_adjustment = (self.backoff_adjustment * 0.95).max(0.5);
                }
                RestartOutcome::Failure => {
                    // Failure - increase backoff for future attempts
                    self.backoff_adjustment = (self.backoff_adjustment * 1.2).min(3.0);
                }
            }

            // Re-detect patterns with new data
            self.detect_patterns();
        }
    }

    /// Resolve the pending restart observation from the replacement uptime.
    ///
    /// A replacement is not considered successful merely because it spawned:
    /// short-lived crashes must train the policy as failures.  Keeping the
    /// observation-window decision here ensures every lifecycle caller uses
    /// the same bounded criterion.
    pub fn record_observation(&mut self, uptime_secs: u64) {
        let outcome = if uptime_secs >= self.observation_window_secs {
            RestartOutcome::Success
        } else {
            RestartOutcome::Failure
        };
        self.record_outcome(outcome);
    }

    /// Detect crash patterns from history
    fn detect_patterns(&mut self) {
        let records: Vec<_> = self
            .restart_history
            .iter()
            .filter(|r| r.outcome.is_some())
            .collect();

        if records.len() < 3 {
            self.detected_pattern = CrashPattern::Unknown;
            self.pattern_confidence = 0.0;
            return;
        }

        // Calculate uptime statistics first
        let uptimes: Vec<u64> = records.iter().map(|r| r.uptime_before_crash_secs).collect();
        let avg_uptime: f64 = uptimes.iter().sum::<u64>() as f64 / uptimes.len() as f64;
        let variance: f64 = uptimes
            .iter()
            .map(|&u| (u as f64 - avg_uptime).powi(2))
            .sum::<f64>()
            / uptimes.len() as f64;
        let stddev = variance.sqrt();
        let cv = if avg_uptime > 0.0 {
            stddev / avg_uptime
        } else {
            1.0
        };

        // Check for time-based pattern FIRST (higher priority if variance is low)
        // This catches memory leak patterns before checking immediate failures
        if cv < 0.2 && avg_uptime > 60.0 {
            self.detected_pattern = CrashPattern::TimeBased {
                typical_uptime_secs: avg_uptime as u64,
            };
            self.pattern_confidence = 1.0 - cv as f32;
            return;
        }

        // Check for immediate failure pattern
        // Immediate failure = container crashes quickly AND had short uptime before crash
        // This distinguishes from time-based patterns where uptime is long but crash is quick
        let immediate_failures: Vec<_> = records
            .iter()
            .filter(|r| {
                let time = r.time_to_outcome_secs.unwrap_or(u64::MAX);
                let uptime = r.uptime_before_crash_secs;
                // Immediate failure: crashed within 60s of restart AND previous uptime was short
                time < 60 && uptime < 60
            })
            .filter(|r| r.outcome == Some(RestartOutcome::Failure))
            .collect();

        if immediate_failures.len() as f32 / records.len() as f32 > 0.7 {
            self.detected_pattern = CrashPattern::ImmediateFailure;
            self.pattern_confidence = immediate_failures.len() as f32 / records.len() as f32;
            return;
        }

        // Check for recurring OOM-like exits (e.g., SIGKILL=137)
        let memory_pressure = records
            .iter()
            .filter(|r| r.exit_code == 137 || r.exit_code == 9)
            .count();
        if memory_pressure as f32 / records.len() as f32 > 0.6 {
            self.detected_pattern = CrashPattern::MemoryPressure;
            self.pattern_confidence = memory_pressure as f32 / records.len() as f32;
            return;
        }

        // Default to random pattern
        self.detected_pattern = CrashPattern::Random;
        self.pattern_confidence = 0.3;
    }

    fn build_decision_features(&self, signal: &RestartSignal) -> [f32; 5] {
        let failure_norm =
            (signal.recent_failures as f32 / self.max_retries.max(1) as f32).clamp(0.0, 1.0);
        let uptime_norm = (signal.uptime_secs as f32 / self.observation_window_secs.max(1) as f32)
            .clamp(0.0, 1.0);
        let exit_severity = match signal.exit_code {
            137 | 139 => 1.0,
            125..=255 => 0.8,
            1..=124 => 0.6,
            _ => 0.2,
        };
        let success_rate = self.success_rate().clamp(0.0, 1.0);
        let pattern_conf = self.pattern_confidence.clamp(0.0, 1.0);
        [
            1.0 - failure_norm,
            uptime_norm,
            1.0 - exit_severity,
            success_rate,
            pattern_conf,
        ]
    }

    fn predict_success_probability(&self, features: [f32; 5]) -> f32 {
        let mut z = self.decision_bias;
        for (w, x) in self.decision_weights.iter().zip(features.iter()) {
            z += w * x;
        }
        1.0 / (1.0 + (-z).exp())
    }

    /// Estimate the probability that a restart will succeed for a signal.
    /// This is exposed for explainability only; `decide` remains the authority
    /// that applies retry and safety thresholds.
    pub fn estimate_success_probability(&self, signal: &RestartSignal) -> f32 {
        self.predict_success_probability(self.build_decision_features(signal))
    }

    fn update_decision_model(&mut self, features: [f32; 5], outcome: RestartOutcome) {
        let target = match outcome {
            RestartOutcome::Success => 1.0,
            RestartOutcome::Failure => 0.0,
        };
        let pred = self.predict_success_probability(features);
        let error = target - pred;
        for (w, x) in self.decision_weights.iter_mut().zip(features.iter()) {
            *w += self.decision_learning_rate * error * x;
        }
        self.decision_bias += self.decision_learning_rate * error;
    }

    /// Get the detected crash pattern
    pub fn get_pattern(&self) -> CrashPattern {
        self.detected_pattern
    }

    /// Get pattern confidence
    pub fn get_confidence(&self) -> f32 {
        self.pattern_confidence
    }

    /// Get restart history count
    pub fn restart_count(&self) -> usize {
        self.restart_history.len()
    }

    /// Get success rate
    pub fn success_rate(&self) -> f32 {
        let completed: Vec<_> = self
            .restart_history
            .iter()
            .filter(|r| r.outcome.is_some())
            .collect();

        if completed.is_empty() {
            return 0.0;
        }

        let successes = completed
            .iter()
            .filter(|r| r.outcome == Some(RestartOutcome::Success))
            .count();

        successes as f32 / completed.len() as f32
    }

    /// Generate a decision trace for explainability
    pub fn decision_trace(&self, signal: &RestartSignal, decision: &RestartDecision) -> String {
        format!(
            "container={} exit_code={} recent_failures={} pattern={:?} confidence={:.2} success_rate={:.2} backoff_adj={:.2} decision={:?}",
            self.container_id,
            signal.exit_code,
            signal.recent_failures,
            self.detected_pattern,
            self.pattern_confidence,
            self.success_rate(),
            self.backoff_adjustment,
            decision
        )
    }

    /// Persist the bounded learned state used by restart decisions.
    pub fn save_snapshot(&self, path: &std::path::Path) -> Result<(), String> {
        let snapshot = RestartPolicySnapshot::from_policy(self);
        let bytes = serde_json::to_vec(&snapshot).map_err(|error| error.to_string())?;
        if bytes.len() > MAX_SNAPSHOT_BYTES as usize {
            return Err("restart policy snapshot exceeds size limit".to_string());
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let temporary = path.with_extension(format!("tmp-{}-{nonce}", std::process::id()));
        let result = (|| {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)
                .map_err(|error| error.to_string())?;
            file.write_all(&bytes).map_err(|error| error.to_string())?;
            file.sync_all().map_err(|error| error.to_string())?;
            std::fs::rename(&temporary, path).map_err(|error| error.to_string())?;
            if let Some(parent) = path.parent() {
                std::fs::File::open(parent)
                    .and_then(|directory| directory.sync_all())
                    .map_err(|error| error.to_string())?;
            }
            Ok::<(), String>(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }

    /// Load a persisted policy, rejecting malformed, oversized, or mismatched
    /// snapshots before they can influence restart behavior.
    pub fn from_snapshot(path: &std::path::Path, container_id: &str) -> Result<Self, String> {
        let metadata = std::fs::metadata(path).map_err(|error| error.to_string())?;
        if metadata.len() > MAX_SNAPSHOT_BYTES {
            return Err("restart policy snapshot exceeds size limit".to_string());
        }
        let bytes = std::fs::read(path).map_err(|error| error.to_string())?;
        let snapshot: RestartPolicySnapshot = serde_json::from_slice(&bytes)
            .map_err(|error| format!("invalid restart policy snapshot: {error}"))?;
        snapshot.into_policy(container_id)
    }
}

const MAX_SNAPSHOT_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RestartPolicySnapshot {
    schema_version: u8,
    container_id: String,
    max_retries: u32,
    base_backoff_secs: u64,
    max_backoff_secs: u64,
    observation_window_secs: u64,
    detected_pattern: CrashPattern,
    pattern_confidence: f32,
    backoff_adjustment: f32,
    decision_weights: [f32; 5],
    decision_bias: f32,
    decision_learning_rate: f32,
}

impl RestartPolicySnapshot {
    fn from_policy(policy: &AdaptiveRestartPolicy) -> Self {
        Self {
            schema_version: 1,
            container_id: policy.container_id.clone(),
            max_retries: policy.max_retries,
            base_backoff_secs: policy.base_backoff_secs,
            max_backoff_secs: policy.max_backoff_secs,
            observation_window_secs: policy.observation_window_secs,
            detected_pattern: policy.detected_pattern,
            pattern_confidence: policy.pattern_confidence,
            backoff_adjustment: policy.backoff_adjustment,
            decision_weights: policy.decision_weights,
            decision_bias: policy.decision_bias,
            decision_learning_rate: policy.decision_learning_rate,
        }
    }

    fn into_policy(self, expected_container_id: &str) -> Result<AdaptiveRestartPolicy, String> {
        if self.schema_version != 1 {
            return Err("unsupported restart policy snapshot schema".to_string());
        }
        if self.container_id != expected_container_id {
            return Err("restart policy snapshot container identity mismatch".to_string());
        }
        if self.max_retries > 100
            || self.base_backoff_secs > 86_400
            || self.max_backoff_secs > 86_400
            || self.base_backoff_secs > self.max_backoff_secs
            || self.observation_window_secs > 86_400
            || !self.pattern_confidence.is_finite()
            || !(0.0..=1.0).contains(&self.pattern_confidence)
            || !self.backoff_adjustment.is_finite()
            || !(0.1..=10.0).contains(&self.backoff_adjustment)
            || !self.decision_bias.is_finite()
            || self.decision_bias.abs() > 20.0
            || !self.decision_learning_rate.is_finite()
            || !(0.001..=1.0).contains(&self.decision_learning_rate)
            || self
                .decision_weights
                .iter()
                .any(|value| !value.is_finite() || value.abs() > 20.0)
        {
            return Err("restart policy snapshot contains out-of-range values".to_string());
        }
        let mut policy = AdaptiveRestartPolicy::new(expected_container_id);
        policy.max_retries = self.max_retries;
        policy.base_backoff_secs = self.base_backoff_secs;
        policy.max_backoff_secs = self.max_backoff_secs;
        policy.observation_window_secs = self.observation_window_secs;
        policy.detected_pattern = self.detected_pattern;
        policy.pattern_confidence = self.pattern_confidence;
        policy.backoff_adjustment = self.backoff_adjustment;
        policy.decision_weights = self.decision_weights;
        policy.decision_bias = self.decision_bias;
        policy.decision_learning_rate = self.decision_learning_rate;
        Ok(policy)
    }
}

/// Basic restart decision (backward compatible)
pub fn decide_restart(signal: RestartSignal) -> RestartDecision {
    if signal.exit_code == 0 {
        return RestartDecision::DoNotRestart;
    }
    if signal.recent_failures >= 3 {
        return RestartDecision::DoNotRestart;
    }
    RestartDecision::Restart
}

/// Global restart policy registry (for persistence across restarts)
#[derive(Debug, Clone, Default)]
pub struct RestartPolicyRegistry {
    policies: HashMap<String, AdaptiveRestartPolicy>,
}

impl RestartPolicyRegistry {
    pub fn new() -> Self {
        Self {
            policies: HashMap::new(),
        }
    }

    /// Get or create a policy for a container
    pub fn get_or_create(&mut self, container_id: &str) -> &mut AdaptiveRestartPolicy {
        self.policies
            .entry(container_id.to_string())
            .or_insert_with(|| AdaptiveRestartPolicy::new(container_id))
    }

    /// Record a restart event
    pub fn record_restart(&mut self, container_id: &str, exit_code: i32, uptime_secs: u64) {
        let policy = self.get_or_create(container_id);
        policy.record_restart(exit_code, uptime_secs);
    }

    /// Record a restart outcome
    pub fn record_outcome(&mut self, container_id: &str, outcome: RestartOutcome) {
        if let Some(policy) = self.policies.get_mut(container_id) {
            policy.record_outcome(outcome);
        }
    }

    /// Make a restart decision
    pub fn decide(&mut self, container_id: &str, signal: &RestartSignal) -> RestartDecision {
        if let Some(policy) = self.policies.get_mut(container_id) {
            policy.decide(signal)
        } else {
            decide_restart(*signal)
        }
    }

    /// Get policy statistics
    pub fn stats(&self) -> (usize, usize) {
        let total_policies = self.policies.len();
        let total_restarts: usize = self.policies.values().map(|p| p.restart_count()).sum();
        (total_policies, total_restarts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_decision_no_restart_on_success() {
        let signal = RestartSignal {
            exit_code: 0,
            recent_failures: 0,
            uptime_secs: 100,
        };
        assert_eq!(decide_restart(signal), RestartDecision::DoNotRestart);
    }

    #[test]
    fn basic_decision_restart_on_failure() {
        let signal = RestartSignal {
            exit_code: 1,
            recent_failures: 0,
            uptime_secs: 100,
        };
        assert_eq!(decide_restart(signal), RestartDecision::Restart);
    }

    #[test]
    fn basic_decision_stop_after_three_failures() {
        let signal = RestartSignal {
            exit_code: 1,
            recent_failures: 3,
            uptime_secs: 100,
        };
        assert_eq!(decide_restart(signal), RestartDecision::DoNotRestart);
    }

    // Task 5.3 Tests

    #[test]
    fn adaptive_policy_starts_with_unknown_pattern() {
        let policy = AdaptiveRestartPolicy::new("test-container");
        assert_eq!(policy.get_pattern(), CrashPattern::Unknown);
        assert_eq!(policy.get_confidence(), 0.0);
    }

    #[test]
    fn loads_trained_restart_artifact_and_preserves_safety_limits() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("model.json");
        std::fs::write(
            &path,
            serde_json::json!({
                "model_type": "restart-policy",
                "artifact": {
                    "success_rate": 0.1,
                    "baseline_accuracy": 0.9,
                    "avg_uptime_success": 120.0,
                    "avg_uptime_failure": 5.0
                }
            })
            .to_string(),
        )
        .expect("artifact");

        let mut policy = AdaptiveRestartPolicy::from_model_artifact(&path, "test-container")
            .expect("load model");
        assert!(
            policy.estimate_success_probability(&RestartSignal {
                exit_code: 1,
                recent_failures: 2,
                uptime_secs: 5,
            }) < 0.20
        );
        assert_eq!(
            policy.decide(&RestartSignal {
                exit_code: 1,
                recent_failures: 5,
                uptime_secs: 5,
            }),
            RestartDecision::DoNotRestart
        );
    }

    #[test]
    fn restart_policy_snapshot_round_trips_learned_state_and_rejects_identity_forks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("restart-policy.json");
        let mut policy = AdaptiveRestartPolicy::new("container-a");
        policy.backoff_adjustment = 2.25;
        policy.pattern_confidence = 0.8;
        policy.record_restart(1, 3);
        policy.record_outcome(RestartOutcome::Failure);
        let before = policy.estimate_success_probability(&RestartSignal {
            exit_code: 1,
            recent_failures: 1,
            uptime_secs: 3,
        });

        policy.save_snapshot(&path).expect("save snapshot");
        let restored =
            AdaptiveRestartPolicy::from_snapshot(&path, "container-a").expect("restore snapshot");
        let after = restored.estimate_success_probability(&RestartSignal {
            exit_code: 1,
            recent_failures: 1,
            uptime_secs: 3,
        });
        assert!((before - after).abs() < f32::EPSILON);
        assert_eq!(restored.restart_count(), 0);
        assert!(AdaptiveRestartPolicy::from_snapshot(&path, "container-b").is_err());
    }

    #[test]
    fn snapshot_load_fails_closed_on_corrupt_or_out_of_range_state() {
        let dir = tempfile::tempdir().expect("tempdir");

        let corrupt = dir.path().join("corrupt.json");
        std::fs::write(&corrupt, b"{ not json").expect("write corrupt snapshot");
        let error = AdaptiveRestartPolicy::from_snapshot(&corrupt, "container-a")
            .expect_err("corrupt snapshot must fail");
        assert!(
            error.contains("invalid restart policy snapshot"),
            "got: {error}"
        );

        // Valid JSON with an unsupported schema must be rejected.
        let wrong_schema = dir.path().join("wrong-schema.json");
        let policy = AdaptiveRestartPolicy::new("container-a");
        policy.save_snapshot(&wrong_schema).expect("save");
        let mut value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&wrong_schema).expect("read"))
                .expect("snapshot json");
        value["schema_version"] = serde_json::json!(2);
        std::fs::write(&wrong_schema, value.to_string()).expect("write patched snapshot");
        let error = AdaptiveRestartPolicy::from_snapshot(&wrong_schema, "container-a")
            .expect_err("unsupported schema must fail");
        assert!(error.contains("schema"), "got: {error}");

        // Out-of-range learned weights must be rejected before they can
        // influence a restart decision.
        let out_of_range = dir.path().join("out-of-range.json");
        let mut value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&wrong_schema).expect("read"))
                .expect("snapshot json");
        value["schema_version"] = serde_json::json!(1);
        value["decision_weights"] = serde_json::json!([999.0, -0.5, -0.2, 0.4, 0.25]);
        std::fs::write(&out_of_range, value.to_string()).expect("write out-of-range snapshot");
        let error = AdaptiveRestartPolicy::from_snapshot(&out_of_range, "container-a")
            .expect_err("out-of-range weights must fail");
        assert!(error.contains("out-of-range"), "got: {error}");
    }

    #[test]
    fn model_artifact_load_fails_closed_on_corrupt_state() {
        let dir = tempfile::tempdir().expect("tempdir");
        let corrupt = dir.path().join("bad-model.json");
        std::fs::write(&corrupt, b"definitely not json").expect("write corrupt artifact");
        let error = AdaptiveRestartPolicy::from_model_artifact(&corrupt, "container-a")
            .expect_err("corrupt artifact must fail");
        assert!(
            error.contains("invalid restart model artifact"),
            "got: {error}"
        );

        let out_of_bounds = dir.path().join("out-of-bounds.json");
        std::fs::write(
            &out_of_bounds,
            serde_json::json!({
                "model_type": "restart-policy",
                "artifact": {
                    "success_rate": 1.5,
                    "baseline_accuracy": 0.9,
                    "avg_uptime_success": 120.0,
                    "avg_uptime_failure": 5.0
                }
            })
            .to_string(),
        )
        .expect("write out-of-bounds artifact");
        let error = AdaptiveRestartPolicy::from_model_artifact(&out_of_bounds, "container-a")
            .expect_err("out-of-bounds statistics must fail");
        assert!(error.contains("0..=1"), "got: {error}");
    }

    #[test]
    fn adaptive_policy_first_failure_restarts_immediately() {
        let mut policy = AdaptiveRestartPolicy::new("test");
        let signal = RestartSignal {
            exit_code: 1,
            recent_failures: 0,
            uptime_secs: 100,
        };
        assert_eq!(policy.decide(&signal), RestartDecision::Restart);
    }

    #[test]
    fn adaptive_policy_exposes_bounded_success_confidence_for_explainability() {
        let policy = AdaptiveRestartPolicy::new("test");
        let confidence = policy.estimate_success_probability(&RestartSignal {
            exit_code: 1,
            recent_failures: 1,
            uptime_secs: 100,
        });
        assert!((0.0..=1.0).contains(&confidence));
    }

    #[test]
    fn adaptive_policy_backoff_increases() {
        let mut policy = AdaptiveRestartPolicy::new("test");

        let signal1 = RestartSignal {
            exit_code: 1,
            recent_failures: 1,
            uptime_secs: 100,
        };
        let signal2 = RestartSignal {
            exit_code: 1,
            recent_failures: 2,
            uptime_secs: 100,
        };
        let signal3 = RestartSignal {
            exit_code: 1,
            recent_failures: 3,
            uptime_secs: 100,
        };

        let backoff1 = match policy.decide(&signal1) {
            RestartDecision::RestartAfterDelay { delay_secs } => delay_secs,
            _ => 0,
        };
        let backoff2 = match policy.decide(&signal2) {
            RestartDecision::RestartAfterDelay { delay_secs } => delay_secs,
            _ => 0,
        };
        let backoff3 = match policy.decide(&signal3) {
            RestartDecision::RestartAfterDelay { delay_secs } => delay_secs,
            _ => 0,
        };

        assert!(backoff2 > backoff1);
        assert!(backoff3 > backoff2);
    }

    #[test]
    fn adaptive_policy_backoff_saturates_before_applying_cap() {
        let policy = AdaptiveRestartPolicy::new("test").with_backoff(u64::MAX, u64::MAX);
        assert_eq!(policy.calculate_backoff(1), u64::MAX);
        assert_eq!(policy.calculate_backoff(10), u64::MAX);
    }

    #[test]
    fn adaptive_policy_detects_immediate_failure_pattern() {
        let mut policy = AdaptiveRestartPolicy::new("test");

        // Simulate 4 immediate failures
        for _ in 0..4 {
            policy.record_restart(1, 10);
            policy.record_outcome(RestartOutcome::Failure);
        }

        assert_eq!(policy.get_pattern(), CrashPattern::ImmediateFailure);
        assert!(policy.get_confidence() > 0.7);
    }

    #[test]
    fn adaptive_policy_success_reduces_backoff() {
        let mut policy = AdaptiveRestartPolicy::new("test");
        policy.backoff_adjustment = 2.0;

        policy.record_restart(1, 100);
        policy.record_outcome(RestartOutcome::Success);

        assert!(policy.backoff_adjustment < 2.0);
    }

    #[test]
    fn observation_requires_the_configured_window() {
        let mut policy = AdaptiveRestartPolicy::new("test");
        policy.record_restart(1, 2);
        policy.record_observation(299);
        assert_eq!(policy.success_rate(), 0.0);

        policy.record_restart(1, 2);
        policy.record_observation(300);
        assert!(policy.success_rate() > 0.0);
    }

    #[test]
    fn adaptive_policy_failure_increases_backoff() {
        let mut policy = AdaptiveRestartPolicy::new("test");
        policy.backoff_adjustment = 1.0;

        policy.record_restart(1, 100);
        policy.record_outcome(RestartOutcome::Failure);

        assert!(policy.backoff_adjustment > 1.0);
    }

    #[test]
    fn decision_trace_includes_context() {
        let mut policy = AdaptiveRestartPolicy::new("container-123");
        let signal = RestartSignal {
            exit_code: 137,
            recent_failures: 2,
            uptime_secs: 3600,
        };
        let decision = policy.decide(&signal);
        let trace = policy.decision_trace(&signal, &decision);

        assert!(trace.contains("container-123"));
        assert!(trace.contains("exit_code=137"));
        assert!(trace.contains("recent_failures=2"));
    }

    #[test]
    fn registry_manages_multiple_containers() {
        let mut registry = RestartPolicyRegistry::new();

        registry.record_restart("container-a", 1, 100);
        registry.record_restart("container-b", 137, 500);

        let (policies, restarts) = registry.stats();
        assert_eq!(policies, 2);
        assert_eq!(restarts, 2);
    }

    #[test]
    fn learned_model_discourages_restarts_after_repeated_failures() {
        let mut policy = AdaptiveRestartPolicy::new("learned");
        let signal = RestartSignal {
            exit_code: 137,
            recent_failures: 3,
            uptime_secs: 10,
        };

        for _ in 0..12 {
            let _ = policy.decide(&signal);
            policy.record_restart(signal.exit_code, signal.uptime_secs);
            policy.record_outcome(RestartOutcome::Failure);
        }

        let final_decision = policy.decide(&signal);
        assert!(matches!(
            final_decision,
            RestartDecision::DoNotRestart | RestartDecision::RestartAfterDelay { .. }
        ));
    }

    #[test]
    fn time_based_pattern_detection() {
        let mut policy = AdaptiveRestartPolicy::new("test");

        // Simulate crashes at consistent uptimes (~1 hour each)
        for _ in 0..5 {
            policy.record_restart(1, 3600); // 1 hour uptime
            policy.record_outcome(RestartOutcome::Failure);
            policy.record_restart(1, 3660); // 1 hour + 1 min
            policy.record_outcome(RestartOutcome::Failure);
        }

        // Should detect time-based pattern
        if let CrashPattern::TimeBased {
            typical_uptime_secs,
        } = policy.get_pattern()
        {
            assert!(typical_uptime_secs > 3000 && typical_uptime_secs < 4000);
        } else {
            // Might be random if variance is too high
            assert!(matches!(
                policy.get_pattern(),
                CrashPattern::TimeBased { .. } | CrashPattern::Random
            ));
        }
    }
}
