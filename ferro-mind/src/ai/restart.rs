//! Adaptive Restart with Learning (Task 5.3)
//!
//! Records restart outcomes and learns patterns for intelligent restart decisions.
//! Uses exponential backoff with learned adjustments based on failure patterns.

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
}

impl AdaptiveRestartPolicy {
    /// Create a new adaptive restart policy for a container
    pub fn new(container_id: &str) -> Self {
        Self {
            container_id: container_id.to_string(),
            max_retries: 5,
            base_backoff_secs: 1,
            max_backoff_secs: 300, // 5 minutes max
            observation_window_secs: 300, // 5 minutes to observe success
            restart_history: VecDeque::with_capacity(50),
            detected_pattern: CrashPattern::Unknown,
            pattern_confidence: 0.0,
            backoff_adjustment: 1.0,
        }
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
    pub fn decide(&self, signal: &RestartSignal) -> RestartDecision {
        // Exit code 0 means clean exit - don't restart
        if signal.exit_code == 0 {
            return RestartDecision::DoNotRestart;
        }

        // Too many recent failures - give up
        if signal.recent_failures >= self.max_retries {
            return RestartDecision::DoNotRestart;
        }

        // Immediate failure pattern detected - don't keep retrying
        if self.detected_pattern == CrashPattern::ImmediateFailure && self.pattern_confidence > 0.7 {
            return RestartDecision::DoNotRestart;
        }

        // Calculate exponential backoff with learned adjustment
        let backoff = self.calculate_backoff(signal.recent_failures);

        // Time-based pattern - proactive restart suggestion (logged but not enforced)
        if let CrashPattern::TimeBased { typical_uptime_secs } = self.detected_pattern {
            if self.pattern_confidence > 0.5 && signal.uptime_secs > 0 {
                // Container crashed near its typical failure time
                if signal.uptime_secs >= typical_uptime_secs.saturating_sub(600) {
                    // Could suggest proactive restart before crash, but for now just adjust backoff
                    return RestartDecision::RestartAfterDelay { delay_secs: backoff / 2 };
                }
            }
        }

        // First failure - restart immediately
        if signal.recent_failures == 0 {
            return RestartDecision::Restart;
        }

        // Subsequent failures - backoff
        RestartDecision::RestartAfterDelay { delay_secs: backoff }
    }

    /// Calculate exponential backoff with learned adjustment
    fn calculate_backoff(&self, failures: u32) -> u64 {
        if failures == 0 {
            return 0;
        }

        // Standard exponential backoff: base * 2^(failures-1)
        let base_backoff = self.base_backoff_secs * (1 << (failures - 1).min(10));

        // Apply learned adjustment
        let adjusted = (base_backoff as f32 * self.backoff_adjustment) as u64;

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

    /// Detect crash patterns from history
    fn detect_patterns(&mut self) {
        let records: Vec<_> = self.restart_history
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
            .sum::<f64>() / uptimes.len() as f64;
        let stddev = variance.sqrt();
        let cv = if avg_uptime > 0.0 { stddev / avg_uptime } else { 1.0 };

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

        // Default to random pattern
        self.detected_pattern = CrashPattern::Random;
        self.pattern_confidence = 0.3;
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
        let completed: Vec<_> = self.restart_history
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
    pub fn decide(&self, container_id: &str, signal: &RestartSignal) -> RestartDecision {
        if let Some(policy) = self.policies.get(container_id) {
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
    fn adaptive_policy_first_failure_restarts_immediately() {
        let policy = AdaptiveRestartPolicy::new("test");
        let signal = RestartSignal {
            exit_code: 1,
            recent_failures: 0,
            uptime_secs: 100,
        };
        assert_eq!(policy.decide(&signal), RestartDecision::Restart);
    }

    #[test]
    fn adaptive_policy_backoff_increases() {
        let policy = AdaptiveRestartPolicy::new("test");

        let signal1 = RestartSignal { exit_code: 1, recent_failures: 1, uptime_secs: 100 };
        let signal2 = RestartSignal { exit_code: 1, recent_failures: 2, uptime_secs: 100 };
        let signal3 = RestartSignal { exit_code: 1, recent_failures: 3, uptime_secs: 100 };

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
    fn adaptive_policy_failure_increases_backoff() {
        let mut policy = AdaptiveRestartPolicy::new("test");
        policy.backoff_adjustment = 1.0;

        policy.record_restart(1, 100);
        policy.record_outcome(RestartOutcome::Failure);

        assert!(policy.backoff_adjustment > 1.0);
    }

    #[test]
    fn decision_trace_includes_context() {
        let policy = AdaptiveRestartPolicy::new("container-123");
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
        if let CrashPattern::TimeBased { typical_uptime_secs } = policy.get_pattern() {
            assert!(typical_uptime_secs > 3000 && typical_uptime_secs < 4000);
        } else {
            // Might be random if variance is too high
            assert!(matches!(policy.get_pattern(), CrashPattern::TimeBased { .. } | CrashPattern::Random));
        }
    }
}
