use serde::Serialize;
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Clone, Serialize)]
pub struct DecisionTrace {
    pub id: String,
    pub summary: String,
    pub model: Option<String>,
    pub model_version: Option<String>,
    pub decision: Option<String>,
    pub evidence: BTreeMap<String, String>,
}

impl DecisionTrace {
    pub fn new(id: impl Into<String>, summary: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            summary: summary.into(),
            model: None,
            model_version: None,
            decision: None,
            evidence: BTreeMap::new(),
        }
    }

    pub fn with_model(mut self, model: impl Into<String>, version: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self.model_version = Some(version.into());
        self
    }

    pub fn with_decision(mut self, decision: impl Into<String>) -> Self {
        self.decision = Some(decision.into());
        self
    }

    pub fn with_evidence(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.evidence.insert(key.into(), value.into());
        self
    }
}

/// Policy threshold for the coherence gate over recorded decision traces.
#[derive(Debug, Clone, PartialEq)]
pub struct CoherencePolicy {
    /// Minimum recorded confidence for an action to be permitted. The
    /// recorded confidence must be a number in `[0, 1]` and satisfy
    /// `confidence >= min_confidence`.
    pub min_confidence: f64,
    /// Evidence keys that must be present and non-empty in the trace, so an
    /// action is never permitted without its recorded inputs.
    pub required_inputs: Vec<String>,
}

impl CoherencePolicy {
    pub fn new(min_confidence: f64) -> Self {
        Self {
            min_confidence,
            required_inputs: Vec::new(),
        }
    }

    pub fn with_required_inputs(
        mut self,
        inputs: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.required_inputs = inputs.into_iter().map(Into::into).collect();
        self
    }
}

#[derive(Debug, Clone, PartialEq, Error)]
pub enum CoherenceGateError {
    #[error("coherence gate failed: recorded confidence {confidence} is below the policy threshold {threshold}")]
    BelowThreshold { confidence: f64, threshold: f64 },
    #[error("coherence gate failed: decision trace records no confidence")]
    MissingConfidence,
    #[error("coherence gate failed: recorded confidence {value:?} is not a number in [0, 1]")]
    InvalidConfidence { value: String },
    #[error("coherence gate failed: recorded input {0:?} is missing or empty")]
    MissingInput(String),
}

/// Refuses an action whose recorded decision trace fails the coherence
/// policy: the recorded confidence must be present, a number in `[0, 1]`, and
/// at least `policy.min_confidence`, and every required input must be
/// recorded as non-empty evidence. Builds on the explainability records, so
/// refusal always names what the trace failed to show.
pub fn check_action_coherence(
    trace: &DecisionTrace,
    policy: &CoherencePolicy,
) -> Result<(), CoherenceGateError> {
    let raw = trace
        .evidence
        .get("confidence")
        .ok_or(CoherenceGateError::MissingConfidence)?;
    let confidence: f64 = raw
        .trim()
        .parse()
        .map_err(|_| CoherenceGateError::InvalidConfidence {
            value: raw.clone(),
        })?;
    if !confidence.is_finite() || !(0.0..=1.0).contains(&confidence) {
        return Err(CoherenceGateError::InvalidConfidence {
            value: raw.clone(),
        });
    }
    if confidence < policy.min_confidence {
        return Err(CoherenceGateError::BelowThreshold {
            confidence,
            threshold: policy.min_confidence,
        });
    }
    for input in &policy.required_inputs {
        if trace
            .evidence
            .get(input)
            .is_none_or(|value| value.trim().is_empty())
        {
            return Err(CoherenceGateError::MissingInput(input.clone()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{check_action_coherence, CoherenceGateError, CoherencePolicy, DecisionTrace};

    fn trace_with(confidence: &str) -> DecisionTrace {
        DecisionTrace::new("trace-1", "summary").with_evidence("confidence", confidence)
    }

    #[test]
    fn permits_action_at_or_above_the_confidence_threshold() {
        let policy = CoherencePolicy::new(0.8);
        assert!(check_action_coherence(&trace_with("0.8"), &policy).is_ok());
        assert!(check_action_coherence(&trace_with("0.95"), &policy).is_ok());
    }

    #[test]
    fn refuses_action_below_the_confidence_threshold() {
        let policy = CoherencePolicy::new(0.8);
        let error =
            check_action_coherence(&trace_with("0.79"), &policy).expect_err("must refuse");
        assert_eq!(
            error,
            CoherenceGateError::BelowThreshold {
                confidence: 0.79,
                threshold: 0.8
            }
        );
    }

    #[test]
    fn refuses_action_without_recorded_confidence() {
        let trace = DecisionTrace::new("trace-1", "summary");
        let error = check_action_coherence(&trace, &CoherencePolicy::new(0.5)).unwrap_err();
        assert_eq!(error, CoherenceGateError::MissingConfidence);
    }

    #[test]
    fn refuses_action_with_non_numeric_or_out_of_range_confidence() {
        let policy = CoherencePolicy::new(0.5);
        for value in ["high", "NaN", "1.5", "-0.1", "inf"] {
            let error = check_action_coherence(&trace_with(value), &policy).unwrap_err();
            assert_eq!(
                error,
                CoherenceGateError::InvalidConfidence {
                    value: value.to_string()
                },
                "confidence {value:?} must be refused"
            );
        }
    }

    #[test]
    fn refuses_action_when_a_required_input_is_missing_or_empty() {
        let policy = CoherencePolicy::new(0.5).with_required_inputs(["container_id", "model"]);
        let complete = trace_with("0.9")
            .with_evidence("container_id", "container-42")
            .with_evidence("model", "restart-policy");
        assert!(check_action_coherence(&complete, &policy).is_ok());

        let missing = trace_with("0.9").with_evidence("container_id", "container-42");
        assert_eq!(
            check_action_coherence(&missing, &policy).unwrap_err(),
            CoherenceGateError::MissingInput("model".to_string())
        );

        let empty = trace_with("0.9")
            .with_evidence("container_id", "container-42")
            .with_evidence("model", "  ");
        assert_eq!(
            check_action_coherence(&empty, &policy).unwrap_err(),
            CoherenceGateError::MissingInput("model".to_string())
        );
    }
}
