use super::{ReasonCode, WitnessError, WitnessOutcome, WitnessRecord, WitnessStage};

/// The single semantic schema used before persistence and after decoding.
pub(super) fn validate_record(record: &WitnessRecord) -> Result<(), WitnessError> {
    let common_absent = record.decision_id.is_none()
        && record.rule.is_none()
        && record.decision.is_none()
        && record.reason.is_none()
        && record.result_digest.is_none()
        && record.recovery_link.is_none();
    let valid = match record.stage {
        WitnessStage::RequestReceived => common_absent && record.outcome == WitnessOutcome::None,
        WitnessStage::Decision => {
            record.decision_id.is_some()
                && record.rule.is_some()
                && record.result_digest.is_none()
                && record.recovery_link.is_none()
                && record.outcome == WitnessOutcome::None
                && match record.decision {
                    Some(true) => record.reason.is_none(),
                    Some(false) => record.reason == Some(ReasonCode::PolicyDenied),
                    None => false,
                }
        }
        WitnessStage::Denied => {
            record.decision_id.is_some()
                && record.rule.is_none()
                && record.decision.is_none()
                && record.reason == Some(ReasonCode::PolicyDenied)
                && record.result_digest.is_none()
                && record.recovery_link.is_none()
                && record.outcome == WitnessOutcome::Denied
        }
        WitnessStage::Outcome => {
            record.decision_id.is_some()
                && record.rule.is_none()
                && record.decision.is_none()
                && record.result_digest.is_some()
                && record.recovery_link.is_none()
                && match record.outcome {
                    WitnessOutcome::Succeeded => record.reason.is_none(),
                    WitnessOutcome::Failed | WitnessOutcome::OutcomeUnknown => {
                        record.reason == Some(ReasonCode::ExecutionFailed)
                    }
                    _ => false,
                }
        }
        WitnessStage::Recovery => {
            record.decision_id.is_some()
                && record.rule.is_none()
                && record.decision.is_none()
                && record.result_digest.is_some()
                && record.recovery_link.is_some()
                && match record.outcome {
                    WitnessOutcome::Recovered => {
                        record.reason == Some(ReasonCode::RecoveryCompleted)
                    }
                    WitnessOutcome::Quarantined => record.reason == Some(ReasonCode::Quarantined),
                    _ => false,
                }
        }
    };
    if valid {
        Ok(())
    } else {
        Err(WitnessError::InvalidLifecycle)
    }
}
