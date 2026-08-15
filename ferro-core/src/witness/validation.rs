use super::{
    ParsedRecord, ReasonCode, WitnessAction, WitnessError, WitnessOutcome, WitnessRecord,
    WitnessStage,
};

pub(super) trait SemanticFields {
    fn stage(&self) -> WitnessStage;
    fn outcome(&self) -> WitnessOutcome;
    fn has_decision_id(&self) -> bool;
    fn has_rule(&self) -> bool;
    fn decision(&self) -> Option<bool>;
    fn reason(&self) -> Option<ReasonCode>;
    fn has_result_digest(&self) -> bool;
    fn has_recovery_link(&self) -> bool;
    fn action(&self) -> WitnessAction;
}

macro_rules! semantic_fields {
    ($type:ty) => {
        impl SemanticFields for $type {
            fn stage(&self) -> WitnessStage {
                self.stage
            }
            fn outcome(&self) -> WitnessOutcome {
                self.outcome
            }
            fn has_decision_id(&self) -> bool {
                self.decision_id.is_some()
            }
            fn has_rule(&self) -> bool {
                self.rule.is_some()
            }
            fn decision(&self) -> Option<bool> {
                self.decision
            }
            fn reason(&self) -> Option<ReasonCode> {
                self.reason
            }
            fn has_result_digest(&self) -> bool {
                self.result_digest.is_some()
            }
            fn has_recovery_link(&self) -> bool {
                self.recovery_link.is_some()
            }
            fn action(&self) -> WitnessAction {
                self.action
            }
        }
    };
}

semantic_fields!(WitnessRecord);
semantic_fields!(ParsedRecord);

/// The single semantic schema used before persistence and after decoding.
pub(super) fn validate_record(record: &impl SemanticFields) -> Result<(), WitnessError> {
    let common_absent = !record.has_decision_id()
        && !record.has_rule()
        && record.decision().is_none()
        && record.reason().is_none()
        && !record.has_result_digest()
        && !record.has_recovery_link();
    let valid = match record.stage() {
        WitnessStage::RequestReceived => common_absent && record.outcome() == WitnessOutcome::None,
        WitnessStage::Decision => {
            record.has_decision_id()
                && record.has_rule()
                && !record.has_result_digest()
                && !record.has_recovery_link()
                && record.outcome() == WitnessOutcome::None
                && match record.decision() {
                    Some(true) => record.reason().is_none()
                        || record.reason() == Some(ReasonCode::EmergencyOverride),
                    Some(false) => record.reason() == Some(ReasonCode::PolicyDenied),
                    None => false,
                }
        }
        WitnessStage::Denied => {
            record.has_decision_id()
                && !record.has_rule()
                && record.decision().is_none()
                && record.reason() == Some(ReasonCode::PolicyDenied)
                && !record.has_result_digest()
                && !record.has_recovery_link()
                && record.outcome() == WitnessOutcome::Denied
        }
        WitnessStage::Outcome => {
            record.has_decision_id()
                && !record.has_rule()
                && record.decision().is_none()
                && record.has_result_digest()
                && !record.has_recovery_link()
                && match record.outcome() {
                    WitnessOutcome::Succeeded => record.reason().is_none(),
                    WitnessOutcome::Failed | WitnessOutcome::OutcomeUnknown => {
                        record.reason() == Some(ReasonCode::ExecutionFailed)
                    }
                    _ => false,
                }
        }
        WitnessStage::Recovery => {
            record.has_decision_id()
                && !record.has_rule()
                && record.decision().is_none()
                && record.has_result_digest()
                && record.has_recovery_link()
                && match record.outcome() {
                    WitnessOutcome::Recovered => {
                        record.reason() == Some(ReasonCode::RecoveryCompleted)
                    }
                    WitnessOutcome::Quarantined => record.reason() == Some(ReasonCode::Quarantined),
                    _ => false,
                }
        }
        WitnessStage::CheckpointPublished => {
            record.action() == WitnessAction::CheckpointPublish
                && record.outcome() == WitnessOutcome::Succeeded
                && record.has_result_digest()
                && !record.has_decision_id()
                && !record.has_rule()
                && record.decision().is_none()
                && record.reason().is_none()
                && !record.has_recovery_link()
        }
    };
    if valid {
        Ok(())
    } else {
        Err(WitnessError::InvalidLifecycle)
    }
}
