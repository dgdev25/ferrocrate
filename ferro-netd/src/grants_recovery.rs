use crate::grants::{GrantError, GrantLedger, GrantPhase, GrantResult, GrantVerifier};

pub(crate) fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) enum RecoveryObservation {
    Consistent(bool),
    Conflict,
}

impl GrantLedger {
    pub(crate) fn quarantine_unknown_after_restart(&mut self) -> Result<(), GrantError> {
        let unknown = self
            .state
            .consumed
            .iter()
            .filter(|(_, operation)| {
                matches!(operation.phase, GrantPhase::OutcomeUnknown)
                    && operation.effect_identity.is_none()
            })
            .map(|(nonce, operation)| (nonce.clone(), operation.claims.clone()))
            .collect::<Vec<_>>();
        for (nonce, claims) in unknown {
            self.state
                .results
                .entry(claims.request_id.clone())
                .or_insert(GrantResult {
                    request_id: claims.request_id,
                    nonce: claims.nonce,
                    result_identity: format!(
                        "quarantine:{}:{:?}",
                        claims.resource.resource_uuid, claims.action
                    ),
                    outcome: "quarantined_after_unknown_effect".into(),
                });
            if let Some(operation) = self.state.consumed.get_mut(&nonce) {
                operation.phase = GrantPhase::Failed;
            }
        }
        self.persist()
    }
    pub(crate) fn reconcile_unknown<F>(&mut self, mut observe: F) -> Result<(), GrantError>
    where
        F: FnMut(&crate::effect_receipt::EffectReceipt) -> RecoveryObservation,
    {
        let unknown = self
            .state
            .consumed
            .iter()
            .filter(|(_, operation)| matches!(operation.phase, GrantPhase::OutcomeUnknown))
            .map(|(nonce, operation)| {
                (
                    nonce.clone(),
                    operation.claims.clone(),
                    operation.expected_receipt.clone(),
                )
            })
            .collect::<Vec<_>>();
        for (nonce, claims, receipt) in unknown {
            let Some(receipt) = receipt else { continue };
            let identity = receipt.identity();
            let expected_exists = receipt.expected_exists();
            let (phase, outcome) = match observe(&receipt) {
                RecoveryObservation::Consistent(exists) if exists == expected_exists => {
                    (GrantPhase::Succeeded, "recovered_after_unknown_effect")
                }
                RecoveryObservation::Consistent(_) => {
                    (GrantPhase::Failed, "failed_after_unknown_effect")
                }
                RecoveryObservation::Conflict => {
                    (GrantPhase::Failed, "quarantined_after_unknown_effect")
                }
            };
            self.state
                .results
                .entry(claims.request_id.clone())
                .or_insert(GrantResult {
                    request_id: claims.request_id,
                    nonce: claims.nonce,
                    result_identity: identity,
                    outcome: outcome.into(),
                });
            if let Some(operation) = self.state.consumed.get_mut(&nonce) {
                operation.phase = phase;
            }
        }
        self.persist()
    }
}

impl GrantVerifier {
    pub(crate) fn reconcile_unknown<F>(&mut self, observe: F) -> Result<(), GrantError>
    where
        F: FnMut(&crate::effect_receipt::EffectReceipt) -> RecoveryObservation,
    {
        self.ledger.reconcile_unknown(observe)
    }
}
