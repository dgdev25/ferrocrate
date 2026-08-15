use crate::grants::{GrantError, GrantLedger, GrantPhase, GrantResult, GrantVerifier};
use ferro_core::authorization::helper_grant::GrantAction;

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
        F: FnMut(&str) -> RecoveryObservation,
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
                    operation.effect_identity.clone(),
                )
            })
            .collect::<Vec<_>>();
        for (nonce, claims, identity) in unknown {
            let Some(identity) = identity else { continue };
            let expected_exists = matches!(
                claims.action,
                GrantAction::NetworkCreate | GrantAction::NetworkAttach
            );
            let (phase, outcome) = match observe(&identity) {
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
        F: FnMut(&str) -> RecoveryObservation,
    {
        self.ledger.reconcile_unknown(observe)
    }
}
