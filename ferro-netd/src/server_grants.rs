use crate::{
    grants::{ConsumedGrant, GrantError},
    protocol::RejectionCode,
    server::NetdServer,
};
use ferro_core::authorization::helper_grant::{GrantAction, GrantParameters, HelperGrant};

pub(crate) fn reject(code: RejectionCode, reason: &str) -> crate::protocol::NetdResponse {
    crate::protocol::NetdResponse::Rejected {
        code,
        reason: reason.to_string(),
    }
}

impl NetdServer {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn consume_grant(
        &mut self,
        grant: &HelperGrant,
        action: GrantAction,
        uuid: &str,
        generation: u64,
        params: &GrantParameters,
        effect_receipt: crate::effect_receipt::EffectReceipt,
        now: u64,
    ) -> Result<(), RejectionCode> {
        let verifier = self.grants.as_mut().ok_or(RejectionCode::MissingGrant)?;
        let consumed = verifier
            .verify_and_consume(
                grant,
                action,
                uuid,
                generation,
                params,
                now,
                monotonic_millis(),
            )
            .map_err(map_grant_error)?;
        verifier
            .arm_effect_target(&consumed, effect_receipt)
            .map_err(map_grant_error)
    }

    pub(crate) fn record_grant_result(
        &mut self,
        request_id: &str,
        nonce: [u8; 16],
        identity: String,
        outcome: &str,
    ) -> Result<(), GrantError> {
        if let Some(verifier) = self.grants.as_mut() {
            verifier.record_result(
                &ConsumedGrant::restored(request_id, nonce),
                identity,
                outcome,
            )?;
        }
        Ok(())
    }

    pub(crate) fn record_grant_failure(
        &mut self,
        request_id: &str,
        nonce: [u8; 16],
        identity: String,
        outcome: &str,
    ) -> Result<(), GrantError> {
        self.grants
            .as_mut()
            .ok_or(GrantError::NotConsumed)?
            .record_failure(
                &ConsumedGrant::restored(request_id, nonce),
                identity,
                outcome,
            )
    }
}

fn monotonic_millis() -> u64 {
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|value| value.split('.').next()?.parse::<u64>().ok())
        .unwrap_or(u64::MAX)
        .saturating_mul(1000)
}

fn map_grant_error(error: GrantError) -> RejectionCode {
    match error {
        GrantError::Replay => RejectionCode::GrantReplay,
        GrantError::InvalidSignature => RejectionCode::InvalidSignature,
        _ => RejectionCode::InvalidGrant,
    }
}
