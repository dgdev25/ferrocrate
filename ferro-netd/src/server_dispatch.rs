use crate::{
    effect_receipt::EffectReceipt,
    protocol::{GrantedEnvelope, NetdResponse, RejectionCode, SignedEnvelope},
    request_binding::{request_overlay_id, request_parameters},
    server::NetdServer,
    server_grants::reject,
};

pub(crate) struct Dispatch {
    pub envelope: crate::protocol::SignedEnvelope,
    pub receipt: EffectReceipt,
    pub request_id: String,
    pub operation_id: [u8; 16],
    pub nonce: [u8; 16],
}

impl NetdServer {
    pub(crate) fn prepare_dispatch(
        &mut self,
        uid: u32,
        frame: &[u8],
        now: u64,
    ) -> Result<Dispatch, NetdResponse> {
        self.validate_frame(uid, frame)?;
        if let Some(response) = self.try_legacy_frame(&frame[4..], now) {
            return Err(response);
        }
        let granted: GrantedEnvelope = serde_json::from_slice(&frame[4..]).map_err(|_| {
            match serde_json::from_slice::<SignedEnvelope>(&frame[4..]) {
                Ok(legacy) => match self.policy.validate(&legacy, now) {
                    Ok(()) => reject(
                        RejectionCode::MissingGrant,
                        "privileged request requires a grant",
                    ),
                    Err(code) => reject(code, "policy rejected request"),
                },
                Err(_) => reject(RejectionCode::InvalidFrame, "invalid JSON"),
            }
        })?;
        if !self.validate_granted_handshake(&granted.handshake) {
            return Err(reject(
                RejectionCode::PolicyViolation,
                "authorization service identity mismatch",
            ));
        }
        let envelope = granted.envelope;
        self.policy
            .validate(&envelope, now)
            .map_err(|code| reject(code, "policy rejected request"))?;
        let (action, params) = request_parameters(&envelope.request)
            .map_err(|code| reject(code, "invalid normalized parameters"))?;
        if self.request_is_quarantined(&envelope.request) {
            self.policy.rollback(
                request_overlay_id(&envelope.request),
                envelope.epoch,
                envelope.revision,
            );
            return Err(reject(
                RejectionCode::PolicyViolation,
                "resource has unverifiable legacy ownership and requires operator reconciliation",
            ));
        }
        let receipt = EffectReceipt::from_request(
            &envelope.request,
            granted.resource_generation,
            envelope.epoch,
            envelope.revision,
        );
        self.consume_grant(
            &granted.grant,
            action,
            &granted.resource_uuid,
            granted.resource_generation,
            &params,
            receipt.clone(),
            now,
        )
        .map_err(|code| {
            self.policy.rollback(
                request_overlay_id(&envelope.request),
                envelope.epoch,
                envelope.revision,
            );
            reject(code, "authorization grant rejected")
        })?;
        Ok(Dispatch {
            envelope,
            receipt,
            request_id: granted.grant.claims.request_id.clone(),
            operation_id: granted.grant.claims.operation_id,
            nonce: granted.grant.claims.nonce,
        })
    }
}
