use crate::{
    effect_receipt::EffectReceipt,
    protocol::{NetdResponse, RejectionCode},
    server::NetdServer,
    server_grants::reject,
};

impl NetdServer {
    pub(crate) fn execute_detach(
        &mut self,
        request_id: String,
        operation_id: [u8; 16],
        nonce: [u8; 16],
        receipt: EffectReceipt,
        endpoint_id: String,
    ) -> NetdResponse {
        let identity = format!("endpoint:{endpoint_id}");
        if self
            .begin_overlay_intent(operation_id, "detach", receipt.clone(), vec![], vec![])
            .is_err()
        {
            let _ = self.record_grant_failure(
                &request_id,
                nonce,
                identity,
                "failed to persist endpoint deletion intent",
            );
            return reject(
                RejectionCode::Busy,
                "failed to persist endpoint deletion intent",
            );
        }
        if self.endpoints.contains_key(&endpoint_id) {
            if self.kernel.remove_endpoint(&endpoint_id).is_err() {
                return self.detach_unknown(
                    nonce,
                    identity,
                    receipt,
                    "failed to destroy endpoint veth",
                );
            }
            if self
                .mark_overlay_intent(&identity, "endpoint_link_removed")
                .is_err()
            {
                return self.detach_unknown(
                    nonce,
                    identity,
                    receipt,
                    "failed to persist mutation phase",
                );
            }
            self.endpoints.remove(&endpoint_id);
        }
        self.effect_receipts.remove(&identity);
        if let Some(intent) = self.overlay_intents.get_mut(&identity) {
            intent.phase = "succeeded".into();
        }
        if self.persist_ownership().is_err() {
            self.quarantined.insert(format!("ambiguous-{identity}"));
            return self.detach_unknown(
                nonce,
                identity,
                receipt,
                "failed to persist endpoint deletion",
            );
        }
        if self
            .record_grant_result(&request_id, nonce, identity, "detached")
            .is_err()
        {
            return reject(RejectionCode::Busy, "result witness unavailable");
        }
        NetdResponse::Detached
    }

    fn detach_unknown(
        &mut self,
        nonce: [u8; 16],
        identity: String,
        receipt: EffectReceipt,
        reason: &'static str,
    ) -> NetdResponse {
        let _ = self.mark_overlay_intent(&identity, "outcome_unknown");
        if self.record_grant_unknown(nonce, identity, receipt).is_err() {
            return reject(RejectionCode::Busy, "failure witness unavailable");
        }
        reject(RejectionCode::Busy, reason)
    }
}
