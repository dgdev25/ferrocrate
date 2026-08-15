use ed25519_dalek::{Signer, SigningKey};
use prost::Message;

use crate::{
    agent::{desired_authorization::DesiredAuthorizationBundle, netd_client::GrantedEnvelope},
    proto::{DesiredState, OverlayState},
};

pub const MAX_LEASE_SECONDS: i64 = 15 * 60;

#[derive(Debug, Clone)]
pub struct DesiredStateBuilder {
    cluster_id: String,
    cluster_epoch: u64,
    signing_key: [u8; 32],
}

impl DesiredStateBuilder {
    pub fn new(cluster_id: impl Into<String>, cluster_epoch: u64, signing_key: Vec<u8>) -> Self {
        let signing_key: [u8; 32] = signing_key
            .try_into()
            .expect("desired-state signing keys must be 32 bytes");
        Self {
            cluster_id: cluster_id.into(),
            cluster_epoch,
            signing_key,
        }
    }

    pub fn snapshot(
        &self,
        revision: u64,
        overlays: Vec<OverlayState>,
        now_unix: i64,
    ) -> DesiredState {
        self.build(revision, overlays, now_unix)
    }

    pub fn delta(&self, revision: u64, overlays: Vec<OverlayState>, now_unix: i64) -> DesiredState {
        self.build(revision, overlays, now_unix)
    }

    pub fn lease(&self, revision: u64, overlays: Vec<OverlayState>, now_unix: i64) -> DesiredState {
        self.build(revision, overlays, now_unix)
    }

    pub fn authorization_bundle(
        &self,
        desired: &DesiredState,
        node_id: impl Into<String>,
        operations: Vec<GrantedEnvelope>,
    ) -> Result<Vec<u8>, serde_json::Error> {
        let bundle = DesiredAuthorizationBundle::sign(
            desired,
            node_id,
            operations,
            &SigningKey::from_bytes(&self.signing_key),
        )?;
        serde_json::to_vec(&bundle)
    }

    fn build(&self, revision: u64, overlays: Vec<OverlayState>, now_unix: i64) -> DesiredState {
        let lease_expires_unix = now_unix.saturating_add(MAX_LEASE_SECONDS);
        let mut state = DesiredState {
            cluster_id: self.cluster_id.clone(),
            cluster_epoch: self.cluster_epoch,
            revision,
            overlays,
            signature: Vec::new(),
            lease_expires_unix,
        };
        let unsigned = state.encode_to_vec();
        state.signature = SigningKey::from_bytes(&self.signing_key)
            .sign(&unsigned)
            .to_bytes()
            .to_vec();
        state
    }
}
