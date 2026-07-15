use prost::Message;
use sha2::{Digest, Sha256};

use crate::proto::{DesiredState, OverlayState};

pub const MAX_LEASE_SECONDS: i64 = 15 * 60;

#[derive(Debug, Clone)]
pub struct DesiredStateBuilder {
    cluster_id: String,
    cluster_epoch: u64,
    signing_key: Vec<u8>,
}

impl DesiredStateBuilder {
    pub fn new(cluster_id: impl Into<String>, cluster_epoch: u64, signing_key: Vec<u8>) -> Self {
        Self { cluster_id: cluster_id.into(), cluster_epoch, signing_key }
    }

    pub fn snapshot(&self, revision: u64, overlays: Vec<OverlayState>, now_unix: i64) -> DesiredState {
        self.build(revision, overlays, now_unix)
    }

    pub fn delta(&self, revision: u64, overlays: Vec<OverlayState>, now_unix: i64) -> DesiredState {
        self.build(revision, overlays, now_unix)
    }

    pub fn lease(&self, revision: u64, overlays: Vec<OverlayState>, now_unix: i64) -> DesiredState {
        self.build(revision, overlays, now_unix)
    }

    fn build(&self, revision: u64, overlays: Vec<OverlayState>, now_unix: i64) -> DesiredState {
        let lease_expires_unix = now_unix.saturating_add(MAX_LEASE_SECONDS);
        let mut state = DesiredState { cluster_id: self.cluster_id.clone(), cluster_epoch: self.cluster_epoch, revision, overlays, signature: Vec::new(), lease_expires_unix };
        let mut digest = Sha256::new();
        digest.update(&self.signing_key);
        let unsigned = state.encode_to_vec();
        digest.update(unsigned);
        state.signature = digest.finalize().to_vec();
        state
    }
}
