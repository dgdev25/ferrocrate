use std::sync::Mutex;

use prost::Message;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{agent::state::{AgentState, StateError, StateStore}, config::MAX_MESSAGE_BYTES, proto::DesiredState};

pub trait NetdClient: Send + Sync {
    fn apply(&self, desired_state: &DesiredState) -> Result<(), String>;
}

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("desired state message exceeds the configured limit")]
    Oversized,
    #[error("desired state belongs to another cluster or epoch")]
    WrongEpoch,
    #[error("desired state revision is stale")]
    StaleRevision,
    #[error("desired state lease has expired")]
    ExpiredLease,
    #[error("desired state signature is invalid")]
    InvalidSignature,
    #[error("netd rejected desired state: {0}")]
    Netd(String),
    #[error(transparent)]
    State(#[from] StateError),
}

pub struct Agent<C> {
    cluster_id: String,
    signing_key: Vec<u8>,
    state: Mutex<AgentState>,
    store: StateStore,
    netd: C,
}

impl<C: NetdClient> Agent<C> {
    pub fn new(cluster_id: impl Into<String>, signing_key: Vec<u8>, store: StateStore, netd: C) -> Result<Self, AgentError> {
        let state = store.load()?;
        Ok(Self { cluster_id: cluster_id.into(), signing_key, state: Mutex::new(state), store, netd })
    }

    pub fn state(&self) -> AgentState { self.state.lock().expect("agent state lock poisoned").clone() }

    pub fn reconcile(&self, desired: DesiredState, now_unix: i64) -> Result<u64, AgentError> {
        if desired.encoded_len() > MAX_MESSAGE_BYTES { return Err(AgentError::Oversized); }
        if desired.cluster_id != self.cluster_id { return Err(AgentError::WrongEpoch); }
        if desired.lease_expires_unix <= now_unix { return Err(AgentError::ExpiredLease); }
        if !self.verify_signature(&desired) { return Err(AgentError::InvalidSignature); }
        let mut current = self.state.lock().expect("agent state lock poisoned");
        if desired.cluster_epoch < current.cluster_epoch || desired.revision <= current.applied_revision { return Err(AgentError::StaleRevision); }
        self.netd.apply(&desired).map_err(AgentError::Netd)?;
        *current = AgentState { cluster_epoch: desired.cluster_epoch, applied_revision: desired.revision, overlays: desired.overlays.iter().map(|overlay| overlay.overlay_id.clone()).collect(), lease_expiry: desired.lease_expires_unix };
        self.store.save(&current)?;
        Ok(current.applied_revision)
    }

    fn verify_signature(&self, desired: &DesiredState) -> bool {
        let mut unsigned = desired.clone();
        let expected = unsigned.signature.clone();
        unsigned.signature.clear();
        let mut digest = Sha256::new();
        digest.update(&self.signing_key);
        digest.update(unsigned.encode_to_vec());
        expected == digest.finalize().to_vec()
    }
}
