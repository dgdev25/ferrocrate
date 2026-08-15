use std::sync::Mutex;

use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use prost::Message;
use thiserror::Error;

use crate::{
    agent::{
        desired_authorization::DesiredAuthorizationBundle,
        netd_sequence::NetdSequence,
        state::{AgentState, StateError, StateStore},
    },
    config::MAX_MESSAGE_BYTES,
    proto::DesiredState,
};

pub trait NetdClient: Send + Sync {
    fn apply(&self, desired_state: &DesiredState) -> Result<(), String>;
    fn apply_authorized(
        &self,
        _desired_state: &DesiredState,
        _bundle: &DesiredAuthorizationBundle,
    ) -> Result<(), String> {
        Err("netd client does not support authorized reconciliation".into())
    }
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
    #[error("desired-state authorization bundle is required")]
    MissingAuthorization,
    #[error("desired-state authorization bundle is invalid")]
    InvalidAuthorization,
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
    enforce_authorization: bool,
    controller_keys: Vec<Vec<u8>>,
    netd_sequence: Option<NetdSequence>,
    netd_envelope_signer: Option<SigningKey>,
}

impl<C: NetdClient> Agent<C> {
    pub fn new(
        cluster_id: impl Into<String>,
        signing_key: Vec<u8>,
        store: StateStore,
        netd: C,
    ) -> Result<Self, AgentError> {
        let state = store.load()?;
        Ok(Self {
            cluster_id: cluster_id.into(),
            signing_key,
            state: Mutex::new(state),
            store,
            netd,
            enforce_authorization: false,
            controller_keys: Vec::new(),
            netd_sequence: None,
            netd_envelope_signer: None,
        })
    }

    pub fn with_netd_sequence(mut self, sequence: NetdSequence) -> Self {
        self.netd_sequence = Some(sequence);
        self
    }

    pub fn with_netd_envelope_signer(mut self, signer: SigningKey) -> Self {
        self.netd_envelope_signer = Some(signer);
        self
    }

    pub fn new_enforcing(
        cluster_id: impl Into<String>,
        signing_key: Vec<u8>,
        store: StateStore,
        netd: C,
    ) -> Result<Self, AgentError> {
        let mut agent = Self::new(cluster_id, signing_key, store, netd)?;
        agent.enforce_authorization = true;
        agent.controller_keys = vec![agent.signing_key.clone()];
        Ok(agent)
    }

    pub fn new_enforcing_with_overlap(
        cluster_id: impl Into<String>,
        signing_keys: Vec<Vec<u8>>,
        store: StateStore,
        netd: C,
    ) -> Result<Self, AgentError> {
        if signing_keys.is_empty() || signing_keys.len() > 2 {
            return Err(AgentError::InvalidAuthorization);
        }
        let mut agent = Self::new(cluster_id, signing_keys[0].clone(), store, netd)?;
        agent.enforce_authorization = true;
        agent.controller_keys = signing_keys;
        Ok(agent)
    }

    pub fn state(&self) -> AgentState {
        self.state
            .lock()
            .expect("agent state lock poisoned")
            .clone()
    }

    pub fn reconcile(&self, desired: DesiredState, now_unix: i64) -> Result<u64, AgentError> {
        if self.enforce_authorization {
            return Err(AgentError::MissingAuthorization);
        }
        self.reconcile_verified(desired, None, now_unix)
    }

    pub fn reconcile_with_bundle(
        &self,
        desired: DesiredState,
        encoded_bundle: &[u8],
        now_unix: i64,
    ) -> Result<u64, AgentError> {
        let bundle = self
            .controller_keys
            .iter()
            .find_map(|bytes| {
                let raw: [u8; 32] = bytes.as_slice().try_into().ok()?;
                let key = VerifyingKey::from_bytes(&raw).ok()?;
                DesiredAuthorizationBundle::decode_and_verify(
                    encoded_bundle,
                    &desired,
                    &key,
                    now_unix,
                )
                .ok()
            })
            .ok_or(AgentError::InvalidAuthorization)?;
        self.reconcile_verified(desired, Some(&bundle), now_unix)
    }

    fn reconcile_verified(
        &self,
        desired: DesiredState,
        bundle: Option<&DesiredAuthorizationBundle>,
        now_unix: i64,
    ) -> Result<u64, AgentError> {
        if desired.encoded_len() > MAX_MESSAGE_BYTES {
            return Err(AgentError::Oversized);
        }
        if desired.cluster_id != self.cluster_id {
            return Err(AgentError::WrongEpoch);
        }
        if desired.lease_expires_unix <= now_unix {
            return Err(AgentError::ExpiredLease);
        }
        if !self.verify_signature(&desired) {
            return Err(AgentError::InvalidSignature);
        }
        let mut current = self.state.lock().expect("agent state lock poisoned");
        if desired.cluster_epoch < current.cluster_epoch
            || (desired.cluster_epoch == current.cluster_epoch
                && (desired.revision < current.applied_revision
                    || (desired.revision == current.applied_revision
                        && desired.lease_expires_unix <= current.lease_expiry)))
        {
            return Err(AgentError::StaleRevision);
        }
        if let Some(bundle) = bundle {
            bundle
                .validate_transition(&desired, &current.overlays)
                .map_err(|_| AgentError::InvalidAuthorization)?;
        }
        let mapped_bundle = match (bundle, &self.netd_sequence, &self.netd_envelope_signer) {
            (Some(bundle), Some(sequence), Some(signer)) => {
                let mut mapped = bundle.clone();
                for (child, operation) in mapped.operations.iter_mut().enumerate() {
                    let reserved = sequence
                        .reserve_controller(desired.cluster_epoch, desired.revision, child as u32)
                        .map_err(|error| AgentError::Netd(error.to_string()))?;
                    operation.envelope.epoch = reserved.epoch;
                    operation.envelope.revision = reserved.revision;
                    operation.envelope.signature.clear();
                    operation.envelope.signature = base64::engine::general_purpose::STANDARD
                        .encode(
                            signer
                                .sign(
                                    &serde_json::to_vec(&operation.envelope)
                                        .map_err(|error| AgentError::Netd(error.to_string()))?,
                                )
                                .to_bytes(),
                        );
                }
                Some(mapped)
            }
            _ => None,
        };
        match bundle {
            Some(bundle) => self
                .netd
                .apply_authorized(&desired, mapped_bundle.as_ref().unwrap_or(bundle)),
            None => self.netd.apply(&desired),
        }
        .map_err(AgentError::Netd)?;
        let next = AgentState {
            cluster_epoch: desired.cluster_epoch,
            applied_revision: desired.revision,
            overlays: desired
                .overlays
                .iter()
                .map(|overlay| overlay.overlay_id.clone())
                .collect(),
            lease_expiry: desired.lease_expires_unix,
        };
        self.store.save(&next)?;
        *current = next;
        Ok(current.applied_revision)
    }

    fn verify_signature(&self, desired: &DesiredState) -> bool {
        let mut unsigned = desired.clone();
        let expected = unsigned.signature.clone();
        unsigned.signature.clear();
        let key: [u8; 32] = match self.signing_key.as_slice().try_into() {
            Ok(key) => key,
            Err(_) => return false,
        };
        let verifying_key = match VerifyingKey::from_bytes(&key) {
            Ok(key) => key,
            Err(_) => return false,
        };
        let signature = match Signature::from_slice(&expected) {
            Ok(signature) => signature,
            Err(_) => return false,
        };
        verifying_key
            .verify(&unsigned.encode_to_vec(), &signature)
            .is_ok()
    }
}
