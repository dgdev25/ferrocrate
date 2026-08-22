//! Authorization-bound instance mutations.
//!
//! Every start/stop the supervisor issues carries an Ed25519 signature over
//! the mutation intent (node ID, action, target, revision, issue time).
//! Executors must verify the signature, the node binding, and freshness
//! before producing any effect — the same fail-closed contract as the
//! desired-state authorization bundles in `crate::agent::desired_authorization`.

use std::{
    collections::BTreeMap,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A signed mutation is valid for this many seconds after issuance.
pub const MAX_MUTATION_AGE_SECONDS: i64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MutationAction {
    Start,
    Stop,
}

/// What the controller ordered: start or stop one instance on one node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationIntent {
    pub node_id: String,
    pub action: MutationAction,
    pub instance_id: String,
    pub service: String,
    pub image: String,
    pub target_revision: u64,
    pub issued_unix: i64,
}

/// Intent plus its detached signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationAuthorization {
    pub intent: MutationIntent,
    pub signature: [u8; 64],
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthorizationError {
    #[error("mutation signature is invalid")]
    InvalidSignature,
    #[error("mutation is bound to another node")]
    WrongNode,
    #[error("mutation has expired")]
    Expired,
}

impl MutationAuthorization {
    /// Sign an intent with the controller key.
    pub fn sign(intent: MutationIntent, key: &SigningKey) -> Self {
        let signature = key.sign(&canonical_bytes(&intent)).to_bytes();
        Self { intent, signature }
    }

    /// Verify signature, node binding, and freshness.
    pub fn verify(
        &self,
        node_id: &str,
        key: &VerifyingKey,
        now_unix: i64,
    ) -> Result<(), AuthorizationError> {
        if self.intent.node_id != node_id {
            return Err(AuthorizationError::WrongNode);
        }
        if now_unix - self.intent.issued_unix > MAX_MUTATION_AGE_SECONDS
            || self.intent.issued_unix > now_unix + MAX_MUTATION_AGE_SECONDS
        {
            return Err(AuthorizationError::Expired);
        }
        let signature = ed25519_dalek::Signature::from_bytes(&self.signature);
        key.verify(&canonical_bytes(&self.intent), &signature)
            .map_err(|_| AuthorizationError::InvalidSignature)
    }
}

fn canonical_bytes(intent: &MutationIntent) -> Vec<u8> {
    // Field-order-stable encoding: serde_json with struct field order.
    serde_json::to_vec(intent).unwrap_or_default()
}

/// Observed state of one instance, as reported by the executor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceView {
    pub instance_id: String,
    pub service: String,
    pub revision: u64,
    pub image: String,
    pub running: bool,
    pub healthy: bool,
    pub address: Option<String>,
    pub port: u16,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ExecutorError {
    #[error("mutation rejected: {0}")]
    Rejected(String),
    #[error("mutation failed: {0}")]
    Failed(String),
    #[error("executor inspection failed: {0}")]
    Inspect(String),
}

/// Effect-producing boundary of the node. Implementations must verify the
/// authorization before acting and must treat repeated identical mutations
/// as idempotent no-ops so crash recovery can safely re-issue them.
pub trait WorkloadExecutor: Send + Sync {
    fn start(&self, authorization: &MutationAuthorization) -> Result<(), ExecutorError>;
    fn stop(&self, authorization: &MutationAuthorization) -> Result<(), ExecutorError>;
    fn list(&self) -> Result<Vec<InstanceView>, ExecutorError>;
}

/// One recorded executor decision, for replay and audit in tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedMutation {
    pub action: MutationAction,
    pub instance_id: String,
    pub outcome: RecordedOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordedOutcome {
    Applied,
    AlreadySatisfied,
    Rejected,
}

/// In-memory executor that enforces the authorization contract and records
/// every decision. Used by the lifecycle tests and as the reference
/// implementation of the idempotency rules.
pub struct RecordingExecutor {
    node_id: String,
    controller_key: VerifyingKey,
    instances: Mutex<BTreeMap<String, InstanceView>>,
    log: Mutex<Vec<RecordedMutation>>,
    unhealthy: Mutex<Vec<String>>,
    fail_starts_for: Mutex<Vec<String>>,
}

impl RecordingExecutor {
    pub fn new(node_id: impl Into<String>, controller_key: &SigningKey) -> Self {
        Self {
            node_id: node_id.into(),
            controller_key: controller_key.verifying_key(),
            instances: Mutex::new(BTreeMap::new()),
            log: Mutex::new(Vec::new()),
            unhealthy: Mutex::new(Vec::new()),
            fail_starts_for: Mutex::new(Vec::new()),
        }
    }

    /// Force an instance to report unhealthy.
    pub fn set_unhealthy(&self, instance_id: &str) {
        let mut instances = self.instances.lock().unwrap();
        self.unhealthy.lock().unwrap().push(instance_id.into());
        if let Some(view) = instances.get_mut(instance_id) {
            view.healthy = false;
        }
    }

    /// Clear an unhealthy marking.
    pub fn clear_unhealthy(&self, instance_id: &str) {
        let mut instances = self.instances.lock().unwrap();
        self.unhealthy
            .lock()
            .unwrap()
            .retain(|id| id != instance_id);
        if let Some(view) = instances.get_mut(instance_id) {
            view.healthy = true;
        }
    }

    /// Make starts of the given instance fail (simulates a bad revision).
    pub fn fail_starts_for(&self, instance_id: &str) {
        self.fail_starts_for
            .lock()
            .unwrap()
            .push(instance_id.into());
    }

    pub fn recorded(&self) -> Vec<RecordedMutation> {
        self.log.lock().unwrap().clone()
    }

    /// Number of instances currently running.
    pub fn running_count(&self) -> usize {
        self.instances.lock().unwrap().len()
    }

    pub fn instance(&self, instance_id: &str) -> Option<InstanceView> {
        self.instances.lock().unwrap().get(instance_id).cloned()
    }

    fn verify(&self, authorization: &MutationAuthorization) -> Result<(), ExecutorError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs() as i64)
            .unwrap_or(i64::MAX);
        authorization
            .verify(&self.node_id, &self.controller_key, now)
            .map_err(|error| ExecutorError::Rejected(error.to_string()))
    }
}

impl WorkloadExecutor for RecordingExecutor {
    fn start(&self, authorization: &MutationAuthorization) -> Result<(), ExecutorError> {
        self.verify(authorization)?;
        let intent = &authorization.intent;
        if intent.action != MutationAction::Start {
            return Err(ExecutorError::Rejected(
                "authorization does not permit start".into(),
            ));
        }
        if self
            .fail_starts_for
            .lock()
            .unwrap()
            .iter()
            .any(|id| id == &intent.instance_id)
        {
            self.log.lock().unwrap().push(RecordedMutation {
                action: MutationAction::Start,
                instance_id: intent.instance_id.clone(),
                outcome: RecordedOutcome::Rejected,
            });
            return Err(ExecutorError::Failed("image failed to start".into()));
        }
        let mut instances = self.instances.lock().unwrap();
        let already = instances
            .get(&intent.instance_id)
            .is_some_and(|view| view.running);
        let healthy = !self
            .unhealthy
            .lock()
            .unwrap()
            .iter()
            .any(|id| id == &intent.instance_id);
        instances.insert(
            intent.instance_id.clone(),
            InstanceView {
                instance_id: intent.instance_id.clone(),
                service: intent.service.clone(),
                revision: intent.target_revision,
                image: intent.image.clone(),
                running: true,
                healthy,
                address: Some("127.0.0.1".into()),
                port: 8080,
            },
        );
        self.log.lock().unwrap().push(RecordedMutation {
            action: MutationAction::Start,
            instance_id: intent.instance_id.clone(),
            outcome: if already {
                RecordedOutcome::AlreadySatisfied
            } else {
                RecordedOutcome::Applied
            },
        });
        Ok(())
    }

    fn stop(&self, authorization: &MutationAuthorization) -> Result<(), ExecutorError> {
        self.verify(authorization)?;
        let intent = &authorization.intent;
        if intent.action != MutationAction::Stop {
            return Err(ExecutorError::Rejected(
                "authorization does not permit stop".into(),
            ));
        }
        let mut instances = self.instances.lock().unwrap();
        let absent = instances.remove(&intent.instance_id).is_none();
        self.log.lock().unwrap().push(RecordedMutation {
            action: MutationAction::Stop,
            instance_id: intent.instance_id.clone(),
            outcome: if absent {
                RecordedOutcome::AlreadySatisfied
            } else {
                RecordedOutcome::Applied
            },
        });
        Ok(())
    }

    fn list(&self) -> Result<Vec<InstanceView>, ExecutorError> {
        Ok(self.instances.lock().unwrap().values().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now_unix() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs() as i64)
            .unwrap_or(0)
    }

    fn intent(action: MutationAction, node: &str, issued: i64) -> MutationIntent {
        MutationIntent {
            node_id: node.into(),
            action,
            instance_id: "web-r1-0".into(),
            service: "web".into(),
            image: "registry.local/demo:1".into(),
            target_revision: 1,
            issued_unix: issued,
        }
    }

    #[test]
    fn executor_applies_authorized_mutations_idempotently() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let executor = RecordingExecutor::new("node-a", &key);
        let now = now_unix();
        let authorization =
            MutationAuthorization::sign(intent(MutationAction::Start, "node-a", now), &key);
        executor.start(&authorization).unwrap();
        executor.start(&authorization).unwrap();
        assert_eq!(executor.running_count(), 1);
        assert_eq!(executor.recorded().len(), 2);
        assert_eq!(
            executor.recorded()[1].outcome,
            RecordedOutcome::AlreadySatisfied
        );

        let stop = MutationAuthorization::sign(intent(MutationAction::Stop, "node-a", now), &key);
        executor.stop(&stop).unwrap();
        executor.stop(&stop).unwrap();
        assert_eq!(executor.running_count(), 0);
    }

    #[test]
    fn executor_rejects_foreign_signatures_nodes_and_stale_intents() {
        let controller = SigningKey::from_bytes(&[7; 32]);
        let other = SigningKey::from_bytes(&[8; 32]);
        let executor = RecordingExecutor::new("node-a", &controller);

        let now = now_unix();
        let forged =
            MutationAuthorization::sign(intent(MutationAction::Start, "node-a", now), &other);
        assert!(matches!(
            executor.start(&forged),
            Err(ExecutorError::Rejected(_))
        ));

        let wrong_node =
            MutationAuthorization::sign(intent(MutationAction::Start, "node-b", now), &controller);
        assert!(matches!(
            executor.start(&wrong_node),
            Err(ExecutorError::Rejected(_))
        ));

        // The recording executor verifies freshness against the wall clock,
        // so an intent issued far in the past is expired.
        let stale =
            MutationAuthorization::sign(intent(MutationAction::Start, "node-a", now), &controller);
        let mut expired = stale;
        expired.intent.issued_unix -= MAX_MUTATION_AGE_SECONDS + 1;
        assert!(matches!(
            executor.start(&expired),
            Err(ExecutorError::Rejected(_))
        ));
        assert_eq!(executor.running_count(), 0);
    }

    #[test]
    fn action_mismatch_is_rejected() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let executor = RecordingExecutor::new("node-a", &key);
        let stop_auth =
            MutationAuthorization::sign(intent(MutationAction::Stop, "node-a", now_unix()), &key);
        assert!(matches!(
            executor.start(&stop_auth),
            Err(ExecutorError::Rejected(_))
        ));
    }

    #[test]
    fn verify_enforces_freshness_bound() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let now = 10_000;
        let fresh = MutationAuthorization::sign(intent(MutationAction::Start, "node-a", now), &key);
        assert_eq!(fresh.verify("node-a", &key.verifying_key(), now), Ok(()));
        assert_eq!(
            fresh.verify(
                "node-a",
                &key.verifying_key(),
                now + MAX_MUTATION_AGE_SECONDS + 1
            ),
            Err(AuthorizationError::Expired)
        );
        assert_eq!(
            fresh.verify(
                "node-a",
                &key.verifying_key(),
                now - MAX_MUTATION_AGE_SECONDS - 1
            ),
            Err(AuthorizationError::Expired)
        );
    }
}
