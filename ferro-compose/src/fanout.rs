//! Immutable authorization bindings for Compose fan-out.

use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FanoutAction {
    ContainerRun,
    ContainerStop,
    ContainerDelete,
}

impl FanoutAction {
    fn code(self) -> u8 {
        match self {
            Self::ContainerRun => 1,
            Self::ContainerStop => 2,
            Self::ContainerDelete => 3,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceMutation {
    service: String,
    action: FanoutAction,
    request_digest: [u8; 32],
}
impl ServiceMutation {
    pub fn new(service: impl Into<String>, action: FanoutAction, request_digest: [u8; 32]) -> Self {
        Self {
            service: service.into(),
            action,
            request_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FanoutChild {
    parent_request_id: [u8; 16],
    child_id: [u8; 16],
    idempotency_key: [u8; 32],
    service: String,
    action: FanoutAction,
    request_digest: [u8; 32],
    deadline_unix_ms: u64,
    policy_generation: u64,
    policy_digest: [u8; 32],
    attempt: u32,
    ordinal: u32,
    plan_digest: [u8; 32],
}
impl FanoutChild {
    pub fn parent_request_id(&self) -> &[u8; 16] {
        &self.parent_request_id
    }
    pub fn child_id(&self) -> &[u8; 16] {
        &self.child_id
    }
    pub fn idempotency_key(&self) -> &[u8; 32] {
        &self.idempotency_key
    }
    pub fn service(&self) -> &str {
        &self.service
    }
    pub fn action(&self) -> FanoutAction {
        self.action
    }
    pub fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
    }
    pub fn deadline_unix_ms(&self) -> u64 {
        self.deadline_unix_ms
    }
    pub fn policy_generation(&self) -> u64 {
        self.policy_generation
    }
    pub fn policy_digest(&self) -> &[u8; 32] {
        &self.policy_digest
    }
    pub fn attempt(&self) -> u32 {
        self.attempt
    }
    pub fn ordinal(&self) -> u32 {
        self.ordinal
    }
    pub fn plan_digest(&self) -> &[u8; 32] {
        &self.plan_digest
    }
}

#[derive(Clone, Debug)]
pub struct FanoutPlan {
    digest: [u8; 32],
    children: Vec<FanoutChild>,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum FanoutError {
    #[error("fan-out context replay or substitution")]
    Replay,
    #[error("fan-out deadline expired")]
    Expired,
    #[error("fan-out contains too many children")]
    TooManyChildren,
    #[error("fan-out replay store failed: {0}")]
    Storage(String),
}

pub struct FanoutReplayStore {
    db: sled::Db,
}
impl FanoutReplayStore {
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, FanoutError> {
        sled::open(path.as_ref().join("compose-replay.db"))
            .map(|db| Self { db })
            .map_err(|error| FanoutError::Storage(error.to_string()))
    }
    pub fn claim(&self, child: &FanoutChild) -> Result<(), FanoutError> {
        let mut value = Vec::with_capacity(96);
        value.extend_from_slice(&child.idempotency_key);
        value.extend_from_slice(&child.plan_digest);
        value.extend_from_slice(&child.request_digest);
        match self
            .db
            .compare_and_swap(child.child_id, None as Option<&[u8]>, Some(value))
            .map_err(|error| FanoutError::Storage(error.to_string()))?
        {
            Ok(()) => {
                self.db
                    .flush()
                    .map_err(|error| FanoutError::Storage(error.to_string()))?;
                Ok(())
            }
            Err(_) => Err(FanoutError::Replay),
        }
    }
}

impl FanoutPlan {
    pub fn derive_dependent(
        &self,
        predecessor: &FanoutChild,
        predecessor_outcome: [u8; 32],
        mutation: ServiceMutation,
    ) -> Result<Self, FanoutError> {
        self.verify_child(predecessor, predecessor.deadline_unix_ms)?;
        let template = self
            .children
            .get(predecessor.ordinal as usize + 1)
            .filter(|template| {
                template.service == mutation.service && template.action == mutation.action
            })
            .ok_or(FanoutError::Replay)?;
        let mut plan = Sha256::new();
        plan.update(b"ferrocrate/compose-dependent-plan/v1");
        plan.update(self.digest);
        plan.update(predecessor.parent_request_id);
        plan.update(predecessor.child_id);
        plan.update(predecessor_outcome);
        plan.update(template.ordinal.to_be_bytes());
        plan.update([mutation.action.code()]);
        plan.update((mutation.service.len() as u64).to_be_bytes());
        plan.update(mutation.service.as_bytes());
        plan.update(mutation.request_digest);
        let digest: [u8; 32] = plan.finalize().into();
        let mut idem = Sha256::new();
        idem.update(b"ferrocrate/compose-dependent-idempotency/v1");
        idem.update(predecessor.parent_request_id);
        idem.update(self.digest);
        idem.update(predecessor.child_id);
        idem.update(predecessor_outcome);
        idem.update(template.ordinal.to_be_bytes());
        idem.update([mutation.action.code()]);
        idem.update((mutation.service.len() as u64).to_be_bytes());
        idem.update(mutation.service.as_bytes());
        idem.update(mutation.request_digest);
        let idempotency_key: [u8; 32] = idem.finalize().into();
        let mut id = Sha256::new();
        id.update(b"ferrocrate/compose-dependent-child/v1");
        id.update(idempotency_key);
        id.update(predecessor.attempt.to_be_bytes());
        let id_hash: [u8; 32] = id.finalize().into();
        let mut child_id = [0; 16];
        child_id.copy_from_slice(&id_hash[..16]);
        Ok(Self {
            digest,
            children: vec![FanoutChild {
                parent_request_id: predecessor.parent_request_id,
                child_id,
                idempotency_key,
                service: mutation.service,
                action: mutation.action,
                request_digest: mutation.request_digest,
                deadline_unix_ms: predecessor.deadline_unix_ms,
                policy_generation: predecessor.policy_generation,
                policy_digest: predecessor.policy_digest,
                attempt: predecessor.attempt,
                ordinal: template.ordinal,
                plan_digest: digest,
            }],
        })
    }

    pub fn derive<I>(
        parent: [u8; 16],
        generation: u64,
        policy: [u8; 32],
        deadline: u64,
        attempt: u32,
        mutations: I,
    ) -> Result<Self, FanoutError>
    where
        I: IntoIterator<Item = ServiceMutation>,
    {
        let mutations: Vec<_> = mutations.into_iter().collect();
        if mutations.len() > u32::MAX as usize {
            return Err(FanoutError::TooManyChildren);
        }
        let mut plan = Sha256::new();
        plan.update(b"ferrocrate/compose-plan/v1");
        plan.update(parent);
        plan.update(generation.to_be_bytes());
        plan.update(policy);
        plan.update(deadline.to_be_bytes());
        for (ordinal, mutation) in mutations.iter().enumerate() {
            plan.update((ordinal as u32).to_be_bytes());
            plan.update([mutation.action.code()]);
            plan.update((mutation.service.len() as u64).to_be_bytes());
            plan.update(mutation.service.as_bytes());
            plan.update(mutation.request_digest);
        }
        let digest: [u8; 32] = plan.finalize().into();
        let children = mutations
            .into_iter()
            .enumerate()
            .map(|(ordinal, mutation)| {
                let mut idem = Sha256::new();
                idem.update(b"ferrocrate/compose-idempotency/v1");
                idem.update(parent);
                idem.update(digest);
                idem.update((ordinal as u32).to_be_bytes());
                idem.update([mutation.action.code()]);
                idem.update((mutation.service.len() as u64).to_be_bytes());
                idem.update(mutation.service.as_bytes());
                idem.update(mutation.request_digest);
                let idempotency_key: [u8; 32] = idem.finalize().into();
                let mut id = Sha256::new();
                id.update(b"ferrocrate/compose-child/v1");
                id.update(idempotency_key);
                id.update(attempt.to_be_bytes());
                let id_hash: [u8; 32] = id.finalize().into();
                let mut child_id = [0; 16];
                child_id.copy_from_slice(&id_hash[..16]);
                FanoutChild {
                    parent_request_id: parent,
                    child_id,
                    idempotency_key,
                    service: mutation.service,
                    action: mutation.action,
                    request_digest: mutation.request_digest,
                    deadline_unix_ms: deadline,
                    policy_generation: generation,
                    policy_digest: policy,
                    attempt,
                    ordinal: ordinal as u32,
                    plan_digest: digest,
                }
            })
            .collect();
        Ok(Self { digest, children })
    }
    pub fn children(&self) -> &[FanoutChild] {
        &self.children
    }
    pub fn plan_digest(&self) -> &[u8; 32] {
        &self.digest
    }
    pub fn verify_child(&self, child: &FanoutChild, now: u64) -> Result<(), FanoutError> {
        if now > child.deadline_unix_ms {
            return Err(FanoutError::Expired);
        }
        self.children
            .iter()
            .find(|expected| expected.ordinal == child.ordinal)
            .filter(|expected| *expected == child && child.plan_digest == self.digest)
            .map(|_| ())
            .ok_or(FanoutError::Replay)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FanoutOutcome {
    Succeeded,
    Denied(String),
    Failed(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FanoutExecutionError {
    Denied(String),
    Failed(String),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FanoutStatus {
    child_id: [u8; 16],
    outcome: FanoutOutcome,
}
impl FanoutStatus {
    pub fn succeeded(id: [u8; 16]) -> Self {
        Self {
            child_id: id,
            outcome: FanoutOutcome::Succeeded,
        }
    }
    pub fn denied(id: [u8; 16], reason: impl Into<String>) -> Self {
        Self {
            child_id: id,
            outcome: FanoutOutcome::Denied(reason.into()),
        }
    }
    pub fn failed(id: [u8; 16], reason: impl Into<String>) -> Self {
        Self {
            child_id: id,
            outcome: FanoutOutcome::Failed(reason.into()),
        }
    }
    pub fn child_id(&self) -> &[u8; 16] {
        &self.child_id
    }
    pub fn outcome(&self) -> &FanoutOutcome {
        &self.outcome
    }
}
pub struct FanoutResult {
    statuses: Vec<FanoutStatus>,
}
impl FanoutResult {
    pub fn new(statuses: Vec<FanoutStatus>) -> Self {
        Self { statuses }
    }
    pub fn statuses(&self) -> &[FanoutStatus] {
        &self.statuses
    }
    pub fn denied(&self) -> usize {
        self.statuses
            .iter()
            .filter(|s| matches!(s.outcome, FanoutOutcome::Denied(_)))
            .count()
    }
    pub fn failed(&self) -> usize {
        self.statuses
            .iter()
            .filter(|s| matches!(s.outcome, FanoutOutcome::Failed(_)))
            .count()
    }
    pub fn is_partial(&self) -> bool {
        let ok = self
            .statuses
            .iter()
            .filter(|s| matches!(s.outcome, FanoutOutcome::Succeeded))
            .count();
        ok > 0 && ok < self.statuses.len()
    }
}


/// Execute every child through the same verified, durably claimed command
/// path. A denial or failure is recorded per child and never aborts or erases
/// the remaining child results.
pub fn execute_fanout<F, N>(
    plan: &FanoutPlan,
    replay: &FanoutReplayStore,
    mut now_unix_ms: N,
    mut execute: F,
) -> FanoutResult
where
    F: FnMut(&FanoutChild) -> Result<(), FanoutExecutionError>,
    N: FnMut() -> u64,
{
    let statuses = plan
        .children()
        .iter()
        .map(|child| {
            let id = *child.child_id();
            if let Err(error) = plan.verify_child(child, now_unix_ms()) {
                return FanoutStatus::failed(id, error.to_string());
            }
            if let Err(error) = replay.claim(child) {
                return FanoutStatus::failed(id, error.to_string());
            }
            match execute(child) {
                Ok(()) => FanoutStatus::succeeded(id),
                Err(FanoutExecutionError::Denied(reason)) => FanoutStatus::denied(id, reason),
                Err(FanoutExecutionError::Failed(reason)) => FanoutStatus::failed(id, reason),
            }
        })
        .collect();
    FanoutResult::new(statuses)
}
