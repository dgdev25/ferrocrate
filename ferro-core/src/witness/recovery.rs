use super::{WitnessAction, WitnessResourceKind};

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum RecoveryRecipeError {
    #[error("cleanup action is not the closed inverse of the original action and resource kind")]
    InvalidInverse,
    #[error("recovery truth strategy does not match the original container action")]
    InvalidTruthStrategy,
}

/// Version of the private durable recovery-recipe encoding.
pub const RECOVERY_RECIPE_SCHEMA_VERSION: u8 = 2;

/// Closed truth source used to reconcile an unknown container mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RecoveryTruthStrategy {
    ContainerAbsent = 1,
    ExecutionObserved = 2,
    ContainerRunning = 3,
    ContainerPaused = 4,
    RestartObserved = 5,
    ContainerPresent = 6,
    /// Canonical inverse precondition for non-container resources.
    InversePrecondition = 7,
}

impl RecoveryTruthStrategy {
    pub const fn for_container_action(action: WitnessAction) -> Option<Self> {
        match action {
            WitnessAction::ContainerCreate | WitnessAction::ContainerRun => {
                Some(Self::ContainerAbsent)
            }
            WitnessAction::ContainerExec => Some(Self::ExecutionObserved),
            WitnessAction::ContainerPause
            | WitnessAction::ContainerStop
            | WitnessAction::ContainerKill => Some(Self::ContainerRunning),
            WitnessAction::ContainerResume => Some(Self::ContainerPaused),
            WitnessAction::ContainerRestart => Some(Self::RestartObserved),
            WitnessAction::ContainerDelete => Some(Self::ContainerPresent),
            _ => None,
        }
    }
}

/// Domain-separated digest of canonical, sanitized kernel/store observations.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ObservationDigest([u8; 32]);

impl ObservationDigest {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for ObservationDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ObservationDigest([redacted])")
    }
}

/// Non-secret correlation handle for locating the observation; never authority.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ObservationHandle([u8; 16]);

impl ObservationHandle {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl std::fmt::Debug for ObservationHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ObservationHandle([opaque])")
    }
}

/// Stable durable identity for one mutation attempt.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct OperationId(pub(super) [u8; 16]);

impl OperationId {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Closed, idempotent startup recovery instruction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryRecipe {
    original_action: WitnessAction,
    resource_kind: WitnessResourceKind,
    action: WitnessAction,
    precondition_digest: [u8; 32],
    resource_generation: u64,
    truth_strategy: RecoveryTruthStrategy,
    observation_digest: ObservationDigest,
    observation_handle: ObservationHandle,
}

impl RecoveryRecipe {
    /// Construct deletion-only cleanup. Creation, attachment, and arbitrary replay
    /// have no representation in the recovery API.
    pub fn for_original(
        original_action: WitnessAction,
        resource_kind: WitnessResourceKind,
        action: WitnessAction,
        precondition_digest: [u8; 32],
        resource_generation: u64,
    ) -> Result<Self, RecoveryRecipeError> {
        let truth_strategy = RecoveryTruthStrategy::for_container_action(original_action)
            .unwrap_or(RecoveryTruthStrategy::InversePrecondition);
        Self::for_original_with_observation(
            original_action,
            resource_kind,
            action,
            precondition_digest,
            resource_generation,
            truth_strategy,
            ObservationDigest::from_bytes(precondition_digest),
            ObservationHandle::from_bytes([0; 16]),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn for_original_with_observation(
        original_action: WitnessAction,
        resource_kind: WitnessResourceKind,
        action: WitnessAction,
        precondition_digest: [u8; 32],
        resource_generation: u64,
        truth_strategy: RecoveryTruthStrategy,
        observation_digest: ObservationDigest,
        observation_handle: ObservationHandle,
    ) -> Result<Self, RecoveryRecipeError> {
        let valid = matches!(
            (original_action, resource_kind, action),
            (
                WitnessAction::ContainerCreate
                    | WitnessAction::ContainerRun
                    | WitnessAction::ContainerExec
                    | WitnessAction::ContainerPause
                    | WitnessAction::ContainerResume
                    | WitnessAction::ContainerStop
                    | WitnessAction::ContainerKill
                    | WitnessAction::ContainerRestart
                    | WitnessAction::ContainerDelete,
                WitnessResourceKind::Container,
                WitnessAction::ContainerDelete
            ) | (
                WitnessAction::ImagePull,
                WitnessResourceKind::Image,
                WitnessAction::ImageDelete
            ) | (
                WitnessAction::VolumeCreate,
                WitnessResourceKind::Volume,
                WitnessAction::VolumeDelete
            ) | (
                WitnessAction::VolumeMount,
                WitnessResourceKind::Volume,
                WitnessAction::VolumeUnmount
            ) | (
                WitnessAction::NetworkCreate,
                WitnessResourceKind::Network,
                WitnessAction::NetworkDelete
            ) | (
                WitnessAction::NetworkAttach,
                WitnessResourceKind::Network,
                WitnessAction::NetworkDetach
            )
        );
        if !valid {
            return Err(RecoveryRecipeError::InvalidInverse);
        }
        let expected = RecoveryTruthStrategy::for_container_action(original_action)
            .unwrap_or(RecoveryTruthStrategy::InversePrecondition);
        if truth_strategy != expected {
            return Err(RecoveryRecipeError::InvalidTruthStrategy);
        }
        Ok(Self {
            original_action,
            resource_kind,
            action,
            precondition_digest,
            resource_generation,
            truth_strategy,
            observation_digest,
            observation_handle,
        })
    }

    pub const fn action(&self) -> WitnessAction {
        self.action
    }
    pub const fn original_action(&self) -> WitnessAction {
        self.original_action
    }
    pub const fn resource_kind(&self) -> WitnessResourceKind {
        self.resource_kind
    }
    pub const fn precondition_digest(&self) -> &[u8; 32] {
        &self.precondition_digest
    }
    pub const fn resource_generation(&self) -> u64 {
        self.resource_generation
    }
    pub const fn truth_strategy(&self) -> RecoveryTruthStrategy {
        self.truth_strategy
    }
    pub const fn observation_digest(&self) -> &ObservationDigest {
        &self.observation_digest
    }
    pub const fn observation_handle(&self) -> &ObservationHandle {
        &self.observation_handle
    }

    pub(super) fn encode(&self, generation: u64) -> [u8; 101] {
        let mut out = [0; 101];
        out[0] = RECOVERY_RECIPE_SCHEMA_VERSION;
        out[1..9].copy_from_slice(&generation.to_be_bytes());
        out[9] = self.original_action as u8;
        out[10] = self.resource_kind as u8;
        out[11] = self.action as u8;
        out[12] = self.truth_strategy as u8;
        out[13..45].copy_from_slice(self.observation_digest.as_bytes());
        out[45..61].copy_from_slice(self.observation_handle.as_bytes());
        out[61..93].copy_from_slice(&self.precondition_digest);
        out[93..].copy_from_slice(&self.resource_generation.to_be_bytes());
        out
    }

    pub(super) fn decode(bytes: &[u8]) -> Option<(u64, Self)> {
        if bytes.len() != 101 || bytes[0] != RECOVERY_RECIPE_SCHEMA_VERSION {
            return None;
        }
        let generation = u64::from_be_bytes(bytes[1..9].try_into().ok()?);
        let original_action = action_from(bytes[9])?;
        let resource_kind = resource_kind_from(bytes[10])?;
        let action = match bytes[11] {
            9 => WitnessAction::ContainerDelete,
            11 => WitnessAction::ImageDelete,
            13 => WitnessAction::VolumeDelete,
            15 => WitnessAction::VolumeUnmount,
            17 => WitnessAction::NetworkDelete,
            19 => WitnessAction::NetworkDetach,
            _ => return None,
        };
        let truth_strategy = truth_strategy_from(bytes[12])?;
        let recipe = Self::for_original_with_observation(
            original_action,
            resource_kind,
            action,
            bytes[61..93].try_into().ok()?,
            u64::from_be_bytes(bytes[93..].try_into().ok()?),
            truth_strategy,
            ObservationDigest::from_bytes(bytes[13..45].try_into().ok()?),
            ObservationHandle::from_bytes(bytes[45..61].try_into().ok()?),
        )
        .ok()?;
        Some((generation, recipe))
    }
}

fn truth_strategy_from(value: u8) -> Option<RecoveryTruthStrategy> {
    match value {
        1 => Some(RecoveryTruthStrategy::ContainerAbsent),
        2 => Some(RecoveryTruthStrategy::ExecutionObserved),
        3 => Some(RecoveryTruthStrategy::ContainerRunning),
        4 => Some(RecoveryTruthStrategy::ContainerPaused),
        5 => Some(RecoveryTruthStrategy::RestartObserved),
        6 => Some(RecoveryTruthStrategy::ContainerPresent),
        7 => Some(RecoveryTruthStrategy::InversePrecondition),
        _ => None,
    }
}

fn action_from(value: u8) -> Option<WitnessAction> {
    match value {
        1 => Some(WitnessAction::ContainerCreate),
        2 => Some(WitnessAction::ContainerRun),
        3 => Some(WitnessAction::ContainerExec),
        4 => Some(WitnessAction::ContainerPause),
        5 => Some(WitnessAction::ContainerResume),
        6 => Some(WitnessAction::ContainerStop),
        7 => Some(WitnessAction::ContainerKill),
        8 => Some(WitnessAction::ContainerRestart),
        9 => Some(WitnessAction::ContainerDelete),
        10 => Some(WitnessAction::ImagePull),
        12 => Some(WitnessAction::VolumeCreate),
        14 => Some(WitnessAction::VolumeMount),
        16 => Some(WitnessAction::NetworkCreate),
        18 => Some(WitnessAction::NetworkAttach),
        _ => None,
    }
}
fn resource_kind_from(value: u8) -> Option<WitnessResourceKind> {
    match value {
        1 => Some(WitnessResourceKind::Container),
        2 => Some(WitnessResourceKind::Image),
        3 => Some(WitnessResourceKind::Volume),
        4 => Some(WitnessResourceKind::Network),
        _ => None,
    }
}

/// Durable pending state exposed to startup reconciliation. It is an inspection
/// recipe, not authority to replay the original mutation.
///
/// ```compile_fail
/// use ferro_core::witness::{RecoveryEvidence, PendingOperation};
/// fn forge(_: PendingOperation) -> RecoveryEvidence { unreachable!() }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingOperation {
    pub(super) operation_id: OperationId,
    pub(super) execution_generation: u64,
    pub(super) recipe: RecoveryRecipe,
}

/// Opaque result of a strategy-specific live-state verifier.  Only trusted
/// runtime recovery code in this crate can construct this value; callers
/// cannot choose a recovery classification at the journal boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RecoveryEvidence {
    pub(super) operation_id: OperationId,
    pub(super) execution_generation: u64,
    pub(super) original_action: WitnessAction,
    pub(super) resource_kind: WitnessResourceKind,
    pub(super) resource_generation: u64,
    pub(super) truth_strategy: RecoveryTruthStrategy,
    pub(super) observation_handle: ObservationHandle,
    pub(super) observation_digest: ObservationDigest,
    pub(super) recovered: bool,
}

impl RecoveryEvidence {
    pub(crate) fn verified(
        pending: &PendingOperation,
        observation_digest: ObservationDigest,
        recovered: bool,
    ) -> Self {
        Self {
            operation_id: pending.operation_id,
            execution_generation: pending.execution_generation,
            original_action: pending.recipe.original_action,
            resource_kind: pending.recipe.resource_kind,
            resource_generation: pending.recipe.resource_generation,
            truth_strategy: pending.recipe.truth_strategy,
            observation_handle: pending.recipe.observation_handle,
            observation_digest,
            recovered,
        }
    }
}

impl PendingOperation {
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }
    pub const fn execution_generation(&self) -> u64 {
        self.execution_generation
    }
    pub const fn recipe(&self) -> &RecoveryRecipe {
        &self.recipe
    }
}
