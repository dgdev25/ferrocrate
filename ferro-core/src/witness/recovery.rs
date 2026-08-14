use super::{WitnessAction, WitnessResourceKind};

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum RecoveryRecipeError {
    #[error("cleanup action is not the closed inverse of the original action and resource kind")]
    InvalidInverse,
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
        let valid = matches!(
            (original_action, resource_kind, action),
            (
                WitnessAction::ContainerCreate | WitnessAction::ContainerRun,
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
        Ok(Self {
            original_action,
            resource_kind,
            action,
            precondition_digest,
            resource_generation,
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

    pub(super) fn encode(&self, generation: u64) -> [u8; 51] {
        let mut out = [0; 51];
        out[..8].copy_from_slice(&generation.to_be_bytes());
        out[8] = self.original_action as u8;
        out[9] = self.resource_kind as u8;
        out[10] = self.action as u8;
        out[11..43].copy_from_slice(&self.precondition_digest);
        out[43..].copy_from_slice(&self.resource_generation.to_be_bytes());
        out
    }

    pub(super) fn decode(bytes: &[u8]) -> Option<(u64, Self)> {
        if bytes.len() != 51 {
            return None;
        }
        let generation = u64::from_be_bytes(bytes[..8].try_into().ok()?);
        let original_action = action_from(bytes[8])?;
        let resource_kind = resource_kind_from(bytes[9])?;
        let action = match bytes[10] {
            9 => WitnessAction::ContainerDelete,
            11 => WitnessAction::ImageDelete,
            13 => WitnessAction::VolumeDelete,
            15 => WitnessAction::VolumeUnmount,
            17 => WitnessAction::NetworkDelete,
            19 => WitnessAction::NetworkDetach,
            _ => return None,
        };
        let recipe = Self::for_original(
            original_action,
            resource_kind,
            action,
            bytes[11..43].try_into().ok()?,
            u64::from_be_bytes(bytes[43..].try_into().ok()?),
        )
        .ok()?;
        Some((generation, recipe))
    }
}

fn action_from(value: u8) -> Option<WitnessAction> {
    match value {
        1 => Some(WitnessAction::ContainerCreate),
        2 => Some(WitnessAction::ContainerRun),
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingOperation {
    pub(super) operation_id: OperationId,
    pub(super) execution_generation: u64,
    pub(super) recipe: RecoveryRecipe,
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
