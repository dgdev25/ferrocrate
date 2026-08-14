use super::WitnessAction;

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
    action: WitnessAction,
    precondition_digest: [u8; 32],
    resource_generation: u64,
}

impl RecoveryRecipe {
    /// Construct deletion-only cleanup. Creation, attachment, and arbitrary replay
    /// have no representation in the recovery API.
    pub fn delete_owned_resource(
        action: WitnessAction,
        precondition_digest: [u8; 32],
        resource_generation: u64,
    ) -> Self {
        assert!(
            matches!(
                action,
                WitnessAction::ContainerDelete
                    | WitnessAction::ImageDelete
                    | WitnessAction::VolumeDelete
                    | WitnessAction::NetworkDelete
                    | WitnessAction::NetworkDetach
                    | WitnessAction::VolumeUnmount
            ),
            "recovery recipes are deletion-only"
        );
        Self {
            action,
            precondition_digest,
            resource_generation,
        }
    }

    pub const fn action(&self) -> WitnessAction {
        self.action
    }
    pub const fn precondition_digest(&self) -> &[u8; 32] {
        &self.precondition_digest
    }
    pub const fn resource_generation(&self) -> u64 {
        self.resource_generation
    }

    pub(super) fn encode(&self, generation: u64) -> [u8; 49] {
        let mut out = [0; 49];
        out[..8].copy_from_slice(&generation.to_be_bytes());
        out[8] = self.action as u8;
        out[9..41].copy_from_slice(&self.precondition_digest);
        out[41..].copy_from_slice(&self.resource_generation.to_be_bytes());
        out
    }

    pub(super) fn decode(bytes: &[u8]) -> Option<(u64, Self)> {
        if bytes.len() != 49 {
            return None;
        }
        let generation = u64::from_be_bytes(bytes[..8].try_into().ok()?);
        let action = match bytes[8] {
            9 => WitnessAction::ContainerDelete,
            11 => WitnessAction::ImageDelete,
            13 => WitnessAction::VolumeDelete,
            15 => WitnessAction::VolumeUnmount,
            17 => WitnessAction::NetworkDelete,
            19 => WitnessAction::NetworkDetach,
            _ => return None,
        };
        Some((
            generation,
            Self {
                action,
                precondition_digest: bytes[9..41].try_into().ok()?,
                resource_generation: u64::from_be_bytes(bytes[41..].try_into().ok()?),
            },
        ))
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
