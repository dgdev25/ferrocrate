use super::{
    state::{OperationState, COMPLETE},
    JournalError, WitnessJournal,
};
use crate::witness::{OperationId, PendingOperation, RecoveryRecipe};

impl WitnessJournal {
    pub fn pending(&self) -> Result<Vec<PendingOperation>, JournalError> {
        self.pending
            .iter()
            .map(|entry| {
                let (key, value) = entry?;
                let id = OperationId(key.as_ref().try_into().map_err(|_| JournalError::Corrupt)?);
                let (execution_generation, recipe) =
                    RecoveryRecipe::decode(&value).ok_or(JournalError::Corrupt)?;
                Ok(PendingOperation {
                    operation_id: id,
                    execution_generation,
                    recipe,
                })
            })
            .collect()
    }

    pub fn records(&self) -> Result<Vec<Vec<u8>>, JournalError> {
        self.records
            .iter()
            .map(|entry| {
                entry
                    .map(|(_, bytes)| bytes.to_vec())
                    .map_err(JournalError::Storage)
            })
            .collect()
    }

    pub fn recover(&self, id: OperationId) -> Result<PendingOperation, JournalError> {
        let value = self
            .pending
            .get(id.0)?
            .ok_or_else(|| match self.operations.get(id.0) {
                Ok(Some(bytes))
                    if OperationState::decode(&bytes)
                        .is_some_and(|state| state.state == COMPLETE) =>
                {
                    JournalError::AlreadyComplete
                }
                _ => JournalError::NotPending,
            })?;
        let (execution_generation, recipe) =
            RecoveryRecipe::decode(&value).ok_or(JournalError::Corrupt)?;
        Ok(PendingOperation {
            operation_id: id,
            execution_generation,
            recipe,
        })
    }
}
