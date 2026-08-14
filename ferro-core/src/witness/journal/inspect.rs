use super::{
    state::{OperationState, COMPLETE},
    JournalError, WitnessJournal,
};
use crate::witness::{OperationId, PendingOperation, RecoveryRecipe};

impl WitnessJournal {
    pub fn maintain(&self) -> Result<(), JournalError> {
        self.seal_active_segment(true)
    }

    pub fn rotation_deferred(&self) -> Result<bool, JournalError> {
        Ok(self.meta.get(super::ROTATION_DEFERRED)?.is_some())
    }

    pub fn segment_sizes(&self) -> Result<Vec<u64>, JournalError> {
        let mut sizes = Vec::new();
        for entry in self.sealed_segments.iter() {
            let (_, blob) = entry?;
            sizes.push(parse_segment(&blob)?.iter().map(|v| v.len() as u64).sum());
        }
        sizes.push(self.records.iter().try_fold(0_u64, |sum, entry| {
            let (_, value) = entry?;
            Ok::<_, sled::Error>(sum + value.len() as u64)
        })?);
        Ok(sizes)
    }
    pub fn segment_count(&self) -> Result<usize, JournalError> {
        Ok(self.segments.len())
    }
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
        let mut out = Vec::new();
        for entry in self.sealed_segments.iter() {
            let (_, blob) = entry?;
            out.extend(parse_segment(&blob)?);
        }
        for entry in self.records.iter() {
            let (_, bytes) = entry?;
            out.push(bytes.to_vec());
        }
        Ok(out)
    }

    pub fn export_segment(&self, segment: u64) -> Result<Vec<Vec<u8>>, JournalError> {
        let blob = self
            .sealed_segments
            .get(segment.to_be_bytes())?
            .ok_or(JournalError::NotPending)?;
        parse_segment(&blob)
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

fn parse_segment(blob: &[u8]) -> Result<Vec<Vec<u8>>, JournalError> {
    let mut position = 0;
    let mut out = Vec::new();
    while position < blob.len() {
        let header = blob
            .get(position..position + 12)
            .ok_or(JournalError::Corrupt)?;
        let length = u32::from_be_bytes(
            header[8..12]
                .try_into()
                .map_err(|_| JournalError::Corrupt)?,
        ) as usize;
        position += 12;
        let value = blob
            .get(position..position + length)
            .ok_or(JournalError::Corrupt)?;
        out.push(value.to_vec());
        position += length;
    }
    Ok(out)
}
