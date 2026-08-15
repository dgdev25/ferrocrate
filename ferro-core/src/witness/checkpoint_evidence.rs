use super::{
    decode_record, Checkpoint, CheckpointError, CheckpointKind, StreamTrust, VerificationReport,
    WitnessAction, WitnessStage,
};
use crate::witness::verify::StreamVerifier;
use sha2::{Digest, Sha256};

pub(super) fn verify_streaming<I, T>(
    evidence: I,
    journal_id: [u8; 16],
    checkpoints: &[Checkpoint],
    max_records: u64,
    starting_epoch: u64,
    first_sequence: u64,
    predecessor_hash: [u8; 32],
) -> Result<VerificationReport, CheckpointError>
where
    I: IntoIterator<Item = T>,
    T: AsRef<[u8]>,
{
    checkpoints.first().ok_or(CheckpointError::Untrusted)?;
    let mut verifier = StreamVerifier::new(
        StreamTrust::new(journal_id, starting_epoch, first_sequence, predecessor_hash)
            .with_max_records(max_records),
    );
    let mut checkpoint_cursor = 0_usize;
    let mut current_epoch = starting_epoch;

    for item in evidence {
        let bytes = item.as_ref();
        let decoded = decode_record(bytes).map_err(|_| CheckpointError::Rollback)?;
        let record = decoded.record();
        let expected_checkpoint = checkpoints.get(checkpoint_cursor);
        let binds_checkpoint = expected_checkpoint.is_some_and(|checkpoint| {
            checkpoint.head.sequence.checked_add(1) == Some(record.sequence)
        });

        if binds_checkpoint {
            let checkpoint = expected_checkpoint.ok_or(CheckpointError::Rollback)?;
            let digest: [u8; 32] = Sha256::digest(checkpoint.encode()).into();
            if record.stage != WitnessStage::CheckpointPublished
                || record.action != WitnessAction::CheckpointPublish
                || record.result_digest != Some(digest)
                || record.previous_hash != checkpoint.head.hash
                || record.epoch != checkpoint.head.epoch
            {
                return Err(CheckpointError::Rollback);
            }
            if checkpoint.kind == CheckpointKind::TrustReset {
                if checkpoint.previous_epoch != current_epoch
                    || checkpoint.head.epoch
                        != current_epoch
                            .checked_add(1)
                            .ok_or(CheckpointError::Rollback)?
                {
                    return Err(CheckpointError::Rollback);
                }
                verifier
                    .advance_epoch(checkpoint.head.epoch)
                    .map_err(|_| CheckpointError::Rollback)?;
                current_epoch = checkpoint.head.epoch;
            } else if checkpoint.head.epoch != current_epoch {
                return Err(CheckpointError::Rollback);
            }
            checkpoint_cursor += 1;
        } else {
            if expected_checkpoint
                .is_some_and(|checkpoint| checkpoint.head.sequence < record.sequence)
                || record.epoch != current_epoch
            {
                return Err(CheckpointError::Rollback);
            }
        }
        verifier
            .push(bytes)
            .map_err(|_| CheckpointError::Rollback)?;
    }
    if checkpoint_cursor != checkpoints.len() {
        return Err(CheckpointError::Rollback);
    }
    verifier.finish().map_err(|_| CheckpointError::Rollback)
}
