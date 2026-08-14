use super::{
    decode_record, hash_record, verify_stream, Checkpoint, CheckpointError, StreamTrust,
    VerificationReport, WitnessAction, WitnessStage,
};
use sha2::{Digest, Sha256};

pub(super) fn contains_head(evidence: &[Vec<u8>], checkpoint: &Checkpoint) -> bool {
    if checkpoint.head.sequence == 0 {
        return checkpoint.head.hash == [0; 32];
    }
    evidence.iter().any(|bytes| {
        decode_record(bytes).is_ok_and(|record| {
            record.sequence() == checkpoint.head.sequence
                && hash_record(record.bytes()) == checkpoint.head.hash
        })
    })
}

pub(super) fn is_bound(evidence: &[Vec<u8>], checkpoint: &Checkpoint) -> bool {
    if !contains_head(evidence, checkpoint) {
        return false;
    }
    let digest: [u8; 32] = Sha256::digest(checkpoint.encode()).into();
    evidence.iter().any(|bytes| {
        decode_record(bytes).is_ok_and(|record| {
            record.sequence() == checkpoint.head.sequence + 1
                && record.record().stage == WitnessStage::CheckpointPublished
                && record.record().action == WitnessAction::CheckpointPublish
                && record.record().result_digest == Some(digest)
        })
    })
}

pub(super) fn verify(
    evidence: &[Vec<u8>],
    checkpoint: &Checkpoint,
) -> Result<VerificationReport, CheckpointError> {
    if (checkpoint.head.sequence == 0 && checkpoint.head.hash != [0; 32]) || evidence.is_empty() {
        return Err(CheckpointError::Rollback);
    }
    let decoded_first = decode_record(evidence.first().ok_or(CheckpointError::Rollback)?)
        .map_err(|_| CheckpointError::Rollback)?;
    if decoded_first.sequence() != checkpoint.first_sequence || checkpoint.first_sequence != 1 {
        return Err(CheckpointError::Rollback);
    }
    let trust = StreamTrust::new(
        checkpoint.head.journal_id,
        checkpoint.first_sequence,
        [0; 32],
    );
    let mut report = verify_stream(evidence.iter().map(Vec::as_slice), &trust)
        .map_err(|_| CheckpointError::Rollback)?;
    if checkpoint.head.sequence > 0 && !contains_head(evidence, checkpoint) {
        return Err(CheckpointError::Rollback);
    }
    if !is_bound(evidence, checkpoint) {
        return Err(CheckpointError::Rollback);
    }
    report.completeness_through_checkpoint = Some(true);
    Ok(report)
}
