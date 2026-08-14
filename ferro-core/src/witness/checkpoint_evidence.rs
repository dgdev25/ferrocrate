use super::{
    decode_record, hash_record, verify_stream, Checkpoint, CheckpointError, StreamTrust,
    VerificationReport, WitnessAction, WitnessStage,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub(super) struct EvidenceIndex {
    heads: HashMap<(u64, u64), [u8; 32]>,
    publications: HashMap<(u64, u64), [u8; 32]>,
}

pub(super) fn index(evidence: &[&[u8]]) -> Result<EvidenceIndex, CheckpointError> {
    let mut heads = HashMap::with_capacity(evidence.len());
    let mut publications = HashMap::new();
    for bytes in evidence {
        let record = decode_record(bytes).map_err(|_| CheckpointError::Rollback)?;
        heads.insert((record.epoch(), record.sequence()), record.record_hash());
        if record.record().stage == WitnessStage::CheckpointPublished
            && record.record().action == WitnessAction::CheckpointPublish
        {
            if let Some(digest) = record.record().result_digest {
                publications.insert((record.epoch(), record.sequence()), digest);
            }
        }
    }
    Ok(EvidenceIndex {
        heads,
        publications,
    })
}

pub(super) fn contains_head(evidence: &[&[u8]], checkpoint: &Checkpoint) -> bool {
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

pub(super) fn is_bound(index: &EvidenceIndex, checkpoint: &Checkpoint) -> bool {
    let head_matches = if checkpoint.head.sequence == 0 {
        checkpoint.head.hash == [0; 32]
    } else {
        let head_epoch = if checkpoint.kind == super::CheckpointKind::TrustReset {
            checkpoint.previous_epoch
        } else {
            checkpoint.head.epoch
        };
        index.heads.get(&(head_epoch, checkpoint.head.sequence)) == Some(&checkpoint.head.hash)
    };
    if !head_matches {
        return false;
    }
    let digest: [u8; 32] = Sha256::digest(checkpoint.encode()).into();
    checkpoint
        .head
        .sequence
        .checked_add(1)
        .is_some_and(|sequence| {
            index.publications.get(&(checkpoint.head.epoch, sequence)) == Some(&digest)
        })
}

pub(super) fn verify(
    evidence: &[&[u8]],
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
    let mut report = verify_epoch_groups(evidence, checkpoint.head.journal_id)?;
    if checkpoint.head.sequence > 0 && !contains_head(evidence, checkpoint) {
        return Err(CheckpointError::Rollback);
    }
    if !is_bound(&index(evidence)?, checkpoint) {
        return Err(CheckpointError::Rollback);
    }
    report.completeness_through_checkpoint = Some(true);
    Ok(report)
}

fn verify_epoch_groups(
    evidence: &[&[u8]],
    journal_id: [u8; 16],
) -> Result<VerificationReport, CheckpointError> {
    let mut start = 0;
    let mut aggregate: Option<VerificationReport> = None;
    let mut expected_sequence = 1_u64;
    let mut expected_predecessor = [0_u8; 32];
    while start < evidence.len() {
        let first = decode_record(evidence[start]).map_err(|_| CheckpointError::Rollback)?;
        let epoch = first.epoch();
        let mut end = start + 1;
        while end < evidence.len() && decode_record(evidence[end]).is_ok_and(|r| r.epoch() == epoch)
        {
            end += 1;
        }
        if first.sequence() != expected_sequence
            || first.record().previous_hash != expected_predecessor
        {
            return Err(CheckpointError::Rollback);
        }
        let trust = StreamTrust::new(journal_id, epoch, first.sequence(), expected_predecessor);
        let current = verify_stream(evidence[start..end].iter().copied(), &trust)
            .map_err(|_| CheckpointError::Rollback)?;
        if let Some(total) = &mut aggregate {
            total.records += current.records;
            total.terminal_denied += current.terminal_denied;
            total.terminal_outcomes += current.terminal_outcomes;
            total.terminal_recoveries += current.terminal_recoveries;
        } else {
            aggregate = Some(current);
        }
        let last = decode_record(evidence[end - 1]).map_err(|_| CheckpointError::Rollback)?;
        expected_sequence = last
            .sequence()
            .checked_add(1)
            .ok_or(CheckpointError::Rollback)?;
        expected_predecessor = hash_record(last.bytes());
        start = end;
    }
    aggregate.ok_or(CheckpointError::Rollback)
}
