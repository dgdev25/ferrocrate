use std::collections::{HashMap, HashSet};

use super::{
    decode_record, hash_record, WitnessError, WitnessOutcome, WitnessRecord, WitnessStage,
};

const MAX_OPEN_REQUESTS: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamTrust {
    expected_journal_id: [u8; 16],
}

impl StreamTrust {
    pub fn new(expected_journal_id: [u8; 16]) -> Self {
        Self {
            expected_journal_id,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationReport {
    pub integrity: bool,
    pub lifecycle_consistent: bool,
    pub completeness_through_checkpoint: Option<bool>,
    pub unknown_tail_freshness: bool,
    pub records: u64,
    pub terminal_denied: u64,
    pub terminal_outcomes: u64,
    pub terminal_recoveries: u64,
}

#[derive(Clone, Copy)]
enum Lifecycle {
    Received,
    Allowed,
    DeniedDecision,
    Unknown([u8; 16]),
}

pub fn verify_stream<'a, I>(
    records: I,
    trust: &StreamTrust,
) -> Result<VerificationReport, WitnessError>
where
    I: IntoIterator<Item = &'a [u8]>,
{
    let mut expected_sequence = None;
    let mut previous_hash = [0_u8; 32];
    let mut lifecycles = HashMap::<[u8; 16], Lifecycle>::new();
    let mut event_ids = HashSet::<[u8; 16]>::new();
    let mut request_ids = HashSet::<[u8; 16]>::new();
    let mut report = VerificationReport {
        integrity: true,
        lifecycle_consistent: true,
        completeness_through_checkpoint: None,
        unknown_tail_freshness: false,
        records: 0,
        terminal_denied: 0,
        terminal_outcomes: 0,
        terminal_recoveries: 0,
    };

    for bytes in records {
        let decoded = decode_record(bytes)?;
        if decoded.journal_id() != &trust.expected_journal_id {
            return Err(WitnessError::WrongJournal);
        }
        let record = decoded.record();
        let sequence = expected_sequence.unwrap_or(record.sequence);
        if record.sequence != sequence || !event_ids.insert(record.event_id) {
            return Err(WitnessError::SequenceGap);
        }
        if record.previous_hash != previous_hash {
            return Err(WitnessError::BrokenLink);
        }
        verify_fields(record)?;
        transition(record, &mut lifecycles, &mut request_ids, &mut report)?;
        if lifecycles.len() > MAX_OPEN_REQUESTS {
            return Err(WitnessError::TooManyOpenRequests);
        }
        previous_hash = hash_record(trust.expected_journal_id, decoded.bytes().as_ref());
        expected_sequence = Some(sequence.checked_add(1).ok_or(WitnessError::SequenceGap)?);
        report.records += 1;
    }

    if !lifecycles.is_empty() {
        return Err(WitnessError::InvalidLifecycle);
    }
    Ok(report)
}

fn verify_fields(record: &WitnessRecord) -> Result<(), WitnessError> {
    let valid = match record.stage {
        WitnessStage::RequestReceived => {
            record.decision.is_none() && record.outcome == WitnessOutcome::None
        }
        WitnessStage::Decision => {
            record.decision.is_some() && record.outcome == WitnessOutcome::None
        }
        WitnessStage::Denied => {
            record.decision.is_none() && record.outcome == WitnessOutcome::Denied
        }
        WitnessStage::Outcome => {
            record.decision.is_none()
                && matches!(
                    record.outcome,
                    WitnessOutcome::Succeeded
                        | WitnessOutcome::Failed
                        | WitnessOutcome::OutcomeUnknown
                )
        }
        WitnessStage::Recovery => {
            record.decision.is_none()
                && matches!(
                    record.outcome,
                    WitnessOutcome::Recovered | WitnessOutcome::Quarantined
                )
                && record.recovery_link.is_some()
        }
    };
    if valid {
        Ok(())
    } else {
        Err(WitnessError::InvalidLifecycle)
    }
}

fn transition(
    record: &WitnessRecord,
    states: &mut HashMap<[u8; 16], Lifecycle>,
    request_ids: &mut HashSet<[u8; 16]>,
    report: &mut VerificationReport,
) -> Result<(), WitnessError> {
    match record.stage {
        WitnessStage::RequestReceived => {
            if !request_ids.insert(record.request_id)
                || states
                    .insert(record.request_id, Lifecycle::Received)
                    .is_some()
            {
                return Err(WitnessError::InvalidLifecycle);
            }
        }
        WitnessStage::Decision => match states.get_mut(&record.request_id) {
            Some(state @ Lifecycle::Received) => {
                *state = if record.decision == Some(true) {
                    Lifecycle::Allowed
                } else {
                    Lifecycle::DeniedDecision
                };
            }
            _ => return Err(WitnessError::InvalidLifecycle),
        },
        WitnessStage::Denied => match states.remove(&record.request_id) {
            Some(Lifecycle::DeniedDecision) => report.terminal_denied += 1,
            _ => return Err(WitnessError::InvalidLifecycle),
        },
        WitnessStage::Outcome => match states.get(&record.request_id).copied() {
            Some(Lifecycle::Allowed) if record.outcome == WitnessOutcome::OutcomeUnknown => {
                states.insert(record.request_id, Lifecycle::Unknown(record.event_id));
            }
            Some(Lifecycle::Allowed) => {
                states.remove(&record.request_id);
                report.terminal_outcomes += 1;
            }
            _ => return Err(WitnessError::InvalidLifecycle),
        },
        WitnessStage::Recovery => match states.remove(&record.request_id) {
            Some(Lifecycle::Unknown(event_id)) if record.recovery_link == Some(event_id) => {
                report.terminal_recoveries += 1;
            }
            _ => return Err(WitnessError::InvalidLifecycle),
        },
    }
    Ok(())
}
