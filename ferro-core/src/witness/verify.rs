use std::collections::{HashMap, HashSet};

use super::{
    decode_record, hash_record, DisclosureClass, Invocation, ParsedRecord, WitnessAction,
    WitnessError, WitnessOutcome, WitnessResourceKind, WitnessStage,
};

const MAX_OPEN_REQUESTS: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamTrust {
    expected_journal_id: [u8; 16],
    expected_epoch: u64,
    expected_first_sequence: u64,
    expected_predecessor_hash: [u8; 32],
    max_records: u64,
}

impl StreamTrust {
    /// Pins the exact prefix boundary. Genesis is `(journal_id, 1, [0; 32])`;
    /// verification of a later segment requires its independently retained
    /// first sequence and predecessor hash.
    pub fn new(
        expected_journal_id: [u8; 16],
        expected_epoch: u64,
        expected_first_sequence: u64,
        expected_predecessor_hash: [u8; 32],
    ) -> Self {
        Self {
            expected_journal_id,
            expected_epoch,
            expected_first_sequence,
            expected_predecessor_hash,
            max_records: 1_000_000,
        }
    }
    /// Bounds duplicate-ID tracking memory. Verify larger retained ranges in
    /// independently anchored chunks no larger than this limit.
    pub fn with_max_records(mut self, max_records: u64) -> Self {
        self.max_records = max_records;
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationReport {
    pub integrity: bool,
    pub lifecycle_consistent: bool,
    pub completeness_through_checkpoint: Option<bool>,
    pub tail_freshness: super::Freshness,
    pub checkpoint_age: Option<super::CheckpointAge>,
    pub records: u64,
    pub terminal_denied: u64,
    pub terminal_outcomes: u64,
    pub terminal_recoveries: u64,
    pub discontinuities: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RequestBinding {
    runtime_instance_id: [u8; 16],
    boot_id: [u8; 16],
    principal_digest: [u8; 32],
    invocation: Invocation,
    action: WitnessAction,
    resource_kind: WitnessResourceKind,
    resource_digest: [u8; 32],
    resource_generation: u64,
    policy_version: u64,
    policy_digest: [u8; 32],
    request_digest: [u8; 32],
    path_class: Option<DisclosureClass>,
    device_class: Option<DisclosureClass>,
    correlation_digest: Option<[u8; 32]>,
}

impl From<&ParsedRecord> for RequestBinding {
    fn from(record: &ParsedRecord) -> Self {
        Self {
            runtime_instance_id: record.runtime_instance_id,
            boot_id: record.boot_id,
            principal_digest: record.principal_digest,
            invocation: record.invocation,
            action: record.action,
            resource_kind: record.resource_kind,
            resource_digest: record.resource_digest,
            resource_generation: record.resource_generation,
            policy_version: record.policy_version,
            policy_digest: record.policy_digest,
            request_digest: record.request_digest,
            path_class: record.path_class,
            device_class: record.device_class,
            correlation_digest: record.correlation_digest,
        }
    }
}

#[derive(Clone)]
enum Lifecycle {
    Received(RequestBinding),
    Allowed(RequestBinding, [u8; 16]),
    DeniedDecision(RequestBinding, [u8; 16]),
    Unknown(RequestBinding, [u8; 16], [u8; 16]),
}

pub fn verify_stream<'a, I>(
    records: I,
    trust: &StreamTrust,
) -> Result<VerificationReport, WitnessError>
where
    I: IntoIterator<Item = &'a [u8]>,
{
    let mut verifier = StreamVerifier::new(trust.clone());
    for bytes in records {
        verifier.push(bytes)?;
    }
    verifier.finish()
}

pub(super) struct StreamVerifier {
    trust: StreamTrust,
    expected_sequence: u64,
    previous_hash: [u8; 32],
    lifecycles: HashMap<[u8; 16], Lifecycle>,
    event_ids: HashSet<[u8; 16]>,
    request_ids: HashSet<[u8; 16]>,
    report: VerificationReport,
}

impl StreamVerifier {
    pub(super) fn new(trust: StreamTrust) -> Self {
        Self {
            expected_sequence: trust.expected_first_sequence,
            previous_hash: trust.expected_predecessor_hash,
            trust,
            lifecycles: HashMap::new(),
            event_ids: HashSet::new(),
            request_ids: HashSet::new(),
            report: VerificationReport {
                integrity: true,
                lifecycle_consistent: true,
                completeness_through_checkpoint: None,
                tail_freshness: super::Freshness::UnknownTail,
                checkpoint_age: None,
                records: 0,
                terminal_denied: 0,
                terminal_outcomes: 0,
                terminal_recoveries: 0,
                discontinuities: 0,
            },
        }
    }

    pub(super) fn advance_epoch(&mut self, epoch: u64) -> Result<(), WitnessError> {
        if !self.lifecycles.is_empty()
            || epoch
                != self
                    .trust
                    .expected_epoch
                    .checked_add(1)
                    .ok_or(WitnessError::WrongEpoch)?
        {
            return Err(WitnessError::WrongEpoch);
        }
        self.trust.expected_epoch = epoch;
        self.report.discontinuities += 1;
        Ok(())
    }

    pub(super) fn push(&mut self, bytes: &[u8]) -> Result<(), WitnessError> {
        if self.report.records >= self.trust.max_records {
            return Err(WitnessError::TooManyRecords);
        }
        let decoded = decode_record(bytes)?;
        if decoded.journal_id() != &self.trust.expected_journal_id {
            return Err(WitnessError::WrongJournal);
        }
        let record = decoded.record();
        if record.epoch != self.trust.expected_epoch {
            return Err(WitnessError::WrongEpoch);
        }
        if record.sequence != self.expected_sequence || !self.event_ids.insert(record.event_id) {
            return Err(WitnessError::SequenceGap);
        }
        if record.previous_hash != self.previous_hash {
            return Err(WitnessError::BrokenLink);
        }
        super::validation::validate_record(record)?;
        transition(
            record,
            &mut self.lifecycles,
            &mut self.request_ids,
            &mut self.report,
        )?;
        if self.lifecycles.len() > MAX_OPEN_REQUESTS {
            return Err(WitnessError::TooManyOpenRequests);
        }
        self.previous_hash = hash_record(decoded.bytes());
        self.expected_sequence = self
            .expected_sequence
            .checked_add(1)
            .ok_or(WitnessError::SequenceGap)?;
        self.report.records += 1;
        Ok(())
    }
    pub(super) fn finish(self) -> Result<VerificationReport, WitnessError> {
        if !self.lifecycles.is_empty() {
            return Err(WitnessError::InvalidLifecycle);
        }
        Ok(self.report)
    }
}

fn same_binding(record: &ParsedRecord, binding: &RequestBinding) -> bool {
    &RequestBinding::from(record) == binding
}

fn transition(
    record: &ParsedRecord,
    states: &mut HashMap<[u8; 16], Lifecycle>,
    request_ids: &mut HashSet<[u8; 16]>,
    report: &mut VerificationReport,
) -> Result<(), WitnessError> {
    match record.stage {
        WitnessStage::RequestReceived => {
            if !request_ids.insert(record.request_id)
                || states
                    .insert(record.request_id, Lifecycle::Received(record.into()))
                    .is_some()
            {
                return Err(WitnessError::InvalidLifecycle);
            }
        }
        WitnessStage::Decision => match states.remove(&record.request_id) {
            Some(Lifecycle::Received(binding)) if same_binding(record, &binding) => {
                let decision_id = record.decision_id.ok_or(WitnessError::InvalidLifecycle)?;
                let next = if record.decision == Some(true) {
                    Lifecycle::Allowed(binding, decision_id)
                } else {
                    Lifecycle::DeniedDecision(binding, decision_id)
                };
                states.insert(record.request_id, next);
            }
            _ => return Err(WitnessError::InvalidLifecycle),
        },
        WitnessStage::Denied => match states.remove(&record.request_id) {
            Some(Lifecycle::DeniedDecision(binding, decision_id))
                if same_binding(record, &binding) && record.decision_id == Some(decision_id) =>
            {
                report.terminal_denied += 1;
            }
            _ => return Err(WitnessError::InvalidLifecycle),
        },
        WitnessStage::Outcome => match states.remove(&record.request_id) {
            Some(Lifecycle::Allowed(binding, decision_id))
                if same_binding(record, &binding) && record.decision_id == Some(decision_id) =>
            {
                if record.outcome == WitnessOutcome::OutcomeUnknown {
                    states.insert(
                        record.request_id,
                        Lifecycle::Unknown(binding, decision_id, record.event_id),
                    );
                } else {
                    report.terminal_outcomes += 1;
                }
            }
            _ => return Err(WitnessError::InvalidLifecycle),
        },
        WitnessStage::Recovery => match states.remove(&record.request_id) {
            Some(Lifecycle::Unknown(binding, decision_id, event_id))
                if same_binding(record, &binding)
                    && record.decision_id == Some(decision_id)
                    && record.recovery_link == Some(event_id) =>
            {
                report.terminal_recoveries += 1
            }
            _ => return Err(WitnessError::InvalidLifecycle),
        },
        WitnessStage::CheckpointPublished => {}
    }
    Ok(())
}
