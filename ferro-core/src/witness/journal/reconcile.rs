use super::{
    state::{OperationState, ALLOWED, COMPLETE, UNKNOWN},
    FlushBoundary, JournalError, WitnessJournal, HEAD_HASH, HEAD_SEQUENCE, RESERVE,
};
use crate::witness::{encode_record, hash_record, OperationId, WitnessRecord, WitnessStage};
use crate::witness::{
    DisclosureClass, Invocation, ObservationDigest, PrincipalSummary, ReasonCode, RecoveryEvidence,
    RecoveryRecipe, ResourceSummary, WitnessAction, WitnessOutcome, WitnessResourceKind,
};
use sha2::{Digest, Sha256};
use std::sync::atomic::Ordering;

impl WitnessJournal {
    /// Classify a pending mutation from a disclosure-safe observation without
    /// ever replaying the original external action.
    pub(crate) fn reconcile_observed(
        &self,
        evidence: RecoveryEvidence,
    ) -> Result<(), JournalError> {
        let id = evidence.operation_id;
        let observation = evidence.observation_digest;
        let pending = self.pending.get(id.0)?.ok_or(JournalError::NotPending)?;
        let (execution_generation, recipe) =
            RecoveryRecipe::decode(&pending).ok_or(JournalError::Corrupt)?;
        if execution_generation != evidence.execution_generation
            || recipe.original_action() != evidence.original_action
            || recipe.resource_kind() != evidence.resource_kind
            || recipe.resource_generation() != evidence.resource_generation
            || recipe.truth_strategy() != evidence.truth_strategy
            || recipe.observation_handle() != &evidence.observation_handle
        {
            return Err(JournalError::BindingMismatch);
        }
        let state_bytes = self.operations.get(id.0)?.ok_or(JournalError::NotPending)?;
        let state = OperationState::decode(&state_bytes).ok_or(JournalError::Corrupt)?;
        let unknown_event_id = match state.state {
            ALLOWED => {
                let event_id = reconciliation_event_id(id, &observation, b"unknown");
                let mut unknown = record_from_state(&state, WitnessStage::Outcome, event_id)?;
                unknown.result_digest = Some(*observation.as_bytes());
                unknown.reason = Some(ReasonCode::ExecutionFailed);
                unknown.outcome = WitnessOutcome::OutcomeUnknown;
                self.record_outcome_unknown(id, unknown)?;
                event_id
            }
            UNKNOWN => state.unknown_event_id,
            COMPLETE => return Err(JournalError::AlreadyComplete),
            _ => return Err(JournalError::BindingMismatch),
        };

        let label: &[u8] = if evidence.recovered {
            b"recovered"
        } else {
            b"quarantined"
        };
        let mut recovery = record_from_state(
            &state,
            WitnessStage::Recovery,
            reconciliation_event_id(id, &observation, label),
        )?;
        recovery.result_digest = Some(*observation.as_bytes());
        recovery.recovery_link = Some(unknown_event_id);
        if evidence.recovered {
            recovery.reason = Some(ReasonCode::RecoveryCompleted);
            recovery.outcome = WitnessOutcome::Recovered;
        } else {
            recovery.reason = Some(ReasonCode::Quarantined);
            recovery.outcome = WitnessOutcome::Quarantined;
        }
        self.complete_recovery(id, recovery)
    }

    /// Record that an already-authorized execution generation may have changed
    /// external state after its terminal receipt could not be proven durable.
    /// This grants no authority to repeat the external action.
    pub fn record_outcome_unknown(
        &self,
        id: OperationId,
        mut record: WitnessRecord,
    ) -> Result<(), JournalError> {
        record.epoch = self.epoch.load(Ordering::Acquire);
        if record.stage != WitnessStage::Outcome
            || record.outcome != crate::witness::WitnessOutcome::OutcomeUnknown
        {
            return Err(JournalError::InvalidStage);
        }
        let _guard = self.coordinator.lock().map_err(|_| JournalError::Corrupt)?;
        self.preflight(FlushBoundary::Outcome)?;
        let mut state =
            OperationState::decode(&self.operations.get(id.0)?.ok_or(JournalError::NotPending)?)
                .ok_or(JournalError::Corrupt)?;
        if state.state == COMPLETE {
            self.flush(FlushBoundary::Outcome, id)?;
            return Err(JournalError::AlreadyComplete);
        }
        if state.state != ALLOWED || !state.terminal_matches(&record) {
            return Err(JournalError::BindingMismatch);
        }
        let (sequence, previous) = self.head()?;
        record.sequence = sequence + 1;
        record.previous_hash = previous;
        let bytes = encode_record(self.journal_id, &record)?;
        self.ensure_user_capacity(bytes.as_ref().len() as u64)?;
        let next_hash = hash_record(&bytes);
        let seq_key = record.sequence.to_be_bytes();
        let expected_head = sequence.to_be_bytes();
        state.state = UNKNOWN;
        state.unknown_event_id = record.event_id;
        state.pending_generation += 1;
        let state = state.encode();
        self.db.transaction(|transaction| {
            if transaction.get(self.meta.name(), HEAD_SEQUENCE)?.as_deref()
                != Some(expected_head.as_slice())
            {
                return Err(JournalError::Corrupt);
            }
            if transaction
                .get(self.events.name(), &record.event_id)?
                .is_some()
            {
                return Err(JournalError::DuplicateEvent);
            }
            transaction.put(self.records.name(), &seq_key, bytes.as_ref())?;
            transaction.put(self.events.name(), &record.event_id, &seq_key)?;
            transaction.put(self.operations.name(), &id.0, state.as_slice())?;
            transaction.put(self.meta.name(), HEAD_SEQUENCE, &seq_key)?;
            transaction.put(self.meta.name(), HEAD_HASH, &next_hash)?;
            Ok(())
        })?;
        self.flush(FlushBoundary::Outcome, id)?;
        crate::observability::authorization_metrics().record(
            crate::observability::AuthorizationMetric::Recovery(
                crate::observability::RecoveryMetric::OutcomeUnknown,
            ),
        );
        self.post_ack_rotation();
        Ok(())
    }

    pub fn complete_recovery(
        &self,
        id: OperationId,
        mut record: WitnessRecord,
    ) -> Result<(), JournalError> {
        record.epoch = self.epoch.load(Ordering::Acquire);
        if self.automation_stopped.load(Ordering::Acquire) {
            return Err(JournalError::AutomationStopped);
        }
        if record.stage != WitnessStage::Recovery {
            return Err(JournalError::InvalidStage);
        }
        let _guard = self.coordinator.lock().map_err(|_| JournalError::Corrupt)?;
        let state =
            OperationState::decode(&self.operations.get(id.0)?.ok_or(JournalError::NotPending)?)
                .ok_or(JournalError::Corrupt)?;
        if state.state != UNKNOWN
            || !state.terminal_matches(&record)
            || record.recovery_link != Some(state.unknown_event_id)
        {
            return Err(JournalError::BindingMismatch);
        }
        let (sequence, previous) = self.head()?;
        record.sequence = sequence + 1;
        record.previous_hash = previous;
        let bytes = encode_record(self.journal_id, &record)?;
        if self.events.contains_key(record.event_id)? {
            return Err(JournalError::DuplicateEvent);
        }
        let reserve_after = self.begin_cleanup_reservation(id, bytes.as_ref().len() as u64)?;
        if self
            .faults
            .take(super::FaultPoint::BeforeTransaction(FlushBoundary::Outcome))
            || self
                .faults
                .take(super::FaultPoint::Transaction(FlushBoundary::Outcome))
        {
            self.stop_automation();
            return Err(JournalError::AutomationStopped);
        }
        let next_hash = hash_record(&bytes);
        let seq_key = record.sequence.to_be_bytes();
        let expected_head = sequence.to_be_bytes();
        let mut terminal = state;
        terminal.state = COMPLETE;
        terminal.pending_generation += 1;
        let terminal = terminal.encode();
        self.db.transaction(|transaction| {
            if transaction.get(self.meta.name(), HEAD_SEQUENCE)?.as_deref()
                != Some(expected_head.as_slice())
            {
                return Err(JournalError::Corrupt);
            }
            if transaction
                .get(self.events.name(), &record.event_id)?
                .is_some()
            {
                return Err(JournalError::DuplicateEvent);
            }
            transaction.put(self.records.name(), &seq_key, bytes.as_ref())?;
            transaction.put(self.events.name(), &record.event_id, &seq_key)?;
            transaction.put(self.operations.name(), &id.0, terminal.as_slice())?;
            transaction.remove(self.pending.name(), &id.0)?;
            transaction.put(self.meta.name(), HEAD_SEQUENCE, &seq_key)?;
            transaction.put(self.meta.name(), HEAD_HASH, &next_hash)?;
            transaction.put(self.meta.name(), RESERVE, &reserve_after.to_be_bytes())?;
            Ok(())
        })?;
        if self.flush(FlushBoundary::Outcome, id).is_err() {
            self.stop_automation();
            return Err(JournalError::AutomationStopped);
        }
        self.finish_cleanup_reservation(reserve_after)?;
        crate::observability::authorization_metrics().record(
            crate::observability::AuthorizationMetric::Recovery(
                crate::observability::RecoveryMetric::Recovered,
            ),
        );
        self.post_ack_rotation();
        Ok(())
    }
}

fn reconciliation_event_id(
    id: OperationId,
    observation: &ObservationDigest,
    label: &[u8],
) -> [u8; 16] {
    let mut hash = Sha256::new();
    hash.update(b"FERROCRATE-RECONCILIATION-EVENT-V1");
    hash.update(id.as_bytes());
    hash.update(observation.as_bytes());
    hash.update((label.len() as u64).to_be_bytes());
    hash.update(label);
    let digest: [u8; 32] = hash.finalize().into();
    digest[..16].try_into().expect("fixed digest prefix")
}

fn record_from_state(
    state: &OperationState,
    stage: WitnessStage,
    event_id: [u8; 16],
) -> Result<WitnessRecord, JournalError> {
    Ok(WitnessRecord {
        epoch: 0,
        sequence: 0,
        previous_hash: [0; 32],
        event_id,
        request_id: state.request_id,
        runtime_instance_id: state.runtime_id,
        boot_id: state.boot_id,
        principal: PrincipalSummary(state.principal),
        invocation: invocation(state.invocation)?,
        action: action(state.action)?,
        resource_kind: resource_kind(state.resource_kind)?,
        resource: ResourceSummary(state.resource),
        resource_generation: state.resource_generation,
        policy_version: state.policy_version,
        policy_digest: state.policy_digest,
        decision_id: Some(state.decision_id),
        rule: None,
        decision: None,
        reason: None,
        request_digest: state.request_digest,
        result_digest: None,
        wall_time_ns: 0,
        monotonic_ns: 0,
        stage,
        outcome: WitnessOutcome::None,
        recovery_link: None,
        path_class: disclosure(state.path_class)?,
        device_class: disclosure(state.device_class)?,
        correlation_digest: state.correlation_digest,
    })
}

fn invocation(value: u8) -> Result<Invocation, JournalError> {
    match value {
        1 => Ok(Invocation::Cli),
        2 => Ok(Invocation::DockerUnix),
        3 => Ok(Invocation::Compose),
        4 => Ok(Invocation::Cri),
        5 => Ok(Invocation::Manager),
        6 => Ok(Invocation::InternalCleanup),
        _ => Err(JournalError::Corrupt),
    }
}

fn action(value: u8) -> Result<WitnessAction, JournalError> {
    use WitnessAction::*;
    match value {
        1 => Ok(ContainerCreate),
        2 => Ok(ContainerRun),
        3 => Ok(ContainerExec),
        4 => Ok(ContainerPause),
        5 => Ok(ContainerResume),
        6 => Ok(ContainerStop),
        7 => Ok(ContainerKill),
        8 => Ok(ContainerRestart),
        9 => Ok(ContainerDelete),
        10 => Ok(ImagePull),
        11 => Ok(ImageDelete),
        12 => Ok(VolumeCreate),
        13 => Ok(VolumeDelete),
        14 => Ok(VolumeMount),
        15 => Ok(VolumeUnmount),
        16 => Ok(NetworkCreate),
        17 => Ok(NetworkDelete),
        18 => Ok(NetworkAttach),
        19 => Ok(NetworkDetach),
        20 => Ok(DeviceUse),
        21 => Ok(PolicyReload),
        22 => Ok(PolicyRollback),
        23 => Ok(CheckpointPublish),
        24 => Ok(ImageBuild),
        25 => Ok(ImageTag),
        26 => Ok(ImageReferenceWrite),
        27 => Ok(CheckpointRecover),
        28 => Ok(KeyRotate),
        29 => Ok(RootlessMapping),
        30 => Ok(ContainerRename),
        33 => Ok(ContainerUpdate),
        _ => Err(JournalError::Corrupt),
    }
}

fn resource_kind(value: u8) -> Result<WitnessResourceKind, JournalError> {
    use WitnessResourceKind::*;
    match value {
        1 => Ok(Container),
        2 => Ok(Image),
        3 => Ok(Volume),
        4 => Ok(Network),
        5 => Ok(Device),
        6 => Ok(Policy),
        7 => Ok(Administrative),
        _ => Err(JournalError::Corrupt),
    }
}

fn disclosure(value: u8) -> Result<Option<DisclosureClass>, JournalError> {
    use DisclosureClass::*;
    match value {
        0 => Ok(None),
        1 => Ok(Some(RuntimeManaged)),
        2 => Ok(Some(ReadOnlyHost)),
        3 => Ok(Some(Ephemeral)),
        4 => Ok(Some(BlockDevice)),
        5 => Ok(Some(CharacterDevice)),
        6 => Ok(Some(Accelerator)),
        _ => Err(JournalError::Corrupt),
    }
}
