use ferro_core::witness::{
    verify_stream, DisclosureClass, DurableIntent, FaultPoint, FlushBoundary, Invocation,
    JournalConfig, JournalError, JournalFaults, JournalMode, ObservationDigest, ObservationHandle,
    OperationId, PrincipalSummary, RecoveryRecipe, RecoveryTruthStrategy, ResourceSummary,
    RuleSummary, StreamTrust, WitnessAction, WitnessJournal, WitnessOutcome, WitnessRecord,
    WitnessResourceKind, WitnessStage,
};
use std::sync::{Arc, Barrier};
use tempfile::tempdir;

fn record(stage: WitnessStage) -> WitnessRecord {
    let event = match stage {
        WitnessStage::RequestReceived => 3,
        WitnessStage::Decision => 4,
        WitnessStage::Denied => 5,
        WitnessStage::Outcome => 6,
        WitnessStage::Recovery => 7,
        WitnessStage::CheckpointPublished => 8,
    };
    WitnessRecord {
        epoch: 1,
        sequence: 0,
        previous_hash: [0; 32],
        event_id: [event; 16],
        request_id: [4; 16],
        runtime_instance_id: [5; 16],
        boot_id: [6; 16],
        principal: PrincipalSummary::pseudonymize(&[1; 32], b"uid:1000").unwrap(),
        invocation: Invocation::Cli,
        action: WitnessAction::ContainerCreate,
        resource_kind: WitnessResourceKind::Container,
        resource: ResourceSummary::pseudonymize(&[2; 32], b"container:1").unwrap(),
        resource_generation: 1,
        policy_version: 1,
        policy_digest: [7; 32],
        decision_id: None,
        rule: None,
        decision: None,
        reason: None,
        request_digest: [8; 32],
        result_digest: None,
        wall_time_ns: 1,
        monotonic_ns: 1,
        stage,
        outcome: WitnessOutcome::None,
        recovery_link: None,
        path_class: None,
        device_class: None,
        correlation_digest: None,
    }
}

#[test]
fn restart_reconciles_allowed_observation_through_unknown_and_recovery() {
    let root = tempdir().unwrap();
    let id = OperationId::from_bytes([91; 16]);
    {
        let journal = WitnessJournal::open(config(root.path())).unwrap();
        allow(&journal, id, 91);
    }

    let journal = WitnessJournal::open(config(root.path())).unwrap();
    let evidence = journal
        .recover(id)
        .unwrap()
        .observe_container_absent(ObservationDigest::from_bytes([77; 32]), true)
        .unwrap();
    journal.reconcile_observed(evidence).unwrap();
    let records = journal.records().unwrap();
    let decoded: Vec<_> = records
        .iter()
        .map(|bytes| ferro_core::witness::decode_record(bytes).unwrap())
        .collect();
    let unknown = &decoded[2];
    let recovery = &decoded[3];
    assert_eq!(unknown.stage(), WitnessStage::Outcome);
    assert_eq!(recovery.stage(), WitnessStage::Recovery);
    assert!(
        verify_stream(
            records.iter().map(Vec::as_slice),
            &StreamTrust::new([9; 16], 1, 1, [0; 32])
        )
        .unwrap()
        .lifecycle_consistent
    );
    assert!(journal.pending().unwrap().is_empty());
}

#[test]
fn restart_reconciles_existing_unknown_without_appending_another_unknown() {
    let root = tempdir().unwrap();
    let id = OperationId::from_bytes([92; 16]);
    {
        let journal = WitnessJournal::open(config(root.path())).unwrap();
        let intent = allow(&journal, id, 92);
        journal
            .complete(intent, outcome(92, WitnessOutcome::OutcomeUnknown))
            .unwrap();
    }

    let journal = WitnessJournal::open(config(root.path())).unwrap();
    let evidence = journal
        .recover(id)
        .unwrap()
        .observe_container_absent(ObservationDigest::from_bytes([8; 32]), false)
        .unwrap();
    journal.reconcile_observed(evidence).unwrap();
    let records = journal.records().unwrap();
    let decoded: Vec<_> = records
        .iter()
        .map(|bytes| ferro_core::witness::decode_record(bytes).unwrap())
        .collect();
    assert_eq!(decoded.len(), 4);
    assert_eq!(decoded[2].stage(), WitnessStage::Outcome);
    assert_eq!(decoded[3].stage(), WitnessStage::Recovery);
    assert!(journal.pending().unwrap().is_empty());
}

fn config(path: &std::path::Path) -> JournalConfig {
    JournalConfig::new(path, [9; 16], JournalMode::Required).cleanup_reserve_bytes(4096)
}

#[test]
fn rejects_v1_storage_instead_of_silently_opening_an_unreadable_journal() {
    let dir = tempdir().unwrap();
    let db = sled::open(dir.path().join("witness.sled")).unwrap();
    db.open_tree("witness-meta-v1")
        .unwrap()
        .insert(b"schema", b"v1")
        .unwrap();
    db.flush().unwrap();
    drop(db);
    assert!(matches!(
        WitnessJournal::open(config(dir.path())),
        Err(JournalError::UnsupportedVersion)
    ));
}

#[test]
fn checkpoint_publication_never_relabels_a_mismatched_epoch() {
    let dir = tempdir().unwrap();
    let journal = WitnessJournal::open(config(dir.path())).unwrap();
    let mut publication = record(WitnessStage::CheckpointPublished);
    publication.epoch = 2;
    publication.action = WitnessAction::CheckpointPublish;
    publication.outcome = WitnessOutcome::Succeeded;
    publication.result_digest = Some([8; 32]);
    assert!(matches!(
        journal.append_checkpoint_publication([8; 32], publication),
        Err(JournalError::ProofMismatch)
    ));
    assert!(journal.records().unwrap().is_empty());
}

fn recipe() -> RecoveryRecipe {
    RecoveryRecipe::for_original(
        WitnessAction::ContainerCreate,
        WitnessResourceKind::Container,
        WitnessAction::ContainerDelete,
        [8; 32],
        1,
    )
    .unwrap()
}

#[test]
fn recovery_recipe_persists_action_specific_truth_without_disclosing_observations() {
    let recipe = RecoveryRecipe::for_original_with_observation(
        WitnessAction::ContainerExec,
        WitnessResourceKind::Container,
        WitnessAction::ContainerDelete,
        [8; 32],
        1,
        RecoveryTruthStrategy::ExecutionObserved,
        ObservationDigest::from_bytes([9; 32]),
        ObservationHandle::from_bytes([10; 16]),
    )
    .unwrap();

    let dir = tempdir().unwrap();
    let id = OperationId::from_bytes([33; 16]);
    {
        let journal = WitnessJournal::open(config(dir.path())).unwrap();
        let mut received = record(WitnessStage::RequestReceived);
        received.action = WitnessAction::ContainerExec;
        journal.append_received(id, 7, recipe, received).unwrap();
    }
    let journal = WitnessJournal::open(config(dir.path())).unwrap();
    let pending = journal.pending().unwrap();
    let recipe = pending[0].recipe();

    assert_eq!(
        recipe.truth_strategy(),
        RecoveryTruthStrategy::ExecutionObserved
    );
    assert_eq!(recipe.observation_digest().as_bytes(), &[9; 32]);
    assert_eq!(recipe.observation_handle().as_bytes(), &[10; 16]);
    assert!(matches!(
        pending[0].observe_container_absent(ObservationDigest::from_bytes([11; 32]), true),
        Err(ferro_core::witness::RecoveryRecipeError::InvalidTruthStrategy)
    ));
    assert!(matches!(
        RecoveryRecipe::for_original_with_observation(
            WitnessAction::ContainerExec,
            WitnessResourceKind::Container,
            WitnessAction::ContainerDelete,
            [8; 32],
            1,
            RecoveryTruthStrategy::ContainerAbsent,
            ObservationDigest::from_bytes([9; 32]),
            ObservationHandle::from_bytes([10; 16]),
        ),
        Err(ferro_core::witness::RecoveryRecipeError::InvalidTruthStrategy)
    ));
}

fn allow(journal: &WitnessJournal, id: OperationId, byte: u8) -> DurableIntent {
    journal
        .append_received(id, 1, recipe(), record(WitnessStage::RequestReceived))
        .unwrap();
    let mut decision = record(WitnessStage::Decision);
    decision.event_id = [byte.wrapping_add(1); 16];
    decision.decision_id = Some([byte; 16]);
    decision.rule = Some(RuleSummary::from_id([1; 16]));
    decision.decision = Some(true);
    journal.append_decision(id, decision).unwrap()
}

fn outcome(byte: u8, value: WitnessOutcome) -> WitnessRecord {
    let mut outcome = record(WitnessStage::Outcome);
    outcome.event_id = [byte.wrapping_add(2); 16];
    outcome.decision_id = Some([byte; 16]);
    outcome.result_digest = Some([byte; 32]);
    outcome.outcome = value;
    if value == WitnessOutcome::OutcomeUnknown {
        outcome.reason = Some(ferro_core::witness::ReasonCode::ExecutionFailed);
    }
    outcome
}

#[test]
fn lock_is_exclusive_and_tied_to_journal_identity() {
    let root = tempdir().unwrap();
    let journal = WitnessJournal::open(config(root.path())).unwrap();
    assert!(matches!(
        WitnessJournal::open(config(root.path())),
        Err(JournalError::Locked)
    ));
    drop(journal);
    let other = JournalConfig::new(root.path(), [10; 16], JournalMode::Required);
    assert!(matches!(
        WitnessJournal::open(other),
        Err(JournalError::JournalMismatch)
    ));
    WitnessJournal::open(config(root.path())).unwrap();
}

#[test]
fn disabled_mode_never_mints_or_appends_durable_intent() {
    let root = tempdir().unwrap();
    let journal = WitnessJournal::open(JournalConfig::new(
        root.path(),
        [9; 16],
        JournalMode::Disabled,
    ))
    .unwrap();
    assert!(matches!(
        journal.append_received(
            OperationId::from_bytes([111; 16]),
            1,
            recipe(),
            record(WitnessStage::RequestReceived)
        ),
        Err(JournalError::Disabled)
    ));
    assert!(journal.records().unwrap().is_empty());
}

#[test]
fn durable_intents_are_serialized_idempotent_and_survive_restart() {
    let root = tempdir().unwrap();
    let journal = Arc::new(WitnessJournal::open(config(root.path())).unwrap());
    let barrier = Arc::new(Barrier::new(3));
    let mut threads = Vec::new();
    for byte in [1, 2] {
        let journal = Arc::clone(&journal);
        let barrier = Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            let id = OperationId::from_bytes([byte; 16]);
            let mut received = record(WitnessStage::RequestReceived);
            received.event_id = [byte; 16];
            journal.append_received(id, 1, recipe(), received).unwrap();
            let mut decision = record(WitnessStage::Decision);
            decision.event_id = [byte + 10; 16];
            decision.decision_id = Some([byte; 16]);
            decision.rule = Some(RuleSummary::from_id([1; 16]));
            decision.decision = Some(true);
            journal
                .append_decision(id, decision)
                .unwrap()
                .operation_id()
        }));
    }
    barrier.wait();
    let ids: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_ne!(ids[0], ids[1]);
    assert_eq!(journal.pending().unwrap().len(), 2);
    let duplicate =
        journal.append_received(ids[0], 1, recipe(), record(WitnessStage::RequestReceived));
    assert!(matches!(duplicate, Err(JournalError::DuplicateOperation)));
    drop(journal);
    assert_eq!(
        WitnessJournal::open(config(root.path()))
            .unwrap()
            .pending()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn flush_ambiguity_is_indeterminate_and_requires_reread() {
    let root = tempdir().unwrap();
    let faults = JournalFaults::new();
    let journal = WitnessJournal::open_with_faults(config(root.path()), faults.clone()).unwrap();
    let id = OperationId::from_bytes([3; 16]);
    journal
        .append_received(id, 7, recipe(), record(WitnessStage::RequestReceived))
        .unwrap();
    faults.fail_enospc_once(FaultPoint::AfterFlush(FlushBoundary::Decision));
    let mut decision = record(WitnessStage::Decision);
    decision.decision_id = Some([3; 16]);
    decision.rule = Some(RuleSummary::from_id([1; 16]));
    decision.decision = Some(true);
    assert!(
        matches!(journal.append_decision(id, decision), Err(JournalError::Indeterminate { operation_id }) if operation_id == id)
    );
    assert_eq!(journal.recover(id).unwrap().execution_generation(), 7);
}

#[test]
fn outcome_and_pending_removal_are_atomic_and_recovery_is_not_replay() {
    let root = tempdir().unwrap();
    let faults = JournalFaults::new();
    let journal = WitnessJournal::open_with_faults(config(root.path()), faults.clone()).unwrap();
    let id = OperationId::from_bytes([4; 16]);
    journal
        .append_received(id, 2, recipe(), record(WitnessStage::RequestReceived))
        .unwrap();
    let mut decision = record(WitnessStage::Decision);
    decision.decision_id = Some([4; 16]);
    decision.rule = Some(RuleSummary::from_id([1; 16]));
    decision.decision = Some(true);
    let intent = journal.append_decision(id, decision).unwrap();
    faults.fail_enospc_once(FaultPoint::AfterFlush(FlushBoundary::Outcome));
    let mut outcome = record(WitnessStage::Outcome);
    outcome.decision_id = Some([4; 16]);
    outcome.result_digest = Some([1; 32]);
    outcome.outcome = WitnessOutcome::Succeeded;
    assert!(matches!(
        journal.complete(intent, outcome),
        Err(JournalError::Indeterminate { .. })
    ));
    assert!(journal.pending().unwrap().is_empty());
    assert!(matches!(
        journal.recover(id),
        Err(JournalError::AlreadyComplete)
    ));
    assert!(
        verify_stream(
            journal.records().unwrap().iter().map(Vec::as_slice),
            &StreamTrust::new([9; 16], 1, 1, [0; 32])
        )
        .unwrap()
        .lifecycle_consistent
    );
}

#[test]
fn cleanup_reserve_failure_stops_automation() {
    let root = tempdir().unwrap();
    let faults = JournalFaults::new();
    faults.fail_enospc_once(FaultPoint::AfterFlush(FlushBoundary::Reserve));
    assert!(matches!(
        WitnessJournal::open_with_faults(config(root.path()), faults),
        Err(JournalError::AutomationStopped)
    ));
}

#[test]
fn injected_fault_phases_distinguish_safe_previsibility_from_ambiguity() {
    let root = tempdir().unwrap();
    let faults = JournalFaults::new();
    let journal = WitnessJournal::open_with_faults(config(root.path()), faults.clone()).unwrap();
    faults.fail_enospc_once(FaultPoint::Transaction(FlushBoundary::Received));
    assert!(matches!(
        journal.append_received(
            OperationId::from_bytes([71; 16]),
            1,
            recipe(),
            record(WitnessStage::RequestReceived)
        ),
        Err(JournalError::UnavailableBeforeVisibility)
    ));
    assert!(journal.pending().unwrap().is_empty());
    faults.fail_enospc_once(FaultPoint::DuringFlush(FlushBoundary::Received));
    let id = OperationId::from_bytes([72; 16]);
    assert!(
        matches!(journal.append_received(id, 1, recipe(), record(WitnessStage::RequestReceived)), Err(JournalError::Indeterminate { operation_id }) if operation_id == id)
    );
    assert_eq!(journal.recover(id).unwrap().operation_id(), id);
}

#[test]
fn durable_intent_cannot_cross_journals_or_substitute_binding() {
    let first_root = tempdir().unwrap();
    let second_root = tempdir().unwrap();
    let first = WitnessJournal::open(config(first_root.path())).unwrap();
    let second = WitnessJournal::open(
        JournalConfig::new(second_root.path(), [10; 16], JournalMode::Required)
            .cleanup_reserve_bytes(4096),
    )
    .unwrap();
    let id = OperationId::from_bytes([31; 16]);
    first
        .append_received(id, 1, recipe(), record(WitnessStage::RequestReceived))
        .unwrap();
    let mut decision = record(WitnessStage::Decision);
    decision.decision_id = Some([31; 16]);
    decision.rule = Some(RuleSummary::from_id([1; 16]));
    decision.decision = Some(true);
    let intent = first.append_decision(id, decision).unwrap();
    let mut outcome = record(WitnessStage::Outcome);
    outcome.decision_id = Some([31; 16]);
    outcome.result_digest = Some([1; 32]);
    outcome.outcome = WitnessOutcome::Succeeded;
    assert!(matches!(
        second.complete(intent, outcome),
        Err(JournalError::ProofMismatch)
    ));

    let id = OperationId::from_bytes([32; 16]);
    let mut received = record(WitnessStage::RequestReceived);
    received.event_id = [32; 16];
    first.append_received(id, 1, recipe(), received).unwrap();
    let mut decision = record(WitnessStage::Decision);
    decision.event_id = [33; 16];
    decision.decision_id = Some([32; 16]);
    decision.rule = Some(RuleSummary::from_id([1; 16]));
    decision.decision = Some(true);
    let intent = first.append_decision(id, decision).unwrap();
    let mut substituted = record(WitnessStage::Outcome);
    substituted.decision_id = Some([99; 16]);
    substituted.result_digest = Some([1; 32]);
    substituted.outcome = WitnessOutcome::Succeeded;
    assert!(matches!(
        first.complete(intent, substituted),
        Err(JournalError::BindingMismatch)
    ));
    assert_eq!(first.pending().unwrap().len(), 2);
}

#[test]
fn complete_task4_request_binding_is_transition_invariant() {
    let root = tempdir().unwrap();
    let journal = WitnessJournal::open(config(root.path())).unwrap();
    let id = OperationId::from_bytes([81; 16]);
    let mut received = record(WitnessStage::RequestReceived);
    received.path_class = Some(DisclosureClass::RuntimeManaged);
    received.device_class = Some(DisclosureClass::BlockDevice);
    received.correlation_digest = Some([81; 32]);
    journal.append_received(id, 1, recipe(), received).unwrap();
    let mut exact = record(WitnessStage::Decision);
    exact.path_class = Some(DisclosureClass::RuntimeManaged);
    exact.device_class = Some(DisclosureClass::BlockDevice);
    exact.correlation_digest = Some([81; 32]);
    exact.decision_id = Some([81; 16]);
    exact.rule = Some(RuleSummary::from_id([1; 16]));
    exact.decision = Some(true);
    let mut substitutions = Vec::new();
    let mut changed = exact.clone();
    changed.path_class = Some(DisclosureClass::Ephemeral);
    substitutions.push(changed);
    let mut changed = exact.clone();
    changed.device_class = Some(DisclosureClass::CharacterDevice);
    substitutions.push(changed);
    let mut changed = exact.clone();
    changed.correlation_digest = Some([82; 32]);
    substitutions.push(changed);
    for changed in substitutions {
        assert!(matches!(
            journal.append_decision(id, changed),
            Err(JournalError::BindingMismatch)
        ));
    }
    let intent = journal.append_decision(id, exact).unwrap();
    let mut outcome = record(WitnessStage::Outcome);
    outcome.path_class = Some(DisclosureClass::RuntimeManaged);
    outcome.device_class = Some(DisclosureClass::BlockDevice);
    outcome.correlation_digest = Some([81; 32]);
    outcome.decision_id = Some([81; 16]);
    outcome.result_digest = Some([1; 32]);
    outcome.outcome = WitnessOutcome::Succeeded;
    journal.complete(intent, outcome).unwrap();
    assert!(
        verify_stream(
            journal.records().unwrap().iter().map(Vec::as_slice),
            &StreamTrust::new([9; 16], 1, 1, [0; 32])
        )
        .unwrap()
        .lifecycle_consistent
    );
}

#[test]
fn recovery_recipe_rejects_cross_resource_inverse() {
    assert!(RecoveryRecipe::for_original(
        WitnessAction::ContainerCreate,
        WitnessResourceKind::Container,
        WitnessAction::ImageDelete,
        [8; 32],
        1,
    )
    .is_err());
}

#[test]
fn denied_decision_is_terminal_and_never_issues_execution_proof() {
    let root = tempdir().unwrap();
    let journal = WitnessJournal::open(config(root.path())).unwrap();
    let id = OperationId::from_bytes([41; 16]);
    journal
        .append_received(id, 1, recipe(), record(WitnessStage::RequestReceived))
        .unwrap();
    let mut decision = record(WitnessStage::Decision);
    decision.decision_id = Some([41; 16]);
    decision.rule = Some(RuleSummary::from_id([1; 16]));
    decision.decision = Some(false);
    decision.reason = Some(ferro_core::witness::ReasonCode::PolicyDenied);
    let mut denied = record(WitnessStage::Denied);
    denied.decision_id = Some([41; 16]);
    denied.reason = Some(ferro_core::witness::ReasonCode::PolicyDenied);
    denied.outcome = WitnessOutcome::Denied;
    journal.deny(id, decision, denied).unwrap();
    assert!(journal.pending().unwrap().is_empty());
    assert!(matches!(
        journal.recover(id),
        Err(JournalError::AlreadyComplete)
    ));
    assert!(
        verify_stream(
            journal.records().unwrap().iter().map(Vec::as_slice),
            &StreamTrust::new([9; 16], 1, 1, [0; 32])
        )
        .unwrap()
        .lifecycle_consistent
    );
}

#[test]
fn outcome_unknown_remains_pending_until_linked_recovery() {
    let root = tempdir().unwrap();
    let journal = WitnessJournal::open(config(root.path())).unwrap();
    let id = OperationId::from_bytes([51; 16]);
    journal
        .append_received(id, 9, recipe(), record(WitnessStage::RequestReceived))
        .unwrap();
    let mut decision = record(WitnessStage::Decision);
    decision.decision_id = Some([51; 16]);
    decision.rule = Some(RuleSummary::from_id([1; 16]));
    decision.decision = Some(true);
    let intent = journal.append_decision(id, decision).unwrap();
    let mut unknown = record(WitnessStage::Outcome);
    unknown.event_id = [52; 16];
    unknown.decision_id = Some([51; 16]);
    unknown.result_digest = Some([2; 32]);
    unknown.reason = Some(ferro_core::witness::ReasonCode::ExecutionFailed);
    unknown.outcome = WitnessOutcome::OutcomeUnknown;
    journal.complete(intent, unknown).unwrap();
    assert_eq!(journal.recover(id).unwrap().execution_generation(), 9);
    let mut recovery = record(WitnessStage::Recovery);
    recovery.event_id = [53; 16];
    recovery.decision_id = Some([51; 16]);
    recovery.result_digest = Some([3; 32]);
    recovery.reason = Some(ferro_core::witness::ReasonCode::RecoveryCompleted);
    recovery.outcome = WitnessOutcome::Recovered;
    recovery.recovery_link = Some([52; 16]);
    journal.complete_recovery(id, recovery).unwrap();
    assert!(matches!(
        journal.recover(id),
        Err(JournalError::AlreadyComplete)
    ));
}

#[test]
fn terminal_flush_ambiguity_reopens_as_complete_or_linked_unknown() {
    let root = tempdir().unwrap();
    let faults = JournalFaults::new();
    let journal = WitnessJournal::open_with_faults(config(root.path()), faults.clone()).unwrap();
    let id = OperationId::from_bytes([91; 16]);
    journal
        .append_received(id, 1, recipe(), record(WitnessStage::RequestReceived))
        .unwrap();
    let mut decision = record(WitnessStage::Decision);
    decision.decision_id = Some([91; 16]);
    decision.rule = Some(RuleSummary::from_id([1; 16]));
    decision.decision = Some(true);
    let intent = journal.append_decision(id, decision).unwrap();
    faults.fail_once(FaultPoint::BeforeFlush(FlushBoundary::Outcome));
    let mut outcome = record(WitnessStage::Outcome);
    outcome.event_id = [92; 16];
    outcome.decision_id = Some([91; 16]);
    outcome.result_digest = Some([1; 32]);
    outcome.outcome = WitnessOutcome::Succeeded;
    assert!(matches!(
        journal.complete(intent, outcome),
        Err(JournalError::Indeterminate { .. })
    ));
    drop(journal);
    let journal = WitnessJournal::open(config(root.path())).unwrap();
    assert_eq!(journal.recover(id).unwrap().operation_id(), id);
    let mut recovery = record(WitnessStage::Recovery);
    recovery.event_id = [93; 16];
    recovery.decision_id = Some([91; 16]);
    recovery.result_digest = Some([2; 32]);
    recovery.reason = Some(ferro_core::witness::ReasonCode::RecoveryCompleted);
    recovery.outcome = WitnessOutcome::Recovered;
    recovery.recovery_link = Some([92; 16]);
    journal.complete_recovery(id, recovery).unwrap();
    assert!(
        verify_stream(
            journal.records().unwrap().iter().map(Vec::as_slice),
            &StreamTrust::new([9; 16], 1, 1, [0; 32])
        )
        .unwrap()
        .lifecycle_consistent
    );
}

#[test]
fn lost_visible_terminal_is_reconciled_without_consumed_proof_or_reexecution() {
    let root = tempdir().unwrap();
    let journal = WitnessJournal::open(config(root.path())).unwrap();
    let id = OperationId::from_bytes([131; 16]);
    journal
        .append_received(id, 44, recipe(), record(WitnessStage::RequestReceived))
        .unwrap();
    let mut decision = record(WitnessStage::Decision);
    decision.decision_id = Some([131; 16]);
    decision.rule = Some(RuleSummary::from_id([1; 16]));
    decision.decision = Some(true);
    {
        let consumed = journal.append_decision(id, decision).unwrap();
        assert_eq!(consumed.execution_generation(), 44);
    } // proof was consumed before an unacknowledged terminal write
    let mut unknown = record(WitnessStage::Outcome);
    unknown.event_id = [132; 16];
    unknown.decision_id = Some([131; 16]);
    unknown.result_digest = Some([1; 32]);
    unknown.reason = Some(ferro_core::witness::ReasonCode::ExecutionFailed);
    unknown.outcome = WitnessOutcome::OutcomeUnknown;
    journal.record_outcome_unknown(id, unknown).unwrap();
    assert_eq!(journal.recover(id).unwrap().execution_generation(), 44);
}

#[test]
fn visible_complete_requires_explicit_reack_before_classification() {
    let root = tempdir().unwrap();
    let faults = JournalFaults::new();
    let journal = WitnessJournal::open_with_faults(config(root.path()), faults.clone()).unwrap();
    let id = OperationId::from_bytes([151; 16]);
    journal
        .append_received(id, 1, recipe(), record(WitnessStage::RequestReceived))
        .unwrap();
    let mut decision = record(WitnessStage::Decision);
    decision.decision_id = Some([151; 16]);
    decision.rule = Some(RuleSummary::from_id([1; 16]));
    decision.decision = Some(true);
    let intent = journal.append_decision(id, decision).unwrap();
    faults.fail_enospc_once(FaultPoint::DuringFlush(FlushBoundary::Outcome));
    let mut outcome = record(WitnessStage::Outcome);
    outcome.event_id = [152; 16];
    outcome.decision_id = Some([151; 16]);
    outcome.result_digest = Some([1; 32]);
    outcome.outcome = WitnessOutcome::Succeeded;
    assert!(matches!(
        journal.complete(intent, outcome),
        Err(JournalError::Indeterminate { .. })
    ));
    let mut unknown = record(WitnessStage::Outcome);
    unknown.event_id = [153; 16];
    unknown.decision_id = Some([151; 16]);
    unknown.result_digest = Some([2; 32]);
    unknown.reason = Some(ferro_core::witness::ReasonCode::ExecutionFailed);
    unknown.outcome = WitnessOutcome::OutcomeUnknown;
    assert!(matches!(
        journal.record_outcome_unknown(id, unknown),
        Err(JournalError::AlreadyComplete)
    ));
    drop(journal); // explicit re-ack above makes this equivalent to hard termination
    let journal = WitnessJournal::open(config(root.path())).unwrap();
    assert!(matches!(
        journal.recover(id),
        Err(JournalError::AlreadyComplete)
    ));
}

#[test]
fn crash_after_cleanup_reservation_reopens_fail_stopped() {
    let root = tempdir().unwrap();
    let faults = JournalFaults::new();
    let journal = WitnessJournal::open_with_faults(config(root.path()), faults.clone()).unwrap();
    let id = OperationId::from_bytes([121; 16]);
    journal
        .append_received(id, 1, recipe(), record(WitnessStage::RequestReceived))
        .unwrap();
    let mut decision = record(WitnessStage::Decision);
    decision.decision_id = Some([121; 16]);
    decision.rule = Some(RuleSummary::from_id([1; 16]));
    decision.decision = Some(true);
    let intent = journal.append_decision(id, decision).unwrap();
    let mut unknown = record(WitnessStage::Outcome);
    unknown.event_id = [122; 16];
    unknown.decision_id = Some([121; 16]);
    unknown.result_digest = Some([1; 32]);
    unknown.reason = Some(ferro_core::witness::ReasonCode::ExecutionFailed);
    unknown.outcome = WitnessOutcome::OutcomeUnknown;
    journal.complete(intent, unknown).unwrap();
    faults.fail_enospc_once(FaultPoint::AfterFlush(FlushBoundary::Reserve));
    let mut recovery = record(WitnessStage::Recovery);
    recovery.event_id = [123; 16];
    recovery.decision_id = Some([121; 16]);
    recovery.result_digest = Some([2; 32]);
    recovery.reason = Some(ferro_core::witness::ReasonCode::RecoveryCompleted);
    recovery.outcome = WitnessOutcome::Recovered;
    recovery.recovery_link = Some([122; 16]);
    assert!(matches!(
        journal.complete_recovery(id, recovery),
        Err(JournalError::AutomationStopped)
    ));
    drop(journal);
    assert!(matches!(
        WitnessJournal::open(config(root.path())),
        Err(JournalError::AutomationStopped)
    ));
}

#[test]
fn quota_preserves_cleanup_reserve_and_exhaustion_stops_cleanup() {
    let quota_root = tempdir().unwrap();
    let quota = JournalConfig::new(quota_root.path(), [9; 16], JournalMode::Required)
        .cleanup_reserve_bytes(4096)
        .max_journal_bytes(4196);
    let journal = WitnessJournal::open(quota).unwrap();
    assert!(matches!(
        journal.append_received(
            OperationId::from_bytes([61; 16]),
            1,
            recipe(),
            record(WitnessStage::RequestReceived)
        ),
        Err(JournalError::QuotaExceeded)
    ));

    let cleanup_root = tempdir().unwrap();
    let cleanup = JournalConfig::new(cleanup_root.path(), [9; 16], JournalMode::Required)
        .cleanup_reserve_bytes(128);
    let journal = WitnessJournal::open(cleanup).unwrap();
    let id = OperationId::from_bytes([62; 16]);
    journal
        .append_received(id, 1, recipe(), record(WitnessStage::RequestReceived))
        .unwrap();
    let mut decision = record(WitnessStage::Decision);
    decision.decision_id = Some([62; 16]);
    decision.rule = Some(RuleSummary::from_id([1; 16]));
    decision.decision = Some(true);
    let intent = journal.append_decision(id, decision).unwrap();
    let mut unknown = record(WitnessStage::Outcome);
    unknown.event_id = [63; 16];
    unknown.decision_id = Some([62; 16]);
    unknown.result_digest = Some([2; 32]);
    unknown.reason = Some(ferro_core::witness::ReasonCode::ExecutionFailed);
    unknown.outcome = WitnessOutcome::OutcomeUnknown;
    journal.complete(intent, unknown).unwrap();
    let mut recovery = record(WitnessStage::Recovery);
    recovery.event_id = [64; 16];
    recovery.decision_id = Some([62; 16]);
    recovery.result_digest = Some([3; 32]);
    recovery.reason = Some(ferro_core::witness::ReasonCode::RecoveryCompleted);
    recovery.outcome = WitnessOutcome::Recovered;
    recovery.recovery_link = Some([63; 16]);
    assert!(matches!(
        journal.complete_recovery(id, recovery),
        Err(JournalError::AutomationStopped)
    ));
    assert_eq!(journal.pending().unwrap().len(), 1);
}

#[test]
fn segment_rotation_handoff_preserves_chain_across_reopen() {
    let root = tempdir().unwrap();
    let rotating = config(root.path()).segment_bytes(400);
    let journal = WitnessJournal::open(rotating.clone()).unwrap();
    let id = OperationId::from_bytes([101; 16]);
    journal
        .append_received(id, 1, recipe(), record(WitnessStage::RequestReceived))
        .unwrap();
    let mut decision = record(WitnessStage::Decision);
    decision.decision_id = Some([101; 16]);
    decision.rule = Some(RuleSummary::from_id([1; 16]));
    decision.decision = Some(true);
    let intent = journal.append_decision(id, decision).unwrap();
    let mut outcome = record(WitnessStage::Outcome);
    outcome.decision_id = Some([101; 16]);
    outcome.result_digest = Some([1; 32]);
    outcome.outcome = WitnessOutcome::Succeeded;
    journal.complete(intent, outcome).unwrap();
    assert!(journal
        .segment_sizes()
        .unwrap()
        .into_iter()
        .all(|size| size <= 400));
    assert!(journal.segment_count().unwrap() >= 2);
    assert!(!journal.export_segment(0).unwrap().is_empty());
    drop(journal);
    let journal = WitnessJournal::open(rotating).unwrap();
    assert!(journal.segment_count().unwrap() >= 2);
    assert!(
        verify_stream(
            journal.records().unwrap().iter().map(Vec::as_slice),
            &StreamTrust::new([9; 16], 1, 1, [0; 32])
        )
        .unwrap()
        .integrity
    );
    // Task 5 exposes no deletion API; sealed evidence remains locally retained.
    assert!(!journal.export_segment(0).unwrap().is_empty());
}

#[test]
fn pre_append_rotation_failure_is_non_durable_and_retryable() {
    let root = tempdir().unwrap();
    let faults = JournalFaults::new();
    let config = config(root.path()).segment_bytes(400);
    let journal = WitnessJournal::open_with_faults(config, faults.clone()).unwrap();
    let id = OperationId::from_bytes([141; 16]);
    journal
        .append_received(id, 1, recipe(), record(WitnessStage::RequestReceived))
        .unwrap();
    faults.fail_once(FaultPoint::RotationSeal);
    let mut decision = record(WitnessStage::Decision);
    decision.decision_id = Some([141; 16]);
    decision.rule = Some(RuleSummary::from_id([1; 16]));
    decision.decision = Some(true);
    assert!(matches!(
        journal.append_decision(id, decision.clone()),
        Err(JournalError::RotationUnavailable)
    ));
    assert_eq!(journal.records().unwrap().len(), 1);
    assert_eq!(journal.segment_count().unwrap(), 1);
    let intent = journal.append_decision(id, decision).unwrap();
    assert_eq!(intent.operation_id(), id);
    assert_eq!(journal.recover(id).unwrap().operation_id(), id);
    assert!(journal
        .segment_sizes()
        .unwrap()
        .into_iter()
        .all(|size| size <= 400));
}

#[test]
fn explicit_maintenance_retries_deferred_rotation_without_empty_segments() {
    let root = tempdir().unwrap();
    let faults = JournalFaults::new();
    let journal =
        WitnessJournal::open_with_faults(config(root.path()).segment_bytes(400), faults.clone())
            .unwrap();
    journal
        .append_received(
            OperationId::from_bytes([161; 16]),
            1,
            recipe(),
            record(WitnessStage::RequestReceived),
        )
        .unwrap();
    faults.fail_once(FaultPoint::RotationSeal);
    assert!(matches!(
        journal.maintain(),
        Err(JournalError::UnavailableBeforeVisibility)
    ));
    assert_eq!(journal.segment_count().unwrap(), 1);
    journal.maintain().unwrap();
    assert_eq!(journal.segment_count().unwrap(), 2);
    assert!(journal
        .segment_sizes()
        .unwrap()
        .into_iter()
        .all(|n| n <= 400));
}

#[test]
fn temp_only_stop_marker_and_repeated_stop_are_fail_closed() {
    let root = tempdir().unwrap();
    std::fs::write(
        root.path().join("witness.automation-stopped.tmp"),
        b"stopped-v1",
    )
    .unwrap();
    assert!(matches!(
        WitnessJournal::open(config(root.path())),
        Err(JournalError::AutomationStopped)
    ));
    assert!(matches!(
        WitnessJournal::open(config(root.path())),
        Err(JournalError::AutomationStopped)
    ));
    #[cfg(unix)]
    {
        let symlink_root = tempdir().unwrap();
        std::os::unix::fs::symlink(
            symlink_root.path().join("missing-target"),
            symlink_root.path().join("witness.automation-stopped.tmp"),
        )
        .unwrap();
        assert!(matches!(
            WitnessJournal::open(config(symlink_root.path())),
            Err(JournalError::AutomationStopped)
        ));
    }
}

#[test]
fn enospc_received_transaction_and_flush_matrix_reopens_safely() {
    for (point, previsible) in [
        (FaultPoint::Transaction(FlushBoundary::Received), true),
        (FaultPoint::BeforeFlush(FlushBoundary::Received), false),
        (FaultPoint::DuringFlush(FlushBoundary::Received), false),
        (FaultPoint::AfterFlush(FlushBoundary::Received), false),
    ] {
        let root = tempdir().unwrap();
        let faults = JournalFaults::new();
        let journal =
            WitnessJournal::open_with_faults(config(root.path()), faults.clone()).unwrap();
        let id = OperationId::from_bytes([171; 16]);
        faults.fail_enospc_once(point);
        let error = journal
            .append_received(id, 1, recipe(), record(WitnessStage::RequestReceived))
            .unwrap_err();
        assert_eq!(
            matches!(error, JournalError::UnavailableBeforeVisibility),
            previsible
        );
        drop(journal);
        let reopened = WitnessJournal::open(config(root.path())).unwrap();
        if previsible {
            assert!(matches!(
                reopened.recover(id),
                Err(JournalError::NotPending)
            ));
        } else {
            assert_eq!(reopened.recover(id).unwrap().operation_id(), id);
        }
    }
}

#[test]
fn enospc_decision_transaction_and_each_flush_boundary_reopen_safely() {
    for (point, previsible) in [
        (FaultPoint::Transaction(FlushBoundary::Decision), true),
        (FaultPoint::BeforeFlush(FlushBoundary::Decision), false),
        (FaultPoint::DuringFlush(FlushBoundary::Decision), false),
        (FaultPoint::AfterFlush(FlushBoundary::Decision), false),
    ] {
        let root = tempdir().unwrap();
        let faults = JournalFaults::new();
        let journal =
            WitnessJournal::open_with_faults(config(root.path()), faults.clone()).unwrap();
        let id = OperationId::from_bytes([172; 16]);
        journal
            .append_received(id, 1, recipe(), record(WitnessStage::RequestReceived))
            .unwrap();
        let mut decision = record(WitnessStage::Decision);
        decision.event_id = [173; 16];
        decision.decision_id = Some([172; 16]);
        decision.rule = Some(RuleSummary::from_id([1; 16]));
        decision.decision = Some(true);
        faults.fail_enospc_once(point);
        let error = journal.append_decision(id, decision).unwrap_err();
        assert_eq!(
            matches!(error, JournalError::UnavailableBeforeVisibility),
            previsible
        );
        drop(journal);
        assert_eq!(
            WitnessJournal::open(config(root.path()))
                .unwrap()
                .recover(id)
                .unwrap()
                .operation_id(),
            id
        );
    }
}

#[test]
fn enospc_outcome_transaction_and_each_flush_boundary_reopen_safely() {
    for (point, previsible) in [
        (FaultPoint::Transaction(FlushBoundary::Outcome), true),
        (FaultPoint::BeforeFlush(FlushBoundary::Outcome), false),
        (FaultPoint::DuringFlush(FlushBoundary::Outcome), false),
        (FaultPoint::AfterFlush(FlushBoundary::Outcome), false),
    ] {
        let root = tempdir().unwrap();
        let faults = JournalFaults::new();
        let journal =
            WitnessJournal::open_with_faults(config(root.path()), faults.clone()).unwrap();
        let id = OperationId::from_bytes([174; 16]);
        let intent = allow(&journal, id, 174);
        faults.fail_enospc_once(point);
        let error = journal
            .complete(intent, outcome(174, WitnessOutcome::Succeeded))
            .unwrap_err();
        assert_eq!(
            matches!(error, JournalError::UnavailableBeforeVisibility),
            previsible
        );
        drop(journal);
        let reopened = WitnessJournal::open(config(root.path())).unwrap();
        let classification = reopened.recover(id);
        assert!(matches!(
            classification,
            Ok(_) | Err(JournalError::AlreadyComplete)
        ));
    }
}

#[test]
fn enospc_reserve_and_cleanup_result_boundaries_latch_fail_stop() {
    let points = [
        FaultPoint::Transaction(FlushBoundary::Reserve),
        FaultPoint::BeforeFlush(FlushBoundary::Reserve),
        FaultPoint::DuringFlush(FlushBoundary::Reserve),
        FaultPoint::AfterFlush(FlushBoundary::Reserve),
        FaultPoint::Transaction(FlushBoundary::Outcome),
        FaultPoint::BeforeFlush(FlushBoundary::Outcome),
        FaultPoint::DuringFlush(FlushBoundary::Outcome),
        FaultPoint::AfterFlush(FlushBoundary::Outcome),
    ];
    for (index, point) in points.into_iter().enumerate() {
        let root = tempdir().unwrap();
        let faults = JournalFaults::new();
        let journal =
            WitnessJournal::open_with_faults(config(root.path()), faults.clone()).unwrap();
        let byte = 181_u8.wrapping_add(index as u8);
        let id = OperationId::from_bytes([byte; 16]);
        let intent = allow(&journal, id, byte);
        let unknown = outcome(byte, WitnessOutcome::OutcomeUnknown);
        let unknown_event = unknown.event_id;
        journal.complete(intent, unknown).unwrap();
        let mut recovery = record(WitnessStage::Recovery);
        recovery.event_id = [byte.wrapping_add(3); 16];
        recovery.decision_id = Some([byte; 16]);
        recovery.result_digest = Some([byte; 32]);
        recovery.reason = Some(ferro_core::witness::ReasonCode::RecoveryCompleted);
        recovery.outcome = WitnessOutcome::Recovered;
        recovery.recovery_link = Some(unknown_event);
        faults.fail_enospc_once(point);
        assert!(matches!(
            journal.complete_recovery(id, recovery.clone()),
            Err(JournalError::AutomationStopped)
        ));
        assert!(matches!(
            journal.complete_recovery(id, recovery),
            Err(JournalError::AutomationStopped)
        ));
        drop(journal);
        assert!(matches!(
            WitnessJournal::open(config(root.path())),
            Err(JournalError::AutomationStopped)
        ));
    }
}
