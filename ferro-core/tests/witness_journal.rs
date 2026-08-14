use ferro_core::witness::{
    verify_stream, DisclosureClass, FaultPoint, FlushBoundary, Invocation, JournalConfig,
    JournalError, JournalFaults, JournalMode, OperationId, PrincipalSummary, RecoveryRecipe,
    ResourceSummary, RuleSummary, StreamTrust, WitnessAction, WitnessJournal, WitnessOutcome,
    WitnessRecord, WitnessResourceKind, WitnessStage,
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
    };
    WitnessRecord {
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

fn config(path: &std::path::Path) -> JournalConfig {
    JournalConfig::new(path, [9; 16], JournalMode::Required).cleanup_reserve_bytes(4096)
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
    faults.fail_ambiguous_once(FlushBoundary::Decision);
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
    faults.fail_ambiguous_once(FlushBoundary::Outcome);
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
            &StreamTrust::new([9; 16], 1, [0; 32])
        )
        .unwrap()
        .lifecycle_consistent
    );
}

#[test]
fn cleanup_reserve_failure_stops_automation() {
    let root = tempdir().unwrap();
    let faults = JournalFaults::new();
    faults.fail_ambiguous_once(FlushBoundary::Reserve);
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
    faults.fail_once(FaultPoint::Transaction(FlushBoundary::Received));
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
    faults.fail_once(FaultPoint::DuringFlush(FlushBoundary::Received));
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
            &StreamTrust::new([9; 16], 1, [0; 32])
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
            &StreamTrust::new([9; 16], 1, [0; 32])
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
            &StreamTrust::new([9; 16], 1, [0; 32])
        )
        .unwrap()
        .lifecycle_consistent
    );
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
    faults.fail_ambiguous_once(FlushBoundary::Reserve);
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
    assert!(journal.segment_count().unwrap() >= 2);
    drop(journal);
    let journal = WitnessJournal::open(rotating).unwrap();
    assert!(journal.segment_count().unwrap() >= 2);
    assert!(
        verify_stream(
            journal.records().unwrap().iter().map(Vec::as_slice),
            &StreamTrust::new([9; 16], 1, [0; 32])
        )
        .unwrap()
        .integrity
    );
}
