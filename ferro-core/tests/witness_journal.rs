use ferro_core::witness::{
    FlushBoundary, Invocation, JournalConfig, JournalError, JournalFaults, JournalMode,
    OperationId, PrincipalSummary, RecoveryRecipe, ResourceSummary, RuleSummary, WitnessAction,
    WitnessJournal, WitnessOutcome, WitnessRecord, WitnessResourceKind, WitnessStage,
};
use std::sync::{Arc, Barrier};
use tempfile::tempdir;

fn record(stage: WitnessStage) -> WitnessRecord {
    WitnessRecord {
        sequence: 0,
        previous_hash: [0; 32],
        event_id: [3; 16],
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
    RecoveryRecipe::delete_owned_resource(WitnessAction::ContainerDelete, [8; 32], 1)
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
            journal
                .append_received(id, 1, recipe(), record(WitnessStage::RequestReceived))
                .unwrap();
            let mut decision = record(WitnessStage::Decision);
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
