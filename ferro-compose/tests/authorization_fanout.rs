use ferro_compose::{
    execute_fanout, FanoutAction, FanoutError, FanoutExecutionError, FanoutPlan,
    FanoutReplayStore, FanoutResult, FanoutStatus, ServiceMutation,
};

fn mutation(name: &str, digest: u8) -> ServiceMutation {
    ServiceMutation::new(name, FanoutAction::ContainerRun, [digest; 32])
}

#[test]
fn command_path_preserves_success_denial_and_failure_for_every_child() {
    let temp = tempfile::tempdir().unwrap();
    let plan = FanoutPlan::derive(
        [4; 16],
        1,
        [5; 32],
        10_000,
        0,
        [mutation("ok", 1), mutation("denied", 2), mutation("failed", 3)],
    )
    .unwrap();
    let replay = FanoutReplayStore::open(temp.path()).unwrap();
    let result = execute_fanout(&plan, &replay, || 9_000, |child| match child.service() {
        "ok" => Ok(()),
        "denied" => Err(FanoutExecutionError::Denied("policy-denied".into())),
        _ => Err(FanoutExecutionError::Failed("executor-failed".into())),
    });

    assert_eq!(result.statuses().len(), 3);
    assert_eq!(result.denied(), 1);
    assert_eq!(result.failed(), 1);
    assert!(result.is_partial());
}

#[test]
fn command_path_rejects_restart_replay_and_executes_attempt_scoped_retry() {
    let temp = tempfile::tempdir().unwrap();
    let first = FanoutPlan::derive([6; 16], 2, [7; 32], 10_000, 0, [mutation("web", 1)]).unwrap();
    let retry = FanoutPlan::derive([6; 16], 2, [7; 32], 10_000, 1, [mutation("web", 1)]).unwrap();
    let store = FanoutReplayStore::open(temp.path()).unwrap();
    assert_eq!(execute_fanout(&first, &store, || 9_000, |_| Ok(())).failed(), 0);
    drop(store);

    let reopened = FanoutReplayStore::open(temp.path()).unwrap();
    let mut replay_executed = false;
    let replay = execute_fanout(&first, &reopened, || 9_000, |_| {
        replay_executed = true;
        Ok(())
    });
    assert_eq!(replay.failed(), 1);
    assert!(!replay_executed);

    let mut retry_executed = false;
    let retried = execute_fanout(&retry, &reopened, || 9_000, |_| {
        retry_executed = true;
        Ok(())
    });
    assert_eq!(retried.failed(), 0);
    assert!(retry_executed);
}

#[test]
fn replay_claims_are_durable_and_attempt_scoped() {
    let temp = tempfile::tempdir().unwrap();
    let first = FanoutPlan::derive([1; 16], 7, [2; 32], 10_000, 0, [mutation("web", 4)]).unwrap();
    let retry = FanoutPlan::derive([1; 16], 7, [2; 32], 10_000, 1, [mutation("web", 4)]).unwrap();
    let store = FanoutReplayStore::open(temp.path()).unwrap();
    store.claim(&first.children()[0]).unwrap();
    assert!(matches!(
        store.claim(&first.children()[0]),
        Err(FanoutError::Replay)
    ));
    store.claim(&retry.children()[0]).unwrap();
    drop(store);
    let reopened = FanoutReplayStore::open(temp.path()).unwrap();
    assert!(matches!(
        reopened.claim(&retry.children()[0]),
        Err(FanoutError::Replay)
    ));
}

#[test]
fn concurrent_children_cannot_claim_each_others_identity() {
    let temp = tempfile::tempdir().unwrap();
    let plan = FanoutPlan::derive(
        [9; 16],
        1,
        [8; 32],
        10_000,
        0,
        [mutation("a", 1), mutation("b", 2)],
    )
    .unwrap();
    let store = std::sync::Arc::new(FanoutReplayStore::open(temp.path()).unwrap());
    let children = plan.children().to_vec();
    let joins: Vec<_> = children
        .into_iter()
        .map(|child| {
            let store = store.clone();
            std::thread::spawn(move || {
                store.claim(&child).unwrap();
                *child.child_id()
            })
        })
        .collect();
    let ids: std::collections::HashSet<_> =
        joins.into_iter().map(|join| join.join().unwrap()).collect();
    assert_eq!(ids.len(), 2);
}

#[test]
fn children_bind_parent_order_action_digest_deadline_and_attempt() {
    let plan = FanoutPlan::derive(
        [1; 16],
        7,
        [2; 32],
        10_000,
        0,
        [mutation("db", 3), mutation("web", 4)],
    )
    .unwrap();
    assert_eq!(plan.children().len(), 2);
    assert_ne!(plan.children()[0].child_id(), plan.children()[1].child_id());
    assert_eq!(plan.children()[0].parent_request_id(), &[1; 16]);
    assert_eq!(plan.children()[0].policy_generation(), 7);
    assert_eq!(plan.children()[0].policy_digest(), &[2; 32]);
    assert_eq!(plan.children()[0].deadline_unix_ms(), 10_000);
    assert_eq!(plan.children()[0].attempt(), 0);
    assert_eq!(plan.children()[0].request_digest(), &[3; 32]);
}

#[test]
fn added_reordered_or_repurposed_children_do_not_replay() {
    let original = FanoutPlan::derive(
        [1; 16],
        7,
        [2; 32],
        10_000,
        0,
        [mutation("db", 3), mutation("web", 4)],
    )
    .unwrap();
    let reordered = FanoutPlan::derive(
        [1; 16],
        7,
        [2; 32],
        10_000,
        0,
        [mutation("web", 4), mutation("db", 3)],
    )
    .unwrap();
    let added = FanoutPlan::derive(
        [1; 16],
        7,
        [2; 32],
        10_000,
        0,
        [mutation("db", 3), mutation("web", 4), mutation("cache", 5)],
    )
    .unwrap();
    assert_ne!(original.plan_digest(), reordered.plan_digest());
    assert_ne!(original.plan_digest(), added.plan_digest());
    assert!(matches!(
        original.verify_child(&reordered.children()[0], 9_000),
        Err(FanoutError::Replay)
    ));
    assert!(matches!(
        original.verify_child(&added.children()[2], 9_000),
        Err(FanoutError::Replay)
    ));
}

#[test]
fn retries_get_new_identity_but_keep_idempotency_binding() {
    let first = FanoutPlan::derive([1; 16], 7, [2; 32], 10_000, 0, [mutation("web", 4)]).unwrap();
    let retry = FanoutPlan::derive([1; 16], 7, [2; 32], 10_000, 1, [mutation("web", 4)]).unwrap();
    assert_ne!(
        first.children()[0].child_id(),
        retry.children()[0].child_id()
    );
    assert_eq!(
        first.children()[0].idempotency_key(),
        retry.children()[0].idempotency_key()
    );
}

#[test]
fn partial_results_preserve_each_child_decision_and_outcome() {
    let result = FanoutResult::new(vec![
        FanoutStatus::succeeded([1; 16]),
        FanoutStatus::denied([2; 16], "policy-denied"),
        FanoutStatus::failed([3; 16], "runtime-failed"),
    ]);
    assert!(result.is_partial());
    assert_eq!(result.denied(), 1);
    assert_eq!(result.failed(), 1);
}
