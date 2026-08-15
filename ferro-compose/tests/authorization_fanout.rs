use ferro_compose::{
    FanoutAction, FanoutError, FanoutPlan, FanoutResult, FanoutStatus, ServiceMutation,
};

fn mutation(name: &str, digest: u8) -> ServiceMutation {
    ServiceMutation::new(name, FanoutAction::ContainerRun, [digest; 32])
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
