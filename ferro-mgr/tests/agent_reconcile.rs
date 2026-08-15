use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use ed25519_dalek::SigningKey;
use ferro_mgr::{
    agent::{
        netd_sequence::{NetdSequence, SequenceValue},
        Agent, AgentError, NetdClient, StateStore,
    },
    desired_state::DesiredStateBuilder,
    proto::OverlayState,
};
use tempfile::tempdir;

struct FakeNetd {
    calls: Arc<AtomicUsize>,
    fail: bool,
}
impl NetdClient for FakeNetd {
    fn apply(&self, _desired: &ferro_mgr::proto::DesiredState) -> Result<(), String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            Err("apply failed".into())
        } else {
            Ok(())
        }
    }
    fn apply_authorized(
        &self,
        _desired: &ferro_mgr::proto::DesiredState,
        _bundle: &ferro_mgr::agent::desired_authorization::DesiredAuthorizationBundle,
    ) -> Result<(), String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            Err("apply failed".into())
        } else {
            Ok(())
        }
    }
}

fn desired(revision: u64, now_unix: i64) -> ferro_mgr::proto::DesiredState {
    let builder = DesiredStateBuilder::new("cluster-a", 2, vec![4; 32]);
    builder.snapshot(
        revision,
        vec![OverlayState {
            overlay_id: "overlay-a".into(),
            routes: vec![],
            peers: vec![],
        }],
        now_unix,
    )
}

fn verifying_key() -> Vec<u8> {
    SigningKey::from_bytes(&[4; 32])
        .verifying_key()
        .to_bytes()
        .to_vec()
}

#[test]
fn enforcing_agent_rejects_desired_state_without_authorization_bundle_before_netd() {
    let directory = tempdir().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let agent = Agent::new_enforcing(
        "cluster-a",
        verifying_key(),
        StateStore::new(directory.path().join("state.json")),
        FakeNetd {
            calls: calls.clone(),
            fail: false,
        },
    )
    .unwrap();

    assert!(matches!(
        agent.reconcile(desired(1, 100), 101),
        Err(AgentError::MissingAuthorization)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn enforcing_agent_rejects_invalid_bundle_before_netd() {
    let directory = tempdir().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let agent = Agent::new_enforcing(
        "cluster-a",
        verifying_key(),
        StateStore::new(directory.path().join("state.json")),
        FakeNetd {
            calls: calls.clone(),
            fail: false,
        },
    )
    .unwrap();
    let desired = desired(1, 100);

    assert!(matches!(
        agent.reconcile_with_bundle(desired, b"{}", 101),
        Err(AgentError::InvalidAuthorization)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn enforcing_agent_accepts_signed_exact_empty_transition_bundle() {
    use ferro_mgr::agent::desired_authorization::DesiredAuthorizationBundle;
    let directory = tempdir().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let agent = Agent::new_enforcing(
        "cluster-a",
        verifying_key(),
        StateStore::new(directory.path().join("state.json")),
        FakeNetd {
            calls: calls.clone(),
            fail: false,
        },
    )
    .unwrap();
    let builder = DesiredStateBuilder::new("cluster-a", 2, vec![4; 32]);
    let desired = builder.snapshot(1, vec![], 100);
    let bundle = DesiredAuthorizationBundle::sign(
        &desired,
        "node-a",
        vec![],
        &SigningKey::from_bytes(&[4; 32]),
    )
    .unwrap();

    assert_eq!(
        agent
            .reconcile_with_bundle(desired, &serde_json::to_vec(&bundle).unwrap(), 101)
            .unwrap(),
        1
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn failed_netd_apply_does_not_advance_persisted_state() {
    let directory = tempdir().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let agent = Agent::new(
        "cluster-a",
        verifying_key(),
        StateStore::new(directory.path().join("state.json")),
        FakeNetd {
            calls: calls.clone(),
            fail: true,
        },
    )
    .unwrap();
    assert!(agent.reconcile(desired(1, 100), 101).is_err());
    assert_eq!(agent.state().applied_revision, 0);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn shared_netd_sequence_advances_only_after_a_successful_apply_and_survives_restart() {
    let directory = tempdir().unwrap();
    let sequence_path = directory.path().join("netd-sequence.json");
    let sequence = NetdSequence::open(
        sequence_path.clone(),
        SequenceValue {
            epoch: 1,
            revision: 7,
        },
    )
    .unwrap();
    let failed = Agent::new(
        "cluster-a",
        verifying_key(),
        StateStore::new(directory.path().join("failed-state.json")),
        FakeNetd {
            calls: Arc::new(AtomicUsize::new(0)),
            fail: true,
        },
    )
    .unwrap()
    .with_netd_sequence(sequence.clone());

    assert!(failed.reconcile(desired(1, 100), 101).is_err());
    assert_eq!(
        sequence.current().unwrap(),
        SequenceValue {
            epoch: 1,
            revision: 7
        }
    );

    let successful = Agent::new(
        "cluster-a",
        verifying_key(),
        StateStore::new(directory.path().join("successful-state.json")),
        FakeNetd {
            calls: Arc::new(AtomicUsize::new(0)),
            fail: false,
        },
    )
    .unwrap()
    .with_netd_sequence(sequence);
    successful.reconcile(desired(9, 100), 101).unwrap();

    let restarted = NetdSequence::open(
        sequence_path,
        SequenceValue {
            epoch: 0,
            revision: 0,
        },
    )
    .unwrap();
    assert_eq!(
        restarted.reserve_child().unwrap(),
        SequenceValue {
            epoch: 2,
            revision: 10
        }
    );
}

#[test]
fn successful_reconcile_persists_revision_after_netd() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("state.json");
    let calls = Arc::new(AtomicUsize::new(0));
    let agent = Agent::new(
        "cluster-a",
        verifying_key(),
        StateStore::new(&path),
        FakeNetd {
            calls: calls.clone(),
            fail: false,
        },
    )
    .unwrap();
    assert_eq!(agent.reconcile(desired(1, 100), 101).unwrap(), 1);
    assert_eq!(StateStore::new(path).load().unwrap().applied_revision, 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn equal_revision_with_extended_lease_is_applied() {
    let directory = tempdir().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let agent = Agent::new(
        "cluster-a",
        verifying_key(),
        StateStore::new(directory.path().join("state.json")),
        FakeNetd {
            calls: calls.clone(),
            fail: false,
        },
    )
    .unwrap();
    let initial = desired(1, 100);
    let renewed = desired(1, 200);

    assert_eq!(agent.reconcile(initial, 101).unwrap(), 1);
    assert_eq!(agent.reconcile(renewed.clone(), 201).unwrap(), 1);
    assert_eq!(agent.state().lease_expiry, renewed.lease_expires_unix);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn equal_revision_without_lease_extension_is_stale() {
    let directory = tempdir().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let agent = Agent::new(
        "cluster-a",
        verifying_key(),
        StateStore::new(directory.path().join("state.json")),
        FakeNetd {
            calls: calls.clone(),
            fail: false,
        },
    )
    .unwrap();
    let desired = desired(1, 100);

    assert_eq!(agent.reconcile(desired.clone(), 101).unwrap(), 1);
    assert!(matches!(
        agent.reconcile(desired, 101),
        Err(ferro_mgr::agent::AgentError::StaleRevision)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
