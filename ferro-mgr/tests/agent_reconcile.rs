use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

use ed25519_dalek::SigningKey;
use ferro_mgr::{agent::{Agent, NetdClient, StateStore}, desired_state::DesiredStateBuilder, proto::OverlayState};
use tempfile::tempdir;

struct FakeNetd { calls: Arc<AtomicUsize>, fail: bool }
impl NetdClient for FakeNetd {
    fn apply(&self, _desired: &ferro_mgr::proto::DesiredState) -> Result<(), String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail { Err("apply failed".into()) } else { Ok(()) }
    }
}

fn desired(revision: u64, now_unix: i64) -> ferro_mgr::proto::DesiredState {
    let builder = DesiredStateBuilder::new("cluster-a", 2, vec![4; 32]);
    builder.snapshot(revision, vec![OverlayState { overlay_id: "overlay-a".into(), routes: vec![], peers: vec![] }], now_unix)
}

fn verifying_key() -> Vec<u8> { SigningKey::from_bytes(&[4; 32]).verifying_key().to_bytes().to_vec() }

#[test]
fn failed_netd_apply_does_not_advance_persisted_state() {
    let directory = tempdir().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let agent = Agent::new("cluster-a", verifying_key(), StateStore::new(directory.path().join("state.json")), FakeNetd { calls: calls.clone(), fail: true }).unwrap();
    assert!(agent.reconcile(desired(1, 100), 101).is_err());
    assert_eq!(agent.state().applied_revision, 0);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn successful_reconcile_persists_revision_after_netd() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("state.json");
    let calls = Arc::new(AtomicUsize::new(0));
    let agent = Agent::new("cluster-a", verifying_key(), StateStore::new(&path), FakeNetd { calls: calls.clone(), fail: false }).unwrap();
    assert_eq!(agent.reconcile(desired(1, 100), 101).unwrap(), 1);
    assert_eq!(StateStore::new(path).load().unwrap().applied_revision, 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn equal_revision_with_extended_lease_is_applied() {
    let directory = tempdir().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let agent = Agent::new("cluster-a", verifying_key(), StateStore::new(directory.path().join("state.json")), FakeNetd { calls: calls.clone(), fail: false }).unwrap();
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
    let agent = Agent::new("cluster-a", verifying_key(), StateStore::new(directory.path().join("state.json")), FakeNetd { calls: calls.clone(), fail: false }).unwrap();
    let desired = desired(1, 100);

    assert_eq!(agent.reconcile(desired.clone(), 101).unwrap(), 1);
    assert!(matches!(agent.reconcile(desired, 101), Err(ferro_mgr::agent::AgentError::StaleRevision)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
