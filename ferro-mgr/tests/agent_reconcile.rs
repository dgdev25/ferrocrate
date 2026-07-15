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

fn desired(revision: u64) -> ferro_mgr::proto::DesiredState {
    let builder = DesiredStateBuilder::new("cluster-a", 2, vec![4; 32]);
    builder.snapshot(revision, vec![OverlayState { overlay_id: "overlay-a".into(), routes: vec![], peers: vec![] }], 100)
}

fn verifying_key() -> Vec<u8> { SigningKey::from_bytes(&[4; 32]).verifying_key().to_bytes().to_vec() }

#[test]
fn failed_netd_apply_does_not_advance_persisted_state() {
    let directory = tempdir().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let agent = Agent::new("cluster-a", verifying_key(), StateStore::new(directory.path().join("state.json")), FakeNetd { calls: calls.clone(), fail: true }).unwrap();
    assert!(agent.reconcile(desired(1), 101).is_err());
    assert_eq!(agent.state().applied_revision, 0);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn successful_reconcile_persists_revision_after_netd() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("state.json");
    let calls = Arc::new(AtomicUsize::new(0));
    let agent = Agent::new("cluster-a", verifying_key(), StateStore::new(&path), FakeNetd { calls: calls.clone(), fail: false }).unwrap();
    assert_eq!(agent.reconcile(desired(1), 101).unwrap(), 1);
    assert_eq!(StateStore::new(path).load().unwrap().applied_revision, 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
