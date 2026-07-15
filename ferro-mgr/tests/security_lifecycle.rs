use std::sync::Arc;

use ferro_mgr::{revocation::RevocationService, rotation::{KeyRotation, RotationState}, store::{Enrollment, ManagerStore}};
use tempfile::tempdir;

#[test]
fn rotation_requires_all_reachable_nodes_before_commit() {
    let mut rotation = KeyRotation::prepare(vec!["node-a".into(), "node-b".into()], vec![8; 32]);
    rotation.acknowledge("node-a");
    assert_eq!(*rotation.state(), RotationState::Preparing);
    assert!(!rotation.commit());
    rotation.acknowledge("node-b");
    assert_eq!(*rotation.state(), RotationState::Ready);
    assert!(rotation.commit());
    assert_eq!(*rotation.state(), RotationState::Committed);
}

#[test]
fn revocation_is_idempotent_and_persisted() {
    let directory = tempdir().unwrap();
    let store = Arc::new(ManagerStore::open(directory.path().join("manager.sqlite")).unwrap());
    store.register_node(Enrollment { node_id: "node-a".into(), public_key: vec![1; 32], endpoint: "198.51.100.1:1".into() }).unwrap();
    let revocation = RevocationService::new(store);
    assert!(revocation.revoke_node("node-a", "compromised").unwrap());
    assert!(!revocation.revoke_node("node-a", "repeat").unwrap());
    assert!(revocation.is_revoked("node-a").unwrap());
}
