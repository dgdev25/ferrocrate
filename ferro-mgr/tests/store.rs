use ferro_mgr::store::{Enrollment, ManagerStore, Overlay, ScopedToken, StoreError};
use ipnet::Ipv4Net;
use tempfile::tempdir;

fn store() -> ManagerStore {
    let directory = tempdir().unwrap();
    let path = directory.keep().join("manager.sqlite");
    ManagerStore::open(path).unwrap()
}

fn enrollment() -> Enrollment {
    Enrollment { node_id: "node-a".into(), public_key: vec![7; 32], endpoint: "198.51.100.10:51820".into() }
}

#[test]
fn token_consumption_and_node_registration_are_atomic() {
    let store = store();
    let token = store.create_token(ScopedToken {
        secret: [9; 32], expected_node: "node-a".into(), approved_endpoint: "198.51.100.10:51820".into(), overlay_scope: "all".into(), expires_at: 100,
    }).unwrap();
    store.register_node_with_token(&token.secret, enrollment(), 99).unwrap();
    assert!(matches!(store.register_node_with_token(&token.secret, enrollment(), 99), Err(StoreError::TokenConsumed)));
}

#[test]
fn allocation_uses_lowest_non_reserved_subnet() {
    let store = store();
    store.register_node(enrollment()).unwrap();
    store.create_overlay(Overlay { id: "overlay-a".into(), cidr: "10.44.0.0/24".into() }).unwrap();
    let reserved: Ipv4Net = "10.44.0.0/26".parse().unwrap();
    let allocated = store.allocate_node_subnet("overlay-a", "node-a", 26, &[reserved]).unwrap();
    assert_eq!(allocated.to_string(), "10.44.0.64/26");
}

#[test]
fn node_count_excludes_revoked_nodes() {
    let store = store();
    store.register_node(enrollment()).unwrap();
    assert_eq!(store.node_count().unwrap(), 1);
    store.revoke_node("node-a", "test").unwrap();
    assert_eq!(store.node_count().unwrap(), 0);
}

#[test]
fn recovery_advances_epoch_and_invalidates_nodes() {
    let store = store();
    store.register_node(enrollment()).unwrap();
    assert_eq!(store.cluster_epoch().unwrap(), 1);
    assert_eq!(store.recover_after_restore("database restore", 200).unwrap(), 2);
    assert_eq!(store.cluster_epoch().unwrap(), 2);
    assert_eq!(store.node_count().unwrap(), 0);
    assert!(!store.node_is_active("node-a").unwrap());
}
