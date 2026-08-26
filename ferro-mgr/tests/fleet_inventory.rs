#![cfg(target_os = "linux")]

use ferro_mgr::store::{Enrollment, HostObservation, ManagerStore};

#[test]
fn manager_persists_and_lists_active_and_revoked_host_inventory() {
    let directory = tempfile::tempdir().unwrap();
    let store = ManagerStore::open(directory.path().join("manager.sqlite")).unwrap();
    for (node_id, endpoint, key) in [
        ("lab-x86", "192.168.122.9:50053", 1_u8),
        ("oracle-arm", "203.0.113.10:50053", 2_u8),
    ] {
        store
            .register_node(Enrollment {
                node_id: node_id.into(),
                public_key: vec![key; 32],
                endpoint: endpoint.into(),
            })
            .unwrap();
    }
    store
        .record_host_observation(HostObservation {
            node_id: "lab-x86".into(),
            last_seen_unix: 1_000,
            version: "0.1.0".into(),
            health: "healthy".into(),
            doctor_summary: "8 checks passed".into(),
            containers_json: r#"[{"id":"abc","name":"fleet-lab","status":"running"}]"#.into(),
            acknowledged_revision: 7,
        })
        .unwrap();
    store.revoke_node("oracle-arm", "qualification").unwrap();

    let hosts = store.list_hosts().unwrap();
    assert_eq!(hosts.len(), 2);
    assert_eq!(hosts[0].node_id, "lab-x86");
    assert_eq!(hosts[0].enrollment_state, "enrolled");
    assert_eq!(hosts[0].last_seen_unix, Some(1_000));
    assert_eq!(hosts[0].acknowledged_revision, Some(7));
    assert!(hosts[0].containers_json.contains("fleet-lab"));
    assert_eq!(hosts[1].node_id, "oracle-arm");
    assert_eq!(hosts[1].enrollment_state, "revoked");
}

#[test]
fn observations_are_rejected_for_unknown_hosts() {
    let directory = tempfile::tempdir().unwrap();
    let store = ManagerStore::open(directory.path().join("manager.sqlite")).unwrap();
    assert!(store
        .record_host_observation(HostObservation {
            node_id: "unknown".into(),
            last_seen_unix: 1,
            version: "0.1.0".into(),
            health: "healthy".into(),
            doctor_summary: String::new(),
            containers_json: "[]".into(),
            acknowledged_revision: 0,
        })
        .is_err());
}
