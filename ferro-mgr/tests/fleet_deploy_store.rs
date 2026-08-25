#![cfg(target_os = "linux")]

use ferro_mgr::store::ManagerStore;

#[test]
fn deployments_are_revisioned_and_link_to_the_previous_generation() {
    let directory = tempfile::tempdir().unwrap();
    let store = ManagerStore::open(directory.path().join("manager.sqlite")).unwrap();
    let first = store
        .begin_fleet_deployment(
            "web",
            "alpine:3.21",
            r#"["sh","-c","echo v1"]"#,
            r#"["node-a","node-b"]"#,
            None,
            1_000,
        )
        .unwrap();
    store
        .update_fleet_deployment(
            &first.deployment_id,
            "succeeded",
            r#"{"node-a":"ready","node-b":"ready"}"#,
            None,
        )
        .unwrap();
    let second = store
        .begin_fleet_deployment(
            "web",
            "alpine:3.22",
            r#"["sh","-c","echo v2"]"#,
            r#"["node-a","node-b"]"#,
            Some(&first.deployment_id),
            1_100,
        )
        .unwrap();
    assert_eq!(first.revision, 1);
    assert_eq!(second.revision, 2);
    assert_eq!(second.previous_deployment_id, Some(first.deployment_id));

    store
        .update_fleet_deployment(
            &second.deployment_id,
            "rolled_back",
            r#"{"node-a":"rolled_back","node-b":"rolled_back"}"#,
            Some(1_200),
        )
        .unwrap();
    let deployments = store.list_fleet_deployments().unwrap();
    assert_eq!(deployments.len(), 2);
    assert_eq!(deployments[0].status, "rolled_back");
    assert_eq!(deployments[0].rolled_back_at, Some(1_200));
    assert_eq!(
        store
            .fleet_deployment(&deployments[0].deployment_id)
            .unwrap()
            .unwrap()
            .image,
        "alpine:3.22"
    );
}

#[test]
fn invalid_deployment_json_and_status_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let store = ManagerStore::open(directory.path().join("manager.sqlite")).unwrap();
    assert!(store
        .begin_fleet_deployment("web", "alpine", "{}", "[]", None, 1)
        .is_err());
}
