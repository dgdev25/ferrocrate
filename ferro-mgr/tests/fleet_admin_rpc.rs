#![cfg(target_os = "linux")]

use std::sync::Arc;

use ferro_mgr::{
    fleet::FleetCommandResult,
    pki::{CertificateIdentity, CertificateRole},
    proto::{
        admin_service_server::AdminService, FleetCommandRequest, FleetRevokeRequest,
        FleetSnapshotRequest,
    },
    rpc::{AdminServiceImpl, ControlServiceImpl},
    store::{Enrollment, HostObservation, ManagerStore},
};
use serde_json::{json, Value};
use tonic::Request;

fn authenticated<T>(message: T) -> Request<T> {
    let mut request = Request::new(message);
    request.extensions_mut().insert(CertificateIdentity {
        cluster_id: "cluster-a".into(),
        role: CertificateRole::Administrator,
        expires_at: i64::MAX,
    });
    request
}

#[tokio::test]
async fn existing_admin_service_lists_hosts_and_relays_commands() {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(ManagerStore::open(directory.path().join("manager.sqlite")).unwrap());
    store
        .register_node(Enrollment {
            node_id: "node-a".into(),
            public_key: vec![1; 32],
            endpoint: "127.0.0.1:50053".into(),
        })
        .unwrap();
    store
        .record_host_observation(HostObservation {
            node_id: "node-a".into(),
            last_seen_unix: 1_000,
            version: "0.1.0".into(),
            health: "healthy".into(),
            doctor_summary: "clear".into(),
            containers_json: "[]".into(),
            acknowledged_revision: 4,
        })
        .unwrap();
    let control = Arc::new(ControlServiceImpl::new(
        "cluster-a",
        1,
        vec![9; 32],
        store.clone(),
    ));
    let admin = AdminServiceImpl::new_authorized(
        store.clone(),
        1,
        "cluster-a",
        control.clone(),
    );

    let snapshot = admin
        .fleet_snapshot(authenticated(FleetSnapshotRequest {
            cluster_id: "cluster-a".into(),
        }))
        .await
        .unwrap()
        .into_inner();
    let snapshot: Value = serde_json::from_str(&snapshot.snapshot_json).unwrap();
    assert_eq!(snapshot["hosts"][0]["node_id"], "node-a");
    assert_eq!(snapshot["hosts"][0]["connected"], false);

    let hub = control.fleet_hub();
    let mut connection = hub.connect("node-a").unwrap();
    let responder_hub = hub.clone();
    let responder = tokio::spawn(async move {
        let command = connection.receiver.recv().await.unwrap();
        responder_hub.complete(
            "node-a",
            FleetCommandResult {
                request_id: command.request_id,
                exit_code: 0,
                stdout: "[]".into(),
                stderr: String::new(),
            },
        );
    });
    let response = admin
        .fleet_command(authenticated(FleetCommandRequest {
            cluster_id: "cluster-a".into(),
            node_id: "node-a".into(),
            action: "list_containers".into(),
            arguments_json: json!({}).to_string(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.exit_code, 0);
    assert_eq!(response.stdout, "[]");
    responder.await.unwrap();
}

#[tokio::test]
async fn admin_revocation_is_idempotent_and_visible_in_snapshot() {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(ManagerStore::open(directory.path().join("manager.sqlite")).unwrap());
    store
        .register_node(Enrollment {
            node_id: "node-a".into(),
            public_key: vec![1; 32],
            endpoint: "127.0.0.1:50053".into(),
        })
        .unwrap();
    let control = Arc::new(ControlServiceImpl::new(
        "cluster-a",
        1,
        vec![9; 32],
        store.clone(),
    ));
    let admin = AdminServiceImpl::new_authorized(store.clone(), 1, "cluster-a", control);
    let response = admin
        .revoke_host(authenticated(FleetRevokeRequest {
            cluster_id: "cluster-a".into(),
            node_id: "node-a".into(),
            reason: "qualification".into(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(response.revoked);
    assert!(!admin
        .revoke_host(authenticated(FleetRevokeRequest {
            cluster_id: "cluster-a".into(),
            node_id: "node-a".into(),
            reason: "repeat".into(),
        }))
        .await
        .unwrap()
        .into_inner()
        .revoked);
}
