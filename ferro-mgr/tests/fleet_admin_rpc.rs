#![cfg(target_os = "linux")]

use std::sync::Arc;

use ferro_mgr::{
    fleet::FleetCommandResult,
    pki::{CertificateIdentity, CertificateRole},
    proto::{
        admin_service_server::AdminService, FleetCommandRequest, FleetDeployRequest,
        FleetRevokeRequest, FleetRollbackRequest, FleetSnapshotRequest,
        IssueEnrollmentTokenRequest,
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
    let admin = AdminServiceImpl::new_authorized(store.clone(), 1, "cluster-a", control.clone());

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
    assert!(
        !admin
            .revoke_host(authenticated(FleetRevokeRequest {
                cluster_id: "cluster-a".into(),
                node_id: "node-a".into(),
                reason: "repeat".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .revoked
    );
}

#[tokio::test]
async fn desired_deploy_rolls_forward_and_back_over_the_control_stream() {
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
    let admin = AdminServiceImpl::new_authorized(store.clone(), 1, "cluster-a", control.clone());
    let hub = control.fleet_hub();
    let mut connection = hub.connect("node-a").unwrap();
    let responder_hub = hub.clone();
    let responder = tokio::spawn(async move {
        for _ in 0..5 {
            let command = connection.receiver.recv().await.unwrap();
            responder_hub.complete(
                "node-a",
                FleetCommandResult {
                    request_id: command.request_id,
                    exit_code: 0,
                    stdout: "ok".into(),
                    stderr: String::new(),
                },
            );
        }
    });
    let first: Value = serde_json::from_str(
        &admin
            .fleet_deploy(authenticated(FleetDeployRequest {
                cluster_id: "cluster-a".into(),
                name: "fleet-web".into(),
                image: "alpine:3.21".into(),
                command: vec!["sh".into(), "-c".into(), "echo v1".into()],
                node_ids: vec!["node-a".into()],
            }))
            .await
            .unwrap()
            .into_inner()
            .deployment_json,
    )
    .unwrap();
    assert_eq!(first["status"], "succeeded");
    let second: Value = serde_json::from_str(
        &admin
            .fleet_deploy(authenticated(FleetDeployRequest {
                cluster_id: "cluster-a".into(),
                name: "fleet-web".into(),
                image: "alpine:3.22".into(),
                command: vec!["sh".into(), "-c".into(), "echo v2".into()],
                node_ids: vec!["node-a".into()],
            }))
            .await
            .unwrap()
            .into_inner()
            .deployment_json,
    )
    .unwrap();
    assert_eq!(second["previous_deployment_id"], first["deployment_id"]);
    let rolled_back: Value = serde_json::from_str(
        &admin
            .fleet_rollback(authenticated(FleetRollbackRequest {
                cluster_id: "cluster-a".into(),
                deployment_id: second["deployment_id"].as_str().unwrap().into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .deployment_json,
    )
    .unwrap();
    assert_eq!(rolled_back["status"], "rolled_back");
    responder.await.unwrap();
}

#[tokio::test]
async fn administrator_issues_a_scoped_short_lived_enrollment_token() {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(ManagerStore::open(directory.path().join("manager.sqlite")).unwrap());
    let control = Arc::new(ControlServiceImpl::new(
        "cluster-a",
        1,
        vec![9; 32],
        store.clone(),
    ));
    let admin = AdminServiceImpl::new_authorized(store.clone(), 1, "cluster-a", control);
    let response = admin
        .issue_enrollment_token(authenticated(IssueEnrollmentTokenRequest {
            cluster_id: "cluster-a".into(),
            node_id: "node-a".into(),
            endpoint: "192.0.2.1:50053".into(),
            overlay_scope: "fleet".into(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(response.expires_at > 0);
    ferro_mgr::enrollment::EnrollmentService::new("cluster-a", store)
        .enroll(
            &response.enrollment_token,
            Enrollment {
                node_id: "node-a".into(),
                public_key: vec![7; 32],
                endpoint: "192.0.2.1:50053".into(),
            },
        )
        .unwrap();
}
