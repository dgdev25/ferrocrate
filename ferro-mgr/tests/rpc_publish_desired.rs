use std::{os::unix::fs::PermissionsExt, sync::Arc};

use ed25519_dalek::SigningKey;
use ferro_core::authorization::helper_grant::{GrantIssuer, ResourceBinding};
use ferro_mgr::{
    agent::desired_authorization::DesiredAuthorizationBundle,
    controller_authorization::{ControllerGrantIssuer, ControllerPolicy},
    pki::{CertificateIdentity, CertificateRole},
    proto::{
        admin_service_client::AdminServiceClient,
        admin_service_server::{AdminService, AdminServiceServer},
        DesiredState, OverlayState, PublishDesiredRequest,
    },
    rpc::{AdminServiceImpl, ControlServiceImpl},
    store::{Enrollment, ManagerStore, Overlay},
};
use prost::Message;
use tonic::{Code, Request};

const RESOURCE: &str = "123e4567-e89b-12d3-a456-426614174000";

#[tokio::test]
async fn authenticated_publish_authorizes_final_overlay_deletion_atomically() {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(ManagerStore::open(directory.path().join("manager.sqlite")).unwrap());
    store
        .register_node(Enrollment {
            node_id: "node-a".into(),
            public_key: vec![1; 32],
            endpoint: "198.51.100.1:51820".into(),
        })
        .unwrap();
    store
        .create_overlay(Overlay {
            id: "wg0".into(),
            cidr: "10.20.0.0/24".into(),
        })
        .unwrap();
    let key_path = directory.path().join("controller.key");
    std::fs::write(&key_path, [7_u8; 32]).unwrap();
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let issuer = ControllerGrantIssuer::new(
        GrantIssuer::from_key_file(
            "controller-1",
            &key_path,
            nix::unistd::Uid::effective().as_raw(),
        )
        .unwrap(),
        SigningKey::from_bytes(&[8; 32]),
        "controller",
        "boot-a",
        ControllerPolicy::new(
            ["node-a".into()],
            [("wg0".into(), ResourceBinding::new(RESOURCE, 7).unwrap())],
        ),
    );
    let control = Arc::new(ControlServiceImpl::new_authorized(
        "cluster-a",
        1,
        vec![9; 32],
        store.clone(),
        issuer,
    ));
    let admin = AdminServiceImpl::new_authorized(store.clone(), 1, "cluster-a", control);
    let address = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let server = tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(AdminServiceServer::with_interceptor(
                admin,
                |mut request: Request<()>| {
                    request.extensions_mut().insert(CertificateIdentity {
                        cluster_id: "cluster-a".into(),
                        role: CertificateRole::Administrator,
                        expires_at: i64::MAX,
                    });
                    Ok(request)
                },
            ))
            .serve(address),
    );
    let mut client = loop {
        match AdminServiceClient::connect(format!("http://{address}")).await {
            Ok(client) => break client,
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(5)).await,
        }
    };

    let first = client
        .publish_desired(PublishDesiredRequest {
            cluster_id: "cluster-a".into(),
            node_id: "node-a".into(),
            overlays: vec![OverlayState {
                overlay_id: "wg0".into(),
                routes: vec![],
                peers: vec![],
                wireguard: Some(true),
            }],
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(first.revision, 1);

    let deleted = client
        .publish_desired(PublishDesiredRequest {
            cluster_id: "cluster-a".into(),
            node_id: "node-a".into(),
            overlays: vec![],
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(deleted.revision, 2);
    let (_, payload, bundle) = store.latest_authorized_revision("node-a").unwrap().unwrap();
    assert!(DesiredState::decode(payload.as_slice())
        .unwrap()
        .overlays
        .is_empty());
    let bundle: DesiredAuthorizationBundle = serde_json::from_slice(&bundle).unwrap();
    assert_eq!(
        bundle.operations.len(),
        1,
        "final deletion needs one child grant"
    );
    server.abort();
}

#[tokio::test]
async fn node_principal_cannot_publish_desired_state() {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(ManagerStore::open(directory.path().join("manager.sqlite")).unwrap());
    let control = Arc::new(ControlServiceImpl::new(
        "cluster-a",
        1,
        vec![9; 32],
        store.clone(),
    ));
    let admin = AdminServiceImpl::new_authorized(store, 1, "cluster-a", control);
    let mut request = Request::new(PublishDesiredRequest {
        cluster_id: "cluster-a".into(),
        node_id: "node-a".into(),
        overlays: vec![],
    });
    request.extensions_mut().insert(CertificateIdentity {
        cluster_id: "cluster-a".into(),
        role: CertificateRole::Node {
            node_id: "node-a".into(),
        },
        expires_at: i64::MAX,
    });
    assert_eq!(
        admin.publish_desired(request).await.unwrap_err().code(),
        Code::PermissionDenied
    );
}
