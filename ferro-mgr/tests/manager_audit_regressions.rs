#![cfg(target_os = "linux")]
use ed25519_dalek::SigningKey;
use ferro_core::authorization::helper_grant::{GrantIssuer, ResourceBinding};
use ferro_mgr::{
    controller_authorization::{ControllerGrantIssuer, ControllerPolicy},
    pki::{CertificateIdentity, CertificateRole},
    proto::{
        control_service_client::ControlServiceClient, control_service_server::ControlServiceServer,
        AgentMessage, OverlayState,
    },
    rpc::ControlServiceImpl,
    store::{Enrollment, ManagerStore, Overlay},
};
use std::{os::unix::fs::PermissionsExt, sync::Arc, time::Duration};
use tokio_stream::wrappers::ReceiverStream;

fn fixture() -> (tempfile::TempDir, Arc<ManagerStore>, ControlServiceImpl) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(ManagerStore::open(dir.path().join("store.sqlite")).unwrap());
    for node in ["node-a", "node-b"] {
        store
            .register_node(Enrollment {
                node_id: node.into(),
                public_key: vec![node.as_bytes()[5]; 32],
                endpoint: format!("{node}:51820"),
            })
            .unwrap();
    }
    store
        .create_overlay(Overlay {
            id: "wg0".into(),
            cidr: "10.20.0.0/24".into(),
        })
        .unwrap();
    let key = dir.path().join("controller.key");
    std::fs::write(&key, [7; 32]).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let issuer = ControllerGrantIssuer::new(
        GrantIssuer::from_key_file("controller-1", &key, nix::unistd::Uid::effective().as_raw())
            .unwrap(),
        SigningKey::from_bytes(&[8; 32]),
        "controller",
        "boot-a",
        ControllerPolicy::new(
            ["node-a".into(), "node-b".into()],
            [(
                "wg0".into(),
                ResourceBinding::new("123e4567-e89b-12d3-a456-426614174000", 7).unwrap(),
            )],
        ),
    );
    let service =
        ControlServiceImpl::new_authorized("cluster-a", 1, vec![9; 32], store.clone(), issuer);
    (dir, store, service)
}
fn overlays() -> Vec<OverlayState> {
    vec![OverlayState {
        overlay_id: "wg0".into(),
        routes: vec![],
        peers: vec![],
        wireguard: Some(true),
        addresses: vec!["10.20.0.1/24".into()],
    }]
}
async fn connect(
    service: ControlServiceImpl,
) -> (
    tokio::task::JoinHandle<()>,
    ControlServiceClient<tonic::transport::Channel>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(ControlServiceServer::with_interceptor(
                service,
                |mut request: tonic::Request<()>| {
                    request.extensions_mut().insert(CertificateIdentity {
                        cluster_id: "cluster-a".into(),
                        role: CertificateRole::Node {
                            node_id: "node-a".into(),
                        },
                        expires_at: i64::MAX,
                    });
                    Ok(request)
                },
            ))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });
    let client = ControlServiceClient::connect(format!("http://{address}"))
        .await
        .unwrap();
    (server, client)
}
async fn reply(
    client: &mut ControlServiceClient<tonic::transport::Channel>,
    ack: u64,
) -> ferro_mgr::proto::ManagerMessage {
    let (tx, rx) = tokio::sync::mpsc::channel(2);
    let mut stream = client
        .control_stream(ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    tx.send(AgentMessage {
        node_id: "node-a".into(),
        acknowledged_revision: ack,
        payload: vec![],
    })
    .await
    .unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(3), stream.message())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    drop(tx);
    while stream.message().await.unwrap().is_some() {}
    reply
}
#[tokio::test]
async fn persisted_per_node_ack_survives_reconnect_and_rejects_other_nodes_revision() {
    let (_dir, _store, service) = fixture();
    let now = ferro_mgr::pki::unix_now();
    service
        .publish_desired("node-a", overlays(), &[], now, 0)
        .unwrap();
    let revision = service
        .publish_desired("node-a", overlays(), &[], now, 0)
        .unwrap();
    let other = service
        .publish_desired("node-b", overlays(), &[], now, 0)
        .unwrap();
    let (server, mut client) = connect(service).await;
    for _ in 0..2 {
        let response = reply(&mut client, revision).await;
        assert!(response.error.is_empty(), "{}", response.error);
        assert_eq!(response.desired_state.unwrap().revision, revision);
    }
    assert!(reply(&mut client, other).await.error.contains("ahead"));
    server.abort();
}
#[tokio::test]
async fn expired_published_state_is_renewed_with_fresh_authorization() {
    let (_dir, store, service) = fixture();
    let now = ferro_mgr::pki::unix_now();
    let old = service
        .publish_desired("node-a", overlays(), &[], now - 901, 0)
        .unwrap();
    let (_, old_payload, old_bundle) = store.latest_authorized_revision("node-a").unwrap().unwrap();
    let (server, mut client) = connect(service).await;
    let response = reply(&mut client, old).await;
    assert!(response.error.is_empty(), "{}", response.error);
    let desired = response.desired_state.unwrap();
    assert!(
        desired.lease_expires_unix > now,
        "healthy connection replayed expired lease"
    );
    assert!(desired.revision > old);
    assert_eq!(desired.overlays, overlays());
    let bundle =
        ferro_mgr::agent::desired_authorization::DesiredAuthorizationBundle::decode_and_verify(
            &response.desired_authorization_bundle,
            &desired,
            &SigningKey::from_bytes(&[9; 32]).verifying_key(),
            now,
        )
        .unwrap();
    bundle
        .validate_transition(&desired, &["wg0".into()])
        .unwrap();
    assert_ne!(response.desired_authorization_bundle, old_bundle);
    use prost::Message;
    assert_ne!(desired.encode_to_vec(), old_payload);
    let (_, persisted, persisted_bundle) =
        store.latest_authorized_revision("node-a").unwrap().unwrap();
    assert_eq!(persisted, desired.encode_to_vec());
    assert_eq!(persisted_bundle, response.desired_authorization_bundle);
    server.abort();
}

struct CheckedNetd {
    policy: std::sync::Mutex<ferro_netd::policy::Policy>,
    now: Arc<std::sync::atomic::AtomicU64>,
    nonces: std::sync::Mutex<std::collections::HashSet<[u8; 16]>>,
}
impl ferro_mgr::agent::NetdClient for CheckedNetd {
    fn apply(&self, _: &ferro_mgr::proto::DesiredState) -> Result<(), String> {
        Err("authorization required".into())
    }
    fn apply_authorized(
        &self,
        _: &ferro_mgr::proto::DesiredState,
        bundle: &ferro_mgr::agent::desired_authorization::DesiredAuthorizationBundle,
    ) -> Result<(), String> {
        use base64::Engine;
        use ed25519_dalek::Verifier;
        let now = self.now.load(std::sync::atomic::Ordering::SeqCst);
        for operation in &bundle.operations {
            let envelope =
                serde_json::from_value(serde_json::to_value(&operation.envelope).unwrap()).unwrap();
            self.policy
                .lock()
                .unwrap()
                .validate(&envelope, now)
                .map_err(|e| format!("{e:?}"))?;
            let signature = base64::engine::general_purpose::STANDARD
                .decode(&operation.grant.signature)
                .unwrap();
            SigningKey::from_bytes(&[7; 32])
                .verifying_key()
                .verify(
                    &ferro_core::authorization::helper_grant::signing_bytes(
                        &operation.grant.claims,
                    ),
                    &ed25519_dalek::Signature::from_slice(&signature).unwrap(),
                )
                .unwrap();
            assert!(operation.grant.claims.wall_deadline_secs > now);
            assert!(operation.grant.claims.monotonic_deadline_millis > (now - 100) * 1000);
            assert!(self
                .nonces
                .lock()
                .unwrap()
                .insert(operation.grant.claims.nonce));
            assert_eq!(operation.resource_generation, 7);
            assert_eq!(
                operation.resource_uuid,
                "123e4567-e89b-12d3-a456-426614174000"
            );
            assert_ne!(operation.grant.claims.precondition_digest, [0; 32]);
            assert_ne!(operation.grant.claims.recovery_recipe_digest, [0; 32]);
        }
        Ok(())
    }
}
#[test]
fn unchanged_configuration_reconciles_through_multiple_original_lease_expiries() {
    use base64::Engine;
    use ferro_mgr::agent::{
        netd_sequence::{NetdSequence, SequenceValue},
        Agent, StateStore,
    };
    let (dir, _store, service) = fixture();
    let mut ack = service
        .publish_desired("node-a", overlays(), &[], 100, 0)
        .unwrap();
    let clock = Arc::new(std::sync::atomic::AtomicU64::new(100));
    let agent = Agent::new_enforcing(
        "cluster-a",
        SigningKey::from_bytes(&[9; 32])
            .verifying_key()
            .to_bytes()
            .to_vec(),
        StateStore::new(dir.path().join("agent.json")),
        CheckedNetd {
            policy: std::sync::Mutex::new(
                ferro_netd::policy::Policy::new(
                    "cluster-a".into(),
                    "node-a".into(),
                    &base64::engine::general_purpose::STANDARD
                        .encode(SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes()),
                )
                .unwrap(),
            ),
            now: clock.clone(),
            nonces: std::sync::Mutex::new(Default::default()),
        },
    )
    .unwrap()
    .with_netd_sequence(
        NetdSequence::open(
            dir.path().join("sequence.json"),
            SequenceValue {
                epoch: 0,
                revision: 0,
            },
        )
        .unwrap(),
    )
    .with_netd_envelope_signer(SigningKey::from_bytes(&[8; 32]));
    let (initial, bundle) = service.desired_reply("node-a", 0, 100, 0).unwrap();
    agent
        .reconcile_with_bundle(initial.clone(), &bundle, 100)
        .unwrap();
    for now in (550..=2350).step_by(450) {
        clock.store(now, std::sync::atomic::Ordering::SeqCst);
        let (state, bundle) = service
            .desired_reply("node-a", ack, now as i64, (now - 100) * 1000)
            .unwrap();
        assert!(state.revision > ack);
        assert_eq!(state.overlays, initial.overlays);
        assert_eq!(state.lease_expires_unix, now as i64 + 900);
        ack = agent
            .reconcile_with_bundle(state, &bundle, now as i64)
            .unwrap();
    }
    assert!(agent.state().lease_expiry > initial.lease_expires_unix + 900);
    assert!(agent.reconcile_with_bundle(initial, &bundle, 2350).is_err());
}

#[test]
fn renewal_preserves_pending_deletions_then_renews_empty_state() {
    use ferro_mgr::agent::desired_authorization::DesiredAuthorizationBundle;
    let (_dir, _store, service) = fixture();
    let first = service
        .publish_desired("node-a", overlays(), &[], 100, 0)
        .unwrap();
    service
        .publish_desired("node-a", vec![], &[], 110, 10_000)
        .unwrap();
    let (pending, encoded) = service.desired_reply("node-a", first, 150, 50_000).unwrap();
    let bundle: DesiredAuthorizationBundle = serde_json::from_slice(&encoded).unwrap();
    bundle
        .validate_transition(&pending, &["wg0".into()])
        .unwrap();
    assert_eq!(bundle.operations.len(), 1);
    let (empty, encoded) = service
        .desired_reply("node-a", pending.revision, 600, 500_000)
        .unwrap();
    let bundle: DesiredAuthorizationBundle = serde_json::from_slice(&encoded).unwrap();
    bundle.validate_transition(&empty, &[]).unwrap();
    assert!(bundle.operations.is_empty());
}

#[test]
fn renewal_fails_closed_after_revocation_or_without_current_controller_authority() {
    let (dir, store, service) = fixture();
    let revision = service
        .publish_desired("node-a", overlays(), &[], 100, 0)
        .unwrap();
    let no_controller = ControlServiceImpl::new("cluster-a", 1, vec![9; 32], store.clone());
    assert!(no_controller
        .desired_reply("node-a", revision, 550, 450_000)
        .is_err());
    let denied = ControlServiceImpl::new_authorized(
        "cluster-a",
        1,
        vec![9; 32],
        store.clone(),
        ControllerGrantIssuer::new(
            GrantIssuer::from_key_file(
                "controller-1",
                &dir.path().join("controller.key"),
                nix::unistd::Uid::effective().as_raw(),
            )
            .unwrap(),
            SigningKey::from_bytes(&[8; 32]),
            "controller",
            "boot-a",
            ControllerPolicy::new(["node-a".into()], []),
        ),
    );
    assert!(denied
        .desired_reply("node-a", revision, 550, 450_000)
        .is_err());
    assert_eq!(
        store
            .latest_authorized_revision("node-a")
            .unwrap()
            .unwrap()
            .0,
        revision
    );
    store.revoke_node("node-a", "test").unwrap();
    assert!(service
        .desired_reply("node-a", revision, 550, 450_000)
        .is_err());
    assert_eq!(
        store
            .latest_authorized_revision("node-a")
            .unwrap()
            .unwrap()
            .0,
        revision
    );
}

#[test]
fn renewal_does_not_reauthorize_persisted_state_from_another_epoch() {
    use prost::Message;
    let (_dir, store, service) = fixture();
    let wrong = ferro_mgr::desired_state::DesiredStateBuilder::new("cluster-a", 2, vec![9; 32])
        .snapshot(1, overlays(), 100);
    store
        .append_authorized_revision_at(1, "wg0", "node-a", &wrong.encode_to_vec(), &[])
        .unwrap();
    assert!(service.desired_reply("node-a", 1, 130, 30_000).is_err());
    assert_eq!(
        store
            .latest_authorized_revision("node-a")
            .unwrap()
            .unwrap()
            .0,
        1
    );
}

#[test]
fn acknowledged_lease_renews_at_half_life_but_pending_grants_refresh_early() {
    let (_dir, _store, service) = fixture();
    let first = service
        .publish_desired("node-a", overlays(), &[], 100, 0)
        .unwrap();
    assert_eq!(
        service
            .desired_reply("node-a", first, 130, 30_000)
            .unwrap()
            .0
            .revision,
        first
    );
    let pending = service.desired_reply("node-a", 0, 130, 30_000).unwrap().0;
    assert!(pending.revision > first);
    assert!(
        service
            .desired_reply("node-a", pending.revision, 580, 480_000)
            .unwrap()
            .0
            .revision
            > pending.revision
    );
}
