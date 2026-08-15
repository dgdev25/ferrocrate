#![cfg(unix)]

use std::{
    fs,
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixStream},
    sync::{Arc, Mutex},
    time::Duration,
};

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use ferro_core::{
    authorization::helper_grant::{
        signing_bytes, GrantAction, GrantClaims, GrantIssuer, GrantKind, HelperGrant,
        ResourceBinding,
    },
    managed_overlay::{
        managed_parameters, DelegatedManagedOverlayRequest, LegacyManagedOverlayRequest,
        ManagedOverlayCompatibilityMode, ManagedOverlayDelegation, ManagedOverlayRequest,
        MANAGED_OVERLAY_PROTOCOL_VERSION,
    },
};
use ferro_mgr::{
    agent::{
        delegation_ledger::DelegationLedger,
        ipam::Ipam,
        local_api::{LocalApi, LocalApiResponse, OverlayConfig},
        netd_client::{endpoint_live_identity_digest, DelegationBridge, UnixNetdClient},
        netd_sequence::{NetdSequence, SequenceValue},
        Agent, StateStore,
    },
    controller_authorization::{ControllerGrantIssuer, ControllerPolicy},
    desired_state::DesiredStateBuilder,
    proto::OverlayState,
};
use ferro_netd::{
    grants::{GrantLedger, GrantVerifier},
    policy::Policy,
    server::NetdServer,
    test_support::{serve_one, FaultHandle, FaultPoint},
};

const RESOURCE: &str = "123e4567-e89b-12d3-a456-426614174000";

#[test]
fn enforcing_controller_agent_and_local_api_attach_cleanup_replay_and_bypass() {
    let directory = tempfile::tempdir().unwrap();
    let uid = nix::unistd::geteuid().as_raw();
    let helper_key = SigningKey::from_bytes(&[8; 32]);
    let envelope_key = SigningKey::from_bytes(&[7; 32]);
    let desired_key = SigningKey::from_bytes(&[4; 32]);
    let key_path = directory.path().join("helper.key");
    fs::write(&key_path, helper_key.to_bytes()).unwrap();
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();

    let policy = Policy::new(
        "cluster-a".into(),
        "node-a".into(),
        &base64::engine::general_purpose::STANDARD.encode(envelope_key.verifying_key().to_bytes()),
    )
    .unwrap();
    let verifier = GrantVerifier::new(
        helper_key.verifying_key(),
        "runtime",
        "key-1",
        "boot-a",
        GrantLedger::open(directory.path().join("netd-grants.json")).unwrap(),
    );
    let faults = FaultHandle::default();
    let server = NetdServer::deterministic_with_faults(
        uid,
        policy,
        directory.path().join("kernel.json"),
        faults.clone(),
    )
    .with_grants(verifier)
    .load_journal(directory.path().join("netd-state.json"))
    .unwrap();
    let server = Arc::new(Mutex::new(server));
    let netd_socket = directory.path().join("netd.sock");
    let listener = std::os::unix::net::UnixListener::bind(&netd_socket).unwrap();

    let resource = ResourceBinding::new(RESOURCE, 7).unwrap();
    let builder = DesiredStateBuilder::new("cluster-a", 2, vec![4; 32]);
    let desired = builder.snapshot(
        1,
        vec![OverlayState {
            overlay_id: "wg0".into(),
            routes: vec![],
            peers: vec![],
        }],
        100,
    );
    let controller = ControllerGrantIssuer::new(
        issuer(&key_path, uid),
        envelope_key.clone(),
        "runtime",
        "boot-a",
        ControllerPolicy::new(["node-a".into()], [("wg0".into(), resource.clone())]),
    );
    let operations = controller
        .issue_exact_diff(&desired, "node-a", &[], u64::MAX - 60_000)
        .unwrap();
    let bundle = builder
        .authorization_bundle(&desired, "node-a", operations)
        .unwrap();
    let sequence = NetdSequence::open(
        directory.path().join("sequence.json"),
        SequenceValue {
            epoch: 0,
            revision: 0,
        },
    )
    .unwrap();
    serve_next(listener.try_clone().unwrap(), server.clone(), uid, 101);
    let agent = Agent::new_enforcing(
        "cluster-a",
        desired_key.verifying_key().to_bytes().to_vec(),
        StateStore::new(directory.path().join("agent-state.json")),
        UnixNetdClient::new(&netd_socket).with_node_id("node-a"),
    )
    .unwrap()
    .with_netd_sequence(sequence.clone());
    assert_eq!(
        agent.reconcile_with_bundle(desired, &bundle, 101).unwrap(),
        1
    );
    assert_eq!(
        sequence.current().unwrap(),
        SequenceValue {
            epoch: 2,
            revision: 1
        }
    );

    let ledger_path = directory.path().join("manager-delegations.json");
    let local = LocalApi::new(
        uid,
        1_000,
        Ipam::with_state(
            "10.20.0.0/29".parse().unwrap(),
            "10.20.0.1".parse().unwrap(),
            vec![],
            directory.path().join("ipam.json"),
        )
        .unwrap(),
    )
    .with_delegation_ledger(
        DelegationBridge::new(
            helper_key.verifying_key(),
            "runtime",
            "key-1",
            "boot-a",
            issuer(&key_path, uid),
            envelope_key,
            "cluster-a",
            "node-a",
        )
        .with_sequence(sequence.clone()),
        UnixNetdClient::new(&netd_socket).with_node_id("node-a"),
        DelegationLedger::open(ledger_path.clone()).unwrap(),
    );
    local
        .register_overlay(
            "wg0",
            OverlayConfig {
                bridge: "wg0".into(),
                gateway: "10.20.0.1".parse().unwrap(),
                prefix: 29,
                mtu: 1400,
            },
        )
        .unwrap();
    let local_socket = directory.path().join("manager.sock");
    let local = Arc::new(local);
    let serving = local.clone();
    let socket = local_socket.clone();
    std::thread::spawn(move || serving.serve_unix(socket).unwrap());
    wait_for_socket(&local_socket);

    let attach_request = ManagedOverlayRequest::AttachContainer {
        overlay_id: "wg0".into(),
        container_id: "container-a".into(),
        now_unix: 100,
    };
    let attach = delegated(
        &helper_key,
        attach_request,
        "attach-parent",
        [1; 16],
        false,
        None,
    );
    serve_next(listener.try_clone().unwrap(), server.clone(), uid, 101);
    assert!(matches!(
        send(&local_socket, &attach),
        LocalApiResponse::Attached(_)
    ));

    let persisted: serde_json::Value =
        serde_json::from_slice(&fs::read(&ledger_path).unwrap()).unwrap();
    let provenance = &persisted["claims"][0][1]["Completed"]["provenance"];
    let origin = provenance["origin_request_id"].as_str().unwrap().to_owned();
    assert_eq!(provenance["container_id"], "container-a");
    assert_eq!(sequence.current().unwrap().revision, 2);
    {
        let snapshot = server.lock().unwrap().test_snapshot();
        assert_eq!(snapshot.endpoints.get("container-a"), Some(&"wg0".into()));
        assert_eq!(snapshot.receipts.len(), 2);
        assert_ne!(snapshot.receipts[0].nonce, snapshot.receipts[1].nonce);
    }

    let detach_request = ManagedOverlayRequest::DetachContainer {
        overlay_id: "wg0".into(),
        container_id: "container-a".into(),
        now_unix: 100,
    };
    let detach = delegated(
        &helper_key,
        detach_request,
        "detach-parent",
        [2; 16],
        true,
        Some(origin),
    );
    serve_next(listener.try_clone().unwrap(), server.clone(), uid, 101);
    let response = send(&local_socket, &detach);
    assert_eq!(response, LocalApiResponse::Detached { released: true });
    let receipt_count = server.lock().unwrap().test_snapshot().receipts.len();
    assert_eq!(receipt_count, 3);
    assert!(server.lock().unwrap().test_snapshot().endpoints.is_empty());
    assert_eq!(sequence.current().unwrap().revision, 3);

    // Exact parent replay is answered from the manager ledger without minting or calling netd.
    assert_eq!(send(&local_socket, &detach), response);
    assert_eq!(
        server.lock().unwrap().test_snapshot().receipts.len(),
        receipt_count
    );
    assert_eq!(sequence.current().unwrap().revision, 3);

    let bypass = LegacyManagedOverlayRequest {
        schema_version: MANAGED_OVERLAY_PROTOCOL_VERSION,
        mode: ManagedOverlayCompatibilityMode::Disabled,
        request: ManagedOverlayRequest::InspectOverlay {
            overlay_id: "wg0".into(),
            now_unix: 100,
        },
    };
    assert!(matches!(
        send(&local_socket, &bypass),
        LocalApiResponse::Rejected { .. }
    ));

    // A failure between kernel effect and ownership persistence is witnessed and never
    // leaves an endpoint that a retry could silently adopt.
    let ambiguous_request = ManagedOverlayRequest::AttachContainer {
        overlay_id: "wg0".into(),
        container_id: "container-b".into(),
        now_unix: 100,
    };
    let ambiguous = delegated(
        &helper_key,
        ambiguous_request,
        "ambiguous-parent",
        [3; 16],
        false,
        None,
    );
    faults.fail_once(FaultPoint::StatePersist);
    serve_next(listener, server.clone(), uid, 101);
    assert!(matches!(
        send(&local_socket, &ambiguous),
        LocalApiResponse::Rejected { .. }
    ));
    let snapshot = server.lock().unwrap().test_snapshot();
    assert!(!snapshot.endpoints.contains_key("container-b"));
    let failure = snapshot
        .receipts
        .iter()
        .find(|receipt| receipt.phase == "failed")
        .expect("failed effect must have a durable receipt");
    assert_eq!(
        failure.outcome.as_deref(),
        Some("failed to persist endpoint ownership")
    );
}

#[test]
fn disabled_mode_requires_the_authenticated_versioned_negotiation_frame() {
    let directory = tempfile::tempdir().unwrap();
    let uid = nix::unistd::geteuid().as_raw();
    let local = Arc::new(LocalApi::new(
        uid,
        1_000,
        Ipam::new(
            "10.21.0.0/29".parse().unwrap(),
            "10.21.0.1".parse().unwrap(),
            vec![],
        )
        .unwrap(),
    ));
    local
        .register_overlay(
            "wg0",
            OverlayConfig {
                bridge: "wg0".into(),
                gateway: "10.21.0.1".parse().unwrap(),
                prefix: 29,
                mtu: 1400,
            },
        )
        .unwrap();
    let socket = directory.path().join("disabled.sock");
    let serving = local.clone();
    let serving_socket = socket.clone();
    std::thread::spawn(move || serving.serve_unix(serving_socket).unwrap());
    wait_for_socket(&socket);

    let request = ManagedOverlayRequest::InspectOverlay {
        overlay_id: "wg0".into(),
        now_unix: 100,
    };
    assert!(matches!(
        send(
            &socket,
            &LegacyManagedOverlayRequest {
                schema_version: MANAGED_OVERLAY_PROTOCOL_VERSION,
                mode: ManagedOverlayCompatibilityMode::Disabled,
                request: request.clone(),
            }
        ),
        LocalApiResponse::Overlay { .. }
    ));
    assert!(matches!(
        send(&socket, &request),
        LocalApiResponse::Rejected { .. }
    ));
}

fn issuer(path: &std::path::Path, uid: u32) -> GrantIssuer {
    GrantIssuer::from_key_file("key-1", path, uid).unwrap()
}

fn delegated(
    key: &SigningKey,
    request: ManagedOverlayRequest,
    request_id: &str,
    nonce: [u8; 16],
    cleanup: bool,
    origin: Option<String>,
) -> DelegatedManagedOverlayRequest {
    let digest = managed_parameters(&request).unwrap().digest();
    let claims = GrantClaims {
        schema_version: 1,
        request_id: request_id.into(),
        action: if cleanup {
            GrantAction::NetworkDetach
        } else {
            GrantAction::NetworkAttach
        },
        resource: ResourceBinding::new(RESOURCE, 7).unwrap(),
        parameter_digest: digest,
        boot_id: "boot-a".into(),
        wall_deadline_secs: 1_000,
        monotonic_deadline_millis: u64::MAX,
        nonce,
        operation_id: nonce,
        request_digest: digest,
        precondition_digest: digest,
        recovery_recipe_digest: digest,
        issuer: "runtime".into(),
        key_id: "key-1".into(),
        kind: if cleanup {
            GrantKind::Cleanup
        } else {
            GrantKind::Mutation
        },
        origin_request_id: origin,
        live_identity_digest: cleanup.then(|| endpoint_live_identity_digest("container-a")),
    };
    let signature = key.sign(&signing_bytes(&claims));
    let grant = HelperGrant {
        claims,
        signature: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
    };
    DelegatedManagedOverlayRequest {
        request,
        delegation: ManagedOverlayDelegation::new(grant),
    }
}

fn serve_next(
    listener: std::os::unix::net::UnixListener,
    server: Arc<Mutex<NetdServer>>,
    uid: u32,
    now: u64,
) {
    std::thread::spawn(move || {
        serve_one(&listener, &mut server.lock().unwrap(), uid, now).unwrap()
    });
}

fn wait_for_socket(path: &std::path::Path) {
    for _ in 0..100 {
        if path.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("local API socket was not created");
}

fn send<T: serde::Serialize>(path: &std::path::Path, request: &T) -> LocalApiResponse {
    let mut stream = UnixStream::connect(path).unwrap();
    let body = serde_json::to_vec(request).unwrap();
    stream
        .write_all(&(body.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(&body).unwrap();
    let mut prefix = [0; 4];
    stream.read_exact(&mut prefix).unwrap();
    let mut body = vec![0; u32::from_be_bytes(prefix) as usize];
    stream.read_exact(&mut body).unwrap();
    serde_json::from_slice(&body).unwrap()
}
