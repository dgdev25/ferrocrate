#![cfg(unix)]

use std::{
    fs,
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixStream},
    sync::{Arc, Mutex},
    time::Duration,
};

use base64::Engine;
use ed25519_dalek::SigningKey;
use ferro_core::{
    authorization::helper_grant::{GrantIssuer, ResourceBinding},
    authorization::{
        gate::AuthorizationGate,
        policy::PolicyStore,
        test_support::{authorize_attach, authorize_cleanup},
    },
    managed_overlay::{
        LegacyManagedOverlayRequest, ManagedOverlayClient, ManagedOverlayCompatibilityMode,
        ManagedOverlayRequest, ManagedOverlayResponse, MANAGED_OVERLAY_PROTOCOL_VERSION,
    },
    witness::{JournalConfig, JournalMode, WitnessJournal},
};
use ferro_mgr::{
    agent::{
        delegation_ledger::DelegationLedger,
        ipam::Ipam,
        local_api::{LocalApi, LocalApiResponse, OverlayConfig},
        netd_client::{DelegationBridge, UnixNetdClient},
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

const RESOURCE: &str = "9e0c6a49-e01e-3e51-9a4f-5bb9663075b4";

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
    let policy_path = directory.path().join("runtime-policy.toml");
    fs::write(
        &policy_path,
        "schema_version = 1\ngeneration = 1\nmode = \"shadow\"\n",
    )
    .unwrap();
    fs::set_permissions(&policy_path, fs::Permissions::from_mode(0o600)).unwrap();
    let gate = Arc::new(AuthorizationGate::new(Arc::new(
        PolicyStore::load(&policy_path).unwrap(),
    )));
    let journal = Arc::new(
        WitnessJournal::open(JournalConfig::new(
            directory.path().join("witness"),
            [70; 16],
            JournalMode::Required,
        ))
        .unwrap(),
    );

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
    let sequence_path = directory.path().join("sequence.json");
    let sequence = NetdSequence::open(
        sequence_path.clone(),
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
        agent
            .reconcile_with_bundle(desired.clone(), &bundle, 101)
            .unwrap(),
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
    .with_runtime_executable(std::env::current_exe().unwrap())
    .with_delegation_ledger(
        DelegationBridge::new(
            helper_key.verifying_key(),
            "runtime",
            "key-1",
            "boot-a",
            issuer(&key_path, uid),
            envelope_key.clone(),
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
    let attach_authority =
        authorize_attach(gate.clone(), journal.clone(), "container-a", 7, "wg0").unwrap();
    serve_next(listener.try_clone().unwrap(), server.clone(), uid, 101);
    let client = ManagedOverlayClient::new(&local_socket);
    let (proof, intent) = attach_authority.parts();
    assert_eq!(
        proof.canonical().context().action(),
        ferro_core::authorization::Action::ContainerRun
    );
    assert_eq!(proof.canonical().resource_id(), RESOURCE);
    assert_ne!(proof.canonical().policy_digest(), &[0; 32]);
    let attach_response = client
        .request_authorized(
            &attach_request,
            proof,
            intent,
            &issuer(&key_path, uid),
            "boot-a",
            1_000,
            u64::MAX,
            [1; 16],
            "runtime",
        )
        .unwrap();
    let ManagedOverlayResponse::Attached(attachment) = attach_response else {
        panic!("attach rejected")
    };
    let cleanup_token = attachment
        .cleanup_provenance
        .expect("manager cleanup provenance");

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
    assert_eq!(cleanup_token.origin_request_id, origin);
    let cleanup_authority =
        authorize_cleanup(gate.clone(), journal.clone(), "container-a", 7).unwrap();
    serve_next(listener.try_clone().unwrap(), server.clone(), uid, 101);
    let (proof, intent) = cleanup_authority.parts();
    let response = client
        .request_cleanup_authorized(
            &detach_request,
            proof,
            intent,
            &cleanup_token,
            &issuer(&key_path, uid),
            "boot-a",
            1_000,
            u64::MAX,
            [2; 16],
            "runtime",
        )
        .unwrap();
    assert_eq!(
        response,
        ManagedOverlayResponse::Detached { released: true }
    );
    let receipt_count = server.lock().unwrap().test_snapshot().receipts.len();
    assert_eq!(receipt_count, 3);
    assert!(server.lock().unwrap().test_snapshot().endpoints.is_empty());
    assert_eq!(sequence.current().unwrap().revision, 3);

    // Exact parent replay is answered from the manager ledger without minting or calling netd.
    assert_eq!(
        client
            .request_cleanup_authorized(
                &detach_request,
                proof,
                intent,
                &cleanup_token,
                &issuer(&key_path, uid),
                "boot-a",
                1_000,
                u64::MAX,
                [2; 16],
                "runtime",
            )
            .unwrap(),
        response
    );
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

    // A second controller publication follows local child work in the same durable
    // revision domain, and another local mutation remains monotonic across restart.
    let desired2 = builder.snapshot(
        4,
        vec![OverlayState {
            overlay_id: "wg0".into(),
            routes: vec!["10.30.0.0/24".into()],
            peers: vec![],
        }],
        200,
    );
    let operations2 = controller
        .issue_exact_diff_from_state(&desired2, "node-a", Some(&desired), u64::MAX - 60_000)
        .unwrap();
    let bundle2 = builder
        .authorization_bundle(&desired2, "node-a", operations2)
        .unwrap();
    serve_next(listener.try_clone().unwrap(), server.clone(), uid, 201);
    assert_eq!(
        agent
            .reconcile_with_bundle(desired2, &bundle2, 201)
            .unwrap(),
        4
    );
    assert_eq!(sequence.current().unwrap().revision, 4);

    let attach2_request = ManagedOverlayRequest::AttachContainer {
        overlay_id: "wg0".into(),
        container_id: "container-c".into(),
        now_unix: 202,
    };
    let attach2 = authorize_attach(gate.clone(), journal.clone(), "container-c", 7, "wg0").unwrap();
    serve_next(listener.try_clone().unwrap(), server.clone(), uid, 203);
    let (proof, intent) = attach2.parts();
    assert!(matches!(
        client
            .request_authorized(
                &attach2_request,
                proof,
                intent,
                &issuer(&key_path, uid),
                "boot-a",
                1_000,
                u64::MAX,
                [4; 16],
                "runtime",
            )
            .unwrap(),
        ManagedOverlayResponse::Attached(_)
    ));
    assert_eq!(sequence.current().unwrap().revision, 5);
    let restarted = NetdSequence::open(
        sequence_path,
        SequenceValue {
            epoch: 2,
            revision: 0,
        },
    )
    .unwrap();
    assert_eq!(restarted.current().unwrap().revision, 5);
    assert_eq!(restarted.reserve_child().unwrap().revision, 6);

    // A failure between kernel effect and ownership persistence is witnessed and never
    // leaves an endpoint that a retry could silently adopt.
    let ambiguous_request = ManagedOverlayRequest::AttachContainer {
        overlay_id: "wg0".into(),
        container_id: "container-b".into(),
        now_unix: 100,
    };
    let ambiguous = authorize_attach(gate, journal, "container-b", 7, "wg0").unwrap();
    faults.fail_once(FaultPoint::StatePersist);
    serve_next(listener, server.clone(), uid, 101);
    let (proof, intent) = ambiguous.parts();
    assert!(matches!(
        client
            .request_authorized(
                &ambiguous_request,
                proof,
                intent,
                &issuer(&key_path, uid),
                "boot-a",
                1_000,
                u64::MAX,
                [3; 16],
                "runtime",
            )
            .unwrap(),
        ManagedOverlayResponse::Rejected { .. }
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
    let local = Arc::new(
        LocalApi::new(
            uid,
            1_000,
            Ipam::new(
                "10.21.0.0/29".parse().unwrap(),
                "10.21.0.1".parse().unwrap(),
                vec![],
            )
            .unwrap(),
        )
        .with_runtime_executable(std::env::current_exe().unwrap()),
    );
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

    let descriptor = fs::File::open("/dev/null").unwrap();
    let mut stream = UnixStream::connect(&socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    use std::os::fd::AsRawFd;
    let prefix = 0_u32.to_be_bytes();
    let iov = [std::io::IoSlice::new(&prefix)];
    let descriptors = [descriptor.as_raw_fd()];
    nix::sys::socket::sendmsg::<()>(
        stream.as_raw_fd(),
        &iov,
        &[nix::sys::socket::ControlMessage::ScmRights(&descriptors)],
        nix::sys::socket::MsgFlags::empty(),
        None,
    )
    .unwrap();
    let mut response = [0_u8; 1];
    assert_eq!(stream.read(&mut response).unwrap(), 0);
}

fn issuer(path: &std::path::Path, uid: u32) -> GrantIssuer {
    GrantIssuer::from_key_file("key-1", path, uid).unwrap()
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
