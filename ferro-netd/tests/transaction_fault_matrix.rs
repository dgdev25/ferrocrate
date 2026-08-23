#![cfg(feature = "test-support")]

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use ferro_core::authorization::helper_grant::{
    signing_bytes, GrantAction, GrantClaims, GrantKind, HelperGrant, ResourceBinding,
};
use ferro_netd::{
    grants::{GrantLedger, GrantVerifier},
    policy::Policy,
    protocol::{
        GrantedEnvelope, NetdRequest, NetdResponse, OverlayMode, RejectionCode, ServiceHandshake,
        SignedEnvelope,
    },
    server::NetdServer,
    test_support::{normalized_request_parameters, FaultHandle, FaultPoint},
};
use sha2::{Digest, Sha256};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

const UUID: &str = "123e4567-e89b-12d3-a456-426614174000";

struct Keys {
    manager: SigningKey,
    helper: SigningKey,
}

fn open_server(root: &Path, keys: &Keys, faults: FaultHandle) -> NetdServer {
    let manager_public =
        base64::engine::general_purpose::STANDARD.encode(keys.manager.verifying_key().to_bytes());
    let verifier = GrantVerifier::new(
        keys.helper.verifying_key(),
        "runtime",
        "key-1",
        "boot-a",
        GrantLedger::open(root.join("grants.json")).unwrap(),
    );
    NetdServer::deterministic_with_faults(
        1001,
        Policy::new("cluster".into(), "node".into(), &manager_public).unwrap(),
        root.join("kernel.json"),
        faults,
    )
    .with_grants(verifier)
    .load_journal(root.join("ownership.json"))
    .unwrap()
}

fn frame(keys: &Keys, request: NetdRequest, revision: u64, origin: Option<&str>) -> Vec<u8> {
    let (action, parameters) = normalized_request_parameters(&request).unwrap();
    let request_id = format!("req-{revision}");
    let mut envelope = SignedEnvelope {
        cluster_id: "cluster".into(),
        node_id: "node".into(),
        epoch: 1,
        revision,
        lease_expires_unix_secs: 500,
        request,
        signature: String::new(),
    };
    envelope.signature = base64::engine::general_purpose::STANDARD.encode(
        keys.manager
            .sign(&serde_json::to_vec(&envelope).unwrap())
            .to_bytes(),
    );
    let mut nonce = [0; 16];
    nonce[..8].copy_from_slice(&revision.to_be_bytes());
    let mut operation_id = [1; 16];
    operation_id[..8].copy_from_slice(&revision.to_be_bytes());
    let cleanup = matches!(
        action,
        GrantAction::NetworkDelete | GrantAction::NetworkDetach
    );
    let result_identity = match action {
        GrantAction::NetworkDelete => "overlay:matrix-overlay",
        GrantAction::NetworkDetach => "endpoint:ep-a",
        _ => "",
    };
    let live_identity_digest = origin.map(|_| {
        Sha256::digest(
            [
                b"ferrocrate.helper-live-identity.v1\0".as_slice(),
                result_identity.as_bytes(),
            ]
            .concat(),
        )
        .into()
    });
    let claims = GrantClaims {
        schema_version: 1,
        request_id,
        action,
        resource: ResourceBinding::new(UUID, 7).unwrap(),
        parameter_digest: parameters.digest(),
        boot_id: "boot-a".into(),
        wall_deadline_secs: 500,
        monotonic_deadline_millis: u64::MAX,
        nonce,
        operation_id,
        request_digest: [5; 32],
        precondition_digest: [6; 32],
        recovery_recipe_digest: [7; 32],
        issuer: "runtime".into(),
        key_id: "key-1".into(),
        kind: if cleanup {
            GrantKind::Cleanup
        } else {
            GrantKind::Mutation
        },
        origin_request_id: origin.map(str::to_owned),
        live_identity_digest,
    };
    let grant = HelperGrant {
        signature: base64::engine::general_purpose::STANDARD
            .encode(keys.helper.sign(&signing_bytes(&claims)).to_bytes()),
        claims,
    };
    let granted = GrantedEnvelope {
        handshake: ServiceHandshake {
            mode: "enforce".into(),
            policy_digest: Some([7; 32]),
            instance_boot: "boot-a".into(),
        },
        envelope,
        resource_uuid: UUID.into(),
        resource_generation: 7,
        grant,
    };
    let body = serde_json::to_vec(&granted).unwrap();
    let mut framed = (body.len() as u32).to_be_bytes().to_vec();
    framed.extend(body);
    framed
}

fn bridge(address: &str, route: &str) -> NetdRequest {
    NetdRequest::ApplyOverlay {
        overlay_id: "matrix-overlay".into(),
        mode: OverlayMode::BridgeOnly,
        peers: vec![],
        routes: vec![route.into()],
        addresses: vec![address.into()],
    }
}
fn wireguard(address: &str, route: &str) -> NetdRequest {
    NetdRequest::ApplyOverlay {
        overlay_id: "matrix-overlay".into(),
        mode: OverlayMode::WireGuard,
        peers: vec![],
        routes: vec![route.into()],
        addresses: vec![address.into()],
    }
}

/// Production-kernel authorization witness: the same signed envelope and
/// helper grant used by the deterministic matrix must reach a real netd
/// WireGuard mutation before the interface is created. This is opt-in because
/// it requires root and leaves no state when the remove operation succeeds.
#[test]
#[ignore]
fn real_kernel_wireguard_grant_path() {
    assert_eq!(nix::unistd::geteuid().as_raw(), 0, "root is required");
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("wireguard.key");
    let key = base64::engine::general_purpose::STANDARD.encode([31_u8; 32]);
    std::fs::write(&key_path, format!("{key}\n")).unwrap();
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let keys = Keys {
        manager: SigningKey::from_bytes(&[17; 32]),
        helper: SigningKey::from_bytes(&[18; 32]),
    };
    let policy = Policy::new(
        "cluster".into(),
        "node".into(),
        &base64::engine::general_purpose::STANDARD.encode(keys.manager.verifying_key().to_bytes()),
    )
    .unwrap();
    let verifier = GrantVerifier::new(
        keys.helper.verifying_key(),
        "runtime",
        "key-1",
        "boot-a",
        GrantLedger::open(dir.path().join("grants.json")).unwrap(),
    );
    let mut server =
        NetdServer::with_wireguard(nix::unistd::geteuid().as_raw(), policy, key_path, 51991)
            .with_grants(verifier)
            .load_journal(dir.path().join("ownership.json"))
            .unwrap();
    let interfaces = ferro_core::managed_overlay::managed_interface_identities("matrix-overlay");
    struct LinkCleanup(Vec<String>);
    impl Drop for LinkCleanup {
        fn drop(&mut self) {
            for name in &self.0 {
                let exists = std::process::Command::new("ip")
                    .args(["link", "show", "dev", name])
                    .status()
                    .map(|status| status.success())
                    .unwrap_or(false);
                if exists {
                    let _ = std::process::Command::new("ip")
                        .args(["link", "delete", name])
                        .status();
                }
            }
        }
    }
    let _cleanup = LinkCleanup(vec![
        "fw-direct".into(),
        interfaces.bridge_ifname.clone(),
        interfaces.wireguard_ifname.clone(),
    ]);
    let direct = ferro_net::WireGuardManager::new(None);
    let direct_name = "fw-direct";
    let direct_result = direct.apply(
        &ferro_net::WireGuardInterfaceConfig {
            name: direct_name.into(),
            private_key_path: dir.path().join("wireguard.key"),
            listen_port: 51990,
            addresses: vec!["10.78.0.1/24".parse().unwrap()],
        },
        &[],
    );
    assert!(
        direct_result.is_ok(),
        "direct real WireGuard apply: {direct_result:?}"
    );
    direct
        .remove(&ferro_net::WireGuardInterfaceConfig {
            name: direct_name.into(),
            private_key_path: dir.path().join("wireguard.key"),
            listen_port: 51990,
            addresses: vec![],
        })
        .unwrap();
    let wireguard_name = interfaces.wireguard_ifname;
    let apply = wireguard("10.77.0.1/24", "10.77.0.0/24");
    let response = server.handle_peer(
        nix::unistd::geteuid().as_raw(),
        &frame(&keys, apply, 1, None),
        100,
    );
    assert_eq!(
        response,
        NetdResponse::Applied,
        "real apply response: {response:?}"
    );
    let show = std::process::Command::new("ip")
        .args(["link", "show", "dev", &wireguard_name])
        .output()
        .unwrap();
    assert!(
        show.status.success(),
        "real WireGuard interface was not created"
    );
    let removed = server.handle_peer(
        nix::unistd::geteuid().as_raw(),
        &frame(
            &keys,
            NetdRequest::RemoveOverlay {
                overlay_id: "matrix-overlay".into(),
            },
            2,
            Some("req-1"),
        ),
        100,
    );
    assert_eq!(
        removed,
        NetdResponse::Removed,
        "real remove response: {removed:?}"
    );
}

#[derive(Clone, Copy)]
enum Scenario {
    Create,
    Update,
    BridgeToWg,
    WgToBridge,
    Remove,
    Attach,
    Detach,
}

fn setup(
    server: &mut NetdServer,
    keys: &Keys,
    scenario: Scenario,
) -> (u64, NetdRequest, Option<String>) {
    let mut revision = 1;
    let mut send_ok = |request: NetdRequest| {
        let request_frame = frame(keys, request, revision, None);
        assert!(matches!(
            server.handle_peer(1001, &request_frame, 100),
            NetdResponse::Applied | NetdResponse::Attached
        ));
        let id = format!("req-{revision}");
        revision += 1;
        id
    };
    let prior = match scenario {
        Scenario::Create => None,
        Scenario::Update | Scenario::BridgeToWg => {
            Some(send_ok(bridge("10.1.0.1/24", "10.1.0.0/16")))
        }
        Scenario::WgToBridge | Scenario::Remove => {
            Some(send_ok(wireguard("10.1.0.1/24", "10.1.0.0/16")))
        }
        Scenario::Attach | Scenario::Detach => {
            send_ok(bridge("10.1.0.1/24", "10.1.0.0/16"));
            if matches!(scenario, Scenario::Detach) {
                Some(send_ok(NetdRequest::AttachEndpoint {
                    overlay_id: "matrix-overlay".into(),
                    endpoint_id: "ep-a".into(),
                    netns: Some("ns-a".into()),
                }))
            } else {
                None
            }
        }
    };
    let target = match scenario {
        Scenario::Create => bridge("10.2.0.1/24", "10.2.0.0/16"),
        Scenario::Update => bridge("10.2.0.1/24", "10.2.0.0/16"),
        Scenario::BridgeToWg => wireguard("10.2.0.1/24", "10.2.0.0/16"),
        Scenario::WgToBridge => bridge("10.2.0.1/24", "10.2.0.0/16"),
        Scenario::Remove => NetdRequest::RemoveOverlay {
            overlay_id: "matrix-overlay".into(),
        },
        Scenario::Attach => NetdRequest::AttachEndpoint {
            overlay_id: "matrix-overlay".into(),
            endpoint_id: "ep-a".into(),
            netns: Some("ns-a".into()),
        },
        Scenario::Detach => NetdRequest::DetachEndpoint {
            overlay_id: "matrix-overlay".into(),
            endpoint_id: "ep-a".into(),
        },
    };
    (revision, target, prior)
}

#[test]
fn granted_transaction_fault_matrix_reopens_without_false_failure_or_replay() {
    let cases: &[(Scenario, &[&str])] = &[
        (
            Scenario::Create,
            &[
                "bridge_created",
                "address_applied:0",
                "route_applied:0",
                "ownership_persist",
            ],
        ),
        (
            Scenario::Update,
            &[
                "address_applied:0",
                "route_applied:0",
                "stale_route_removed:0",
                "stale_address_removed:0",
                "ownership_persist",
            ],
        ),
        (
            Scenario::BridgeToWg,
            &[
                "wireguard_configured",
                "forwarding_enabled",
                "address_applied:0",
                "route_applied:0",
                "stale_route_removed:0",
                "stale_address_removed:0",
                "ownership_persist",
            ],
        ),
        (
            Scenario::WgToBridge,
            &[
                "address_applied:0",
                "route_applied:0",
                "stale_route_removed:0",
                "stale_address_removed:0",
                "stale_wireguard_removed",
                "ownership_persist",
            ],
        ),
        (
            Scenario::Remove,
            &[
                "route_removed:0",
                "address_removed:0",
                "wireguard_removed",
                "bridge_removed",
                "ownership_persist",
            ],
        ),
        (
            Scenario::Attach,
            &[
                "endpoint_link_created",
                "endpoint_master_set",
                "endpoint_netns_moved",
                "ownership_persist",
            ],
        ),
        (
            Scenario::Detach,
            &["endpoint_link_removed", "ownership_persist"],
        ),
    ];
    for (scenario, phases) in cases {
        for phase in *phases {
            let directory = tempfile::tempdir().unwrap();
            let keys = Keys {
                manager: SigningKey::from_bytes(&[71; 32]),
                helper: SigningKey::from_bytes(&[72; 32]),
            };
            let faults = FaultHandle::default();
            let mut server = open_server(directory.path(), &keys, faults.clone());
            let (revision, request, origin) = setup(&mut server, &keys, *scenario);
            if *phase == "ownership_persist" {
                faults.fail_once(FaultPoint::OwnershipPersist);
            } else {
                faults.fail_phase_once(*phase);
            }
            let target_frame = frame(&keys, request, revision, origin.as_deref());
            assert!(
                matches!(
                    server.handle_peer(1001, &target_frame, 100),
                    NetdResponse::Rejected { .. }
                ),
                "{phase}"
            );
            let request_id = format!("req-{revision}");
            let immediate = server.test_snapshot();
            let receipt = immediate
                .receipts
                .iter()
                .find(|receipt| receipt.request_id == request_id)
                .unwrap();
            assert_ne!(receipt.phase, "failed", "{phase}");
            drop(server);
            let mut reopened = open_server(directory.path(), &keys, Default::default());
            let before = reopened.test_snapshot();
            assert!(
                before.receipts.iter().any(|receipt| {
                    receipt.request_id == request_id && receipt.outcome.as_deref() != Some("failed")
                }),
                "{phase}"
            );
            assert!(
                (!before.quarantined.is_empty())
                    || (before.topology_exact && before.ownership_consistent),
                "{phase}: restart exposed partial topology without quarantine"
            );
            let replay = reopened.handle_peer(1001, &target_frame, 100);
            assert!(
                matches!(replay, NetdResponse::Rejected { .. }),
                "{phase}: {replay:?}"
            );
            assert_eq!(
                before.receipts.len(),
                reopened.test_snapshot().receipts.len(),
                "{phase}"
            );
        }
    }
}

#[test]
fn granted_restart_rejects_unexpired_lower_revision_before_kernel_effect() {
    let directory = tempfile::tempdir().unwrap();
    let keys = Keys {
        manager: SigningKey::from_bytes(&[73; 32]),
        helper: SigningKey::from_bytes(&[74; 32]),
    };
    let mut server = open_server(directory.path(), &keys, Default::default());
    assert_eq!(
        server.handle_peer(
            1001,
            &frame(&keys, bridge("10.2.0.1/24", "10.2.0.0/16"), 2, None),
            100
        ),
        NetdResponse::Applied
    );
    drop(server);

    let mut restarted = open_server(directory.path(), &keys, Default::default());
    assert_eq!(
        restarted.handle_peer(
            1001,
            &frame(&keys, bridge("10.1.0.1/24", "10.1.0.0/16"), 1, None),
            100
        ),
        NetdResponse::Rejected {
            code: RejectionCode::StaleRevision,
            reason: "policy rejected request".into(),
        }
    );
    assert_eq!(
        restarted.test_snapshot().routes.get("matrix-overlay"),
        Some(&vec!["10.2.0.0/16".into()])
    );
}

/// Regression: in WireGuard mode the overlay addresses belong on the
/// WireGuard interface (crypto routing needs the source address there), and
/// the bridge must not receive a duplicate assignment.
#[test]
fn wireguard_overlay_addresses_land_on_the_wireguard_interface_not_the_bridge() {
    let directory = tempfile::tempdir().unwrap();
    let keys = Keys {
        manager: SigningKey::from_bytes(&[75; 32]),
        helper: SigningKey::from_bytes(&[76; 32]),
    };
    let mut server = open_server(directory.path(), &keys, Default::default());
    assert_eq!(
        server.handle_peer(
            1001,
            &frame(&keys, wireguard("10.1.0.1/24", "10.1.0.0/16"), 1, None),
            100
        ),
        NetdResponse::Applied
    );
    drop(server);

    let state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.path().join("kernel.json")).unwrap())
            .unwrap();
    let interfaces = ferro_core::managed_overlay::managed_interface_identities("matrix-overlay");
    assert_eq!(
        state["addresses"][interfaces.wireguard_ifname.as_str()],
        serde_json::json!(["10.1.0.1/24"]),
        "WireGuard interface must own the overlay address"
    );
    assert!(
        state["addresses"]
            .get(interfaces.bridge_ifname.as_str())
            .is_none(),
        "bridge must not receive a duplicate overlay address"
    );
}
