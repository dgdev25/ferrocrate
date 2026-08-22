#![cfg(feature = "test-support")]

//! Enforcement proofs for every local mutation path in the netd executor:
//! each path must be authorization-bound (fails closed without a valid
//! consumed grant) and must not touch kernel state it does not own.

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
    test_support::normalized_request_parameters,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;

const UUID: &str = "123e4567-e89b-12d3-a456-426614174000";

struct Keys {
    manager: SigningKey,
    helper: SigningKey,
}

fn open_server(root: &Path, keys: &Keys) -> NetdServer {
    let manager_public =
        base64::engine::general_purpose::STANDARD.encode(keys.manager.verifying_key().to_bytes());
    let verifier = GrantVerifier::new(
        keys.helper.verifying_key(),
        "runtime",
        "key-1",
        "boot-a",
        GrantLedger::open(root.join("grants.json")).unwrap(),
    );
    NetdServer::deterministic(
        1001,
        Policy::new("cluster".into(), "node".into(), &manager_public).unwrap(),
        root.join("kernel.json"),
    )
    .with_grants(verifier)
    .load_journal(root.join("ownership.json"))
    .unwrap()
}

fn sign_envelope(keys: &Keys, request: NetdRequest, revision: u64) -> SignedEnvelope {
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
    envelope
}

fn result_identity(request: &NetdRequest) -> String {
    match request {
        NetdRequest::RemoveOverlay { overlay_id }
        | NetdRequest::ApplyOverlay { overlay_id, .. } => {
            format!("overlay:{overlay_id}")
        }
        NetdRequest::AttachEndpoint { endpoint_id, .. }
        | NetdRequest::DetachEndpoint { endpoint_id, .. } => format!("endpoint:{endpoint_id}"),
        NetdRequest::Inspect { overlay_id } => format!("overlay:{overlay_id}"),
    }
}

fn frame(keys: &Keys, request: NetdRequest, revision: u64, origin: Option<&str>) -> Vec<u8> {
    let envelope = sign_envelope(keys, request.clone(), revision);
    let (action, parameters) = normalized_request_parameters(&request).unwrap();
    let request_id = format!("req-{revision}");
    let mut nonce = [0; 16];
    nonce[..8].copy_from_slice(&revision.to_be_bytes());
    let mut operation_id = [1; 16];
    operation_id[..8].copy_from_slice(&revision.to_be_bytes());
    let cleanup = matches!(
        action,
        GrantAction::NetworkDelete | GrantAction::NetworkDetach
    );
    let identity = result_identity(&request);
    let live_identity_digest = origin.map(|_| {
        let digest: [u8; 32] = Sha256::digest(
            [
                b"ferrocrate.helper-live-identity.v1\0".as_slice(),
                identity.as_bytes(),
            ]
            .concat(),
        )
        .into();
        digest
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

fn bridge_apply(overlay: &str) -> NetdRequest {
    NetdRequest::ApplyOverlay {
        overlay_id: overlay.into(),
        mode: OverlayMode::BridgeOnly,
        peers: vec![],
        routes: vec!["10.1.0.0/16".into()],
        addresses: vec!["10.1.0.1/24".into()],
    }
}

/// Read the deterministic kernel journal and return (links, events).
fn kernel_state(root: &Path) -> (Vec<String>, Vec<String>) {
    let value: Value =
        serde_json::from_slice(&std::fs::read(root.join("kernel.json")).unwrap()).unwrap();
    let links = value["links"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(|row| row.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let events = value["events"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(|row| row.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    (links, events)
}

fn assert_no_kernel_mutation(root: &Path) {
    if root.join("kernel.json").exists() {
        let (_, events) = kernel_state(root);
        assert!(
            events.is_empty(),
            "rejected request must not reach the kernel, events: {events:?}"
        );
    }
}

fn rejected(response: &NetdResponse) -> &RejectionCode {
    match response {
        NetdResponse::Rejected { code, .. } => code,
        other => panic!("expected rejection, got {other:?}"),
    }
}

#[test]
fn mutation_without_grant_is_rejected_and_kernel_untouched() {
    let directory = tempfile::tempdir().unwrap();
    let keys = Keys {
        manager: SigningKey::from_bytes(&[81; 32]),
        helper: SigningKey::from_bytes(&[82; 32]),
    };
    let mut server = open_server(directory.path(), &keys);
    // Manager-signed envelope without any helper grant.
    let envelope = sign_envelope(&keys, bridge_apply("unguarded"), 1);
    let body = serde_json::to_vec(&envelope).unwrap();
    let mut legacy = (body.len() as u32).to_be_bytes().to_vec();
    legacy.extend(body);
    let response = server.handle_peer(1001, &legacy, 100);
    assert_eq!(
        rejected(&response),
        &RejectionCode::MissingGrant,
        "{response:?}"
    );
    assert_no_kernel_mutation(directory.path());
}

#[test]
fn remove_overlay_requires_create_origin_and_rejects_foreign_origin() {
    let directory = tempfile::tempdir().unwrap();
    let keys = Keys {
        manager: SigningKey::from_bytes(&[83; 32]),
        helper: SigningKey::from_bytes(&[84; 32]),
    };
    let mut server = open_server(directory.path(), &keys);
    // A delete grant with no origin at all.
    let no_origin = frame(
        &keys,
        NetdRequest::RemoveOverlay {
            overlay_id: "orphan-overlay".into(),
        },
        1,
        None,
    );
    let response = server.handle_peer(1001, &no_origin, 100);
    assert_eq!(rejected(&response), &RejectionCode::InvalidGrant);
    assert_no_kernel_mutation(directory.path());
    drop(server);

    // A delete grant whose origin points at another resource's attach.
    let directory = tempfile::tempdir().unwrap();
    let mut server = open_server(directory.path(), &keys);
    assert_eq!(
        server.handle_peer(
            1001,
            &frame(&keys, bridge_apply("owned-overlay"), 1, None),
            100
        ),
        NetdResponse::Applied
    );
    assert_eq!(
        server.handle_peer(
            1001,
            &frame(
                &keys,
                NetdRequest::AttachEndpoint {
                    overlay_id: "owned-overlay".into(),
                    endpoint_id: "ep-origin".into(),
                    netns: None,
                },
                2,
                None,
            ),
            100
        ),
        NetdResponse::Attached
    );
    let foreign = frame(
        &keys,
        NetdRequest::RemoveOverlay {
            overlay_id: "other-overlay".into(),
        },
        3,
        Some("req-2"),
    );
    let response = server.handle_peer(1001, &foreign, 100);
    assert_eq!(rejected(&response), &RejectionCode::InvalidGrant);
    // The owned overlay and endpoint survive.
    let (links, _) = kernel_state(directory.path());
    let identities = ferro_core::managed_overlay::managed_interface_identities("owned-overlay");
    assert!(links.contains(&identities.bridge_ifname));
    assert!(links.contains(&"ep-origin".to_string()));
}

#[test]
fn detach_endpoint_authorized_for_a_different_overlay_is_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let keys = Keys {
        manager: SigningKey::from_bytes(&[85; 32]),
        helper: SigningKey::from_bytes(&[86; 32]),
    };
    let mut server = open_server(directory.path(), &keys);
    assert_eq!(
        server.handle_peer(
            1001,
            &frame(&keys, bridge_apply("own-overlay"), 1, None),
            100
        ),
        NetdResponse::Applied
    );
    let attach = NetdRequest::AttachEndpoint {
        overlay_id: "own-overlay".into(),
        endpoint_id: "ep-x".into(),
        netns: None,
    };
    assert_eq!(
        server.handle_peer(1001, &frame(&keys, attach, 2, None), 100),
        NetdResponse::Attached
    );
    // Fully valid cleanup grant chain, but the authorization names an
    // overlay the endpoint is not attached to.
    let cross_overlay = NetdRequest::DetachEndpoint {
        overlay_id: "other-overlay".into(),
        endpoint_id: "ep-x".into(),
    };
    let response = server.handle_peer(1001, &frame(&keys, cross_overlay, 3, Some("req-2")), 100);
    assert_eq!(
        rejected(&response),
        &RejectionCode::PolicyViolation,
        "{response:?}"
    );
    let snapshot = server.test_snapshot();
    assert_eq!(
        snapshot.endpoints.get("ep-x"),
        Some(&"own-overlay".to_string()),
        "endpoint must remain attached"
    );
    let (links, _) = kernel_state(directory.path());
    assert!(links.contains(&"ep-x".to_string()));
    // The consumed grant must be recorded as failed, not left armed.
    let receipt = snapshot
        .receipts
        .iter()
        .find(|receipt| receipt.request_id == "req-3")
        .unwrap();
    assert_eq!(receipt.phase, "failed");
}

#[test]
fn detach_of_foreign_endpoint_cannot_be_authorized_and_link_survives() {
    let directory = tempfile::tempdir().unwrap();
    // Pre-create a link in the deterministic kernel that the server never
    // attached: state owned by somebody else.
    let foreign_endpoint = "ep-foreign";
    std::fs::write(
        directory.path().join("kernel.json"),
        serde_json::json!({
            "links": [foreign_endpoint],
            "kinds": { foreign_endpoint: "veth" },
            "events": [],
        })
        .to_string(),
    )
    .unwrap();
    let keys = Keys {
        manager: SigningKey::from_bytes(&[87; 32]),
        helper: SigningKey::from_bytes(&[88; 32]),
    };
    let mut server = open_server(directory.path(), &keys);
    // A cleanup grant requires a recorded origin result; there is none, and
    // a mutation-kind grant cannot authorize a detach-shaped cleanup.
    let mutation_kind = frame(
        &keys,
        NetdRequest::DetachEndpoint {
            overlay_id: "own-overlay".into(),
            endpoint_id: foreign_endpoint.into(),
        },
        1,
        None,
    );
    let response = server.handle_peer(1001, &mutation_kind, 100);
    assert_eq!(rejected(&response), &RejectionCode::InvalidGrant);
    let (links, _) = kernel_state(directory.path());
    assert!(links.contains(&foreign_endpoint.to_string()));
}
