#[path = "../src/policy.rs"] mod policy;
#[path = "../src/protocol.rs"] mod protocol;
#[path = "../src/grants.rs"] mod grants;
#[path = "../src/server.rs"] mod server;

use base64::Engine;
use ed25519_dalek::SigningKey;
use protocol::{NetdRequest, RejectionCode, SignedEnvelope};

fn server() -> server::NetdServer {
    let signing = SigningKey::from_bytes(&[7; 32]);
    let key = base64::engine::general_purpose::STANDARD.encode(signing.verifying_key().as_bytes());
    server::NetdServer::new(1001, policy::Policy::new("cluster".into(), "node".into(), &key).unwrap())
}

#[test]
fn rejects_wrong_peer_uid_before_decoding_body() {
    let mut server = server();
    let response = server.handle_peer(2002, &vec![0xff; protocol::MAX_FRAME_BYTES + 1], 1);
    assert_eq!(response.code(), Some(RejectionCode::UnauthorizedPeer));
}

#[test]
fn rejects_oversized_frame_for_authorized_peer() {
    let mut server = server();
    let response = server.handle_peer(1001, &vec![0; protocol::MAX_FRAME_BYTES + 5], 1);
    assert_eq!(response.code(), Some(RejectionCode::OversizedFrame));
}

#[test]
fn rejects_invalid_signature() {
    let mut server = server();
    let request = SignedEnvelope { cluster_id: "cluster".into(), node_id: "node".into(), epoch: 1, revision: 1, lease_expires_unix_secs: 2, request: NetdRequest::Inspect { overlay_id: "wg0".into() }, signature: "AAAA".into() };
    let body = serde_json::to_vec(&request).unwrap();
    let mut frame = (body.len() as u32).to_be_bytes().to_vec(); frame.extend(body);
    assert_eq!(server.handle_peer(1001, &frame, 1).code(), Some(RejectionCode::InvalidSignature));
}

#[test]
fn rejects_direct_peer_without_request_bound_grant() {
    let signing = SigningKey::from_bytes(&[7; 32]);
    let mut envelope = SignedEnvelope { cluster_id: "cluster".into(), node_id: "node".into(), epoch: 1, revision: 1, lease_expires_unix_secs: 20, request: NetdRequest::Inspect { overlay_id: "wg0".into() }, signature: String::new() };
    envelope.signature = base64::engine::general_purpose::STANDARD.encode(ed25519_dalek::Signer::sign(&signing, &serde_json::to_vec(&envelope).unwrap()).to_bytes());
    let body = serde_json::to_vec(&envelope).unwrap();
    let mut frame = (body.len() as u32).to_be_bytes().to_vec(); frame.extend(body);
    assert_eq!(server().handle_peer(1001, &frame, 1).code(), Some(RejectionCode::MissingGrant));
}

#[test]
fn policy_revision_can_be_rolled_back_for_retry() {
    let signing = SigningKey::from_bytes(&[7; 32]);
    let key = base64::engine::general_purpose::STANDARD.encode(signing.verifying_key().as_bytes());
    let mut policy = policy::Policy::new("cluster".into(), "node".into(), &key).unwrap();
    let mut envelope = SignedEnvelope { cluster_id: "cluster".into(), node_id: "node".into(), epoch: 4, revision: 9, lease_expires_unix_secs: 100, request: NetdRequest::Inspect { overlay_id: "wg0".into() }, signature: String::new() };
    let unsigned = serde_json::to_vec(&envelope).unwrap();
    envelope.signature = base64::engine::general_purpose::STANDARD.encode(ed25519_dalek::Signer::sign(&signing, &unsigned).to_bytes());
    assert!(policy.validate(&envelope, 1).is_ok());
    policy.rollback("wg0", 4, 9);
    assert!(policy.validate(&envelope, 1).is_ok());
}

fn signed_envelope(signing: &SigningKey, lease_expires_unix_secs: u64) -> SignedEnvelope {
    let mut envelope = SignedEnvelope { cluster_id: "cluster".into(), node_id: "node".into(), epoch: 4, revision: 9, lease_expires_unix_secs, request: NetdRequest::Inspect { overlay_id: "wg0".into() }, signature: String::new() };
    let unsigned = serde_json::to_vec(&envelope).unwrap();
    envelope.signature = base64::engine::general_purpose::STANDARD.encode(ed25519_dalek::Signer::sign(signing, &unsigned).to_bytes());
    envelope
}

#[test]
fn policy_allows_same_revision_only_when_lease_is_extended() {
    let signing = SigningKey::from_bytes(&[7; 32]);
    let key = base64::engine::general_purpose::STANDARD.encode(signing.verifying_key().as_bytes());
    let mut policy = policy::Policy::new("cluster".into(), "node".into(), &key).unwrap();

    assert!(policy.validate(&signed_envelope(&signing, 100), 1).is_ok());
    assert_eq!(policy.validate(&signed_envelope(&signing, 100), 1), Err(RejectionCode::StaleRevision));
    assert!(policy.validate(&signed_envelope(&signing, 200), 1).is_ok());
}
