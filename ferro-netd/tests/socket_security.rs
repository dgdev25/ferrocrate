#[path = "../src/policy.rs"] mod policy;
#[path = "../src/protocol.rs"] mod protocol;
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
