#![cfg(unix)]

use ferro_core::authorization::{AuthorizationMode, AuthorizationServiceMode};
use ferro_core::managed_overlay::{
    ManagedOverlayClient, ManagedOverlayRequest, ManagedOverlayResponse,
};
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;

#[test]
fn disabled_compatibility_client_sends_a_real_mutation_over_the_local_socket() {
    let directory = tempfile::tempdir().expect("temporary socket directory");
    let socket = directory.path().join("managed.sock");
    let listener = UnixListener::bind(&socket).expect("bind local manager socket");
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept client");
        let mut prefix = [0; 4];
        stream.read_exact(&mut prefix).expect("read request size");
        let mut body = vec![0; u32::from_be_bytes(prefix) as usize];
        stream.read_exact(&mut body).expect("read request");
        let request: serde_json::Value = serde_json::from_slice(&body).expect("decode request");
        assert_eq!(request["mode"], "disabled");
        assert_eq!(
            request["request"]["AttachContainer"]["container_id"],
            "compat-container"
        );
        let response = serde_json::to_vec(&ManagedOverlayResponse::Detached { released: true })
            .expect("encode response");
        stream
            .write_all(&(response.len() as u32).to_be_bytes())
            .and_then(|_| stream.write_all(&response))
            .expect("write response");
    });

    let client = ManagedOverlayClient::new(&socket).with_authorization_identity(
        AuthorizationServiceMode::new(AuthorizationMode::Disabled, None)
            .expect("disabled service identity"),
        "fixture-boot",
    );
    let response = client
        .request_disabled_compatibility(&ManagedOverlayRequest::AttachContainer {
            overlay_id: "compat".into(),
            container_id: "compat-container".into(),
            now_unix: 1,
        })
        .expect("public disabled compatibility mutation");
    assert_eq!(
        response,
        ManagedOverlayResponse::Detached { released: true }
    );
    server.join().expect("server completes");
}

#[test]
fn disabled_compatibility_client_rejects_enabled_identity_before_connecting() {
    let client = ManagedOverlayClient::new("/definitely-not-a-manager.sock")
        .with_authorization_identity(
            AuthorizationServiceMode::new(AuthorizationMode::Shadow, Some([7; 32]))
                .expect("shadow service identity"),
            "fixture-boot",
        );
    let error = client
        .request_disabled_compatibility(&ManagedOverlayRequest::InspectOverlay {
            overlay_id: "compat".into(),
            now_unix: 1,
        })
        .expect_err("enabled identities cannot use the disabled protocol");
    assert_eq!(
        error.to_string(),
        "authorized helper grant could not be derived: durable intent does not bind the authorized resource generation"
    );
}
