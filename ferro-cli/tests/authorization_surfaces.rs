#![cfg(target_os = "linux")]

use ferro_cli::authorization_surfaces::{authenticate_docker_peer, DockerTelemetry};
use ferro_core::authorization::RequestOrigin;
use std::os::unix::net::UnixStream;

#[test]
fn docker_authentication_happens_from_socket_not_headers() {
    let (server, _client) = UnixStream::pair().unwrap();
    let result = authenticate_docker_peer(
        &server,
        DockerTelemetry::new()
            .with_header("x-ferrocrate-principal", "root")
            .with_label("actor", "administrator"),
    );
    match result {
        Ok(identity) => {
            assert_ne!(identity.principal_id(), "root");
            assert_eq!(
                identity.telemetry().header("x-ferrocrate-principal"),
                Some("root")
            );
        }
        Err(error) => assert!(error.to_string().contains("pidfd")),
    }
}

#[test]
fn cli_identity_uses_effective_authority_not_sudo_environment() {
    std::env::set_var("SUDO_USER", "forged-administrator");
    let first = RequestOrigin::cli_current().unwrap();
    std::env::set_var("SUDO_USER", "different-forgery");
    let second = RequestOrigin::cli_current().unwrap();
    std::env::remove_var("SUDO_USER");
    assert_eq!(first.principal().id(), second.principal().id());
    assert_ne!(first.principal().id().as_str(), "forged-administrator");
}
