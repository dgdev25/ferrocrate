#![cfg(target_os = "linux")]
#![cfg(target_os = "linux")]

use std::{os::unix::net::UnixStream, sync::Arc};

use ed25519_dalek::{Signer, SigningKey};
use ferro_core::authorization::{Action, PrincipalResolver};
use ferro_cri::server::{
    CriDelegationClaims, CriDelegationVerifier, CriIdentityPolicy, DelegationAssertion,
    DelegationTrustKey,
};

fn transport() -> ferro_core::authorization::TransportPrincipal {
    let (peer, _other) = UnixStream::pair().unwrap();
    PrincipalResolver::from_cri_peer_credentials(&peer).unwrap()
}

#[test]
fn metadata_is_telemetry_only_and_signed_delegation_becomes_gate_origin() {
    let transport = transport();
    let signing = SigningKey::from_bytes(&[11; 32]);
    let replay = tempfile::tempdir().unwrap();
    let verifier = CriDelegationVerifier::open(
        vec![DelegationTrustKey::developer(
            "issuer",
            "key",
            signing.verifying_key(),
        )],
        "ferro-cri",
        "boot",
        [9; 32],
        replay.path(),
    )
    .unwrap();
    let policy = CriIdentityPolicy::with_signed_verifier("unused", Arc::new(verifier));
    let transport_id = transport.principal().id().as_str().to_owned();

    let metadata_only = policy
        .resolve(
            &transport,
            None,
            Some("root".into()),
            Action::ImageDelete,
            "alpine",
            1,
        )
        .unwrap();
    assert_eq!(
        metadata_only.request_origin().principal().id().as_str(),
        transport_id
    );
    assert!(!metadata_only.used_delegation());

    let claims = CriDelegationClaims::new(
        "issuer",
        "key",
        transport_id,
        "ferro-cri",
        "alice",
        vec![Action::ImageDelete],
        vec!["alpine".into()],
        "nonce",
        2_000,
        "boot",
        [9; 32],
    )
    .unwrap();
    let assertion = DelegationAssertion::new(
        claims.clone(),
        signing.sign(&claims.signing_bytes()).to_bytes(),
    )
    .unwrap();
    let effective = policy
        .resolve(
            &transport,
            Some(assertion),
            None,
            Action::ImageDelete,
            "alpine",
            1_000,
        )
        .unwrap();
    assert_eq!(
        effective.request_origin().principal().id().as_str(),
        "alice"
    );
    assert!(effective.used_delegation());
}
