#![cfg(target_os = "linux")]

use ed25519_dalek::{Signer, SigningKey};
use ferro_core::authorization::cri_delegation::{
    CriDelegationClaims, CriDelegationVerifier, DelegationAssertion, DelegationError,
    DelegationTrustKey,
};
use ferro_core::authorization::{Action, Role};

fn claims(deadline: u64, nonce: &str) -> CriDelegationClaims {
    CriDelegationClaims::new(
        "issuer-a",
        "key-a",
        "transport-a",
        "ferro-cri",
        "alice",
        vec![Action::ImageDelete],
        vec!["image:alpine".into()],
        nonce,
        deadline,
        "boot-a",
        [7; 32],
    )
    .unwrap()
}

#[test]
fn signed_delegation_is_single_use_and_expires() {
    let temp = tempfile::tempdir().unwrap();
    let signing = SigningKey::from_bytes(&[3; 32]);
    let verifier = CriDelegationVerifier::open(
        vec![DelegationTrustKey::developer(
            "issuer-a",
            "key-a",
            signing.verifying_key(),
        )],
        "ferro-cri",
        "boot-a",
        [7; 32],
        temp.path().join("replay"),
    )
    .unwrap();
    let valid_claims = claims(2_000, "nonce-a");
    let assertion = DelegationAssertion::new(
        valid_claims.clone(),
        signing.sign(&valid_claims.signing_bytes()).to_bytes(),
    )
    .unwrap();
    assert_eq!(
        DelegationAssertion::from_wire_bytes(&assertion.wire_bytes()).unwrap(),
        assertion
    );

    let verified = verifier
        .verify(
            &assertion,
            "transport-a",
            Action::ImageDelete,
            "image:alpine",
            1_000,
        )
        .unwrap();
    assert_eq!(verified.principal().id().as_str(), "alice");
    assert_eq!(verified.principal().role(), Role::Developer);
    assert_eq!(
        verifier.verify(
            &assertion,
            "transport-a",
            Action::ImageDelete,
            "image:alpine",
            1_000
        ),
        Err(DelegationError::Replay)
    );

    let expired_claims = claims(999, "nonce-b");
    let expired = DelegationAssertion::new(
        expired_claims.clone(),
        signing.sign(&expired_claims.signing_bytes()).to_bytes(),
    )
    .unwrap();
    assert_eq!(
        verifier.verify(
            &expired,
            "transport-a",
            Action::ImageDelete,
            "image:alpine",
            1_000
        ),
        Err(DelegationError::Expired)
    );
}

#[test]
fn verifier_rejects_context_mismatch_and_persists_replay_across_restart() {
    let temp = tempfile::tempdir().unwrap();
    let replay_path = temp.path().join("replay");
    let signing = SigningKey::from_bytes(&[4; 32]);
    let make_verifier = || {
        CriDelegationVerifier::open(
            vec![DelegationTrustKey::developer(
                "issuer-a",
                "key-a",
                signing.verifying_key(),
            )],
            "ferro-cri",
            "boot-a",
            [7; 32],
            &replay_path,
        )
        .unwrap()
    };
    let token_claims = claims(2_000, "durable-nonce");
    let assertion = DelegationAssertion::new(
        token_claims.clone(),
        signing.sign(&token_claims.signing_bytes()).to_bytes(),
    )
    .unwrap();
    let verifier = make_verifier();
    assert_eq!(
        verifier.verify(
            &assertion,
            "other",
            Action::ImageDelete,
            "image:alpine",
            1_000
        ),
        Err(DelegationError::Scope)
    );
    verifier
        .verify(
            &assertion,
            "transport-a",
            Action::ImageDelete,
            "image:alpine",
            1_000,
        )
        .unwrap();
    let reused_nonce = CriDelegationClaims::new(
        "issuer-a",
        "key-a",
        "transport-a",
        "ferro-cri",
        "mallory",
        vec![Action::ImageDelete],
        vec!["image:other".into()],
        "durable-nonce",
        2_000,
        "boot-a",
        [7; 32],
    )
    .unwrap();
    let reused_assertion = DelegationAssertion::new(
        reused_nonce.clone(),
        signing.sign(&reused_nonce.signing_bytes()).to_bytes(),
    )
    .unwrap();
    assert_eq!(
        verifier.verify(
            &reused_assertion,
            "transport-a",
            Action::ImageDelete,
            "image:other",
            1_000
        ),
        Err(DelegationError::Replay),
    );
    drop(verifier);

    let reopened = make_verifier();
    assert_eq!(
        reopened.verify(
            &assertion,
            "transport-a",
            Action::ImageDelete,
            "image:alpine",
            1_000
        ),
        Err(DelegationError::Replay)
    );
}
