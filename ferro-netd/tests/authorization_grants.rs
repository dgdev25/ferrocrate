#[path = "../src/grants.rs"]
mod grants;
#[path = "../src/protocol.rs"]
mod protocol;

use ed25519_dalek::SigningKey;
use ferro_core::authorization::helper_grant::{
    GrantAction, GrantClaims, GrantIssuer, GrantKind, GrantParameters, ResourceBinding,
};
use grants::{GrantError, GrantLedger, GrantVerifier};
use tempfile::tempdir;

fn fixture() -> (SigningKey, GrantClaims, GrantParameters) {
    let key = SigningKey::from_bytes(&[19; 32]);
    let params = GrantParameters::new(
        "overlay.apply",
        vec![("overlay_id".into(), "wg0".into())],
        vec![],
    )
    .unwrap();
    let claims = GrantClaims::new(
        "req-1",
        GrantAction::NetworkCreate,
        ResourceBinding::new("123e4567-e89b-12d3-a456-426614174000", 7).unwrap(),
        params.digest(),
        "boot-a",
        110,
        10_000,
        [3; 16],
        "runtime",
        "key-1",
        GrantKind::Mutation,
    )
    .unwrap();
    (key, claims, params)
}

#[test]
fn accepts_once_and_correlates_the_result() {
    let (key, claims, params) = fixture();
    let grant = GrantIssuer::new("key-1", key.clone()).sign(claims);
    let dir = tempdir().unwrap();
    let mut verifier = GrantVerifier::new(
        key.verifying_key(),
        "runtime",
        "key-1",
        "boot-a",
        GrantLedger::open(dir.path().join("grants.json")).unwrap(),
    );
    let consumed = verifier
        .verify_and_consume(
            &grant,
            GrantAction::NetworkCreate,
            "123e4567-e89b-12d3-a456-426614174000",
            7,
            &params,
            100,
            9_000,
        )
        .unwrap();
    assert_eq!(consumed.request_id(), "req-1");
    verifier
        .record_result(&consumed, "overlay:wg0", "applied")
        .unwrap();
    assert_eq!(
        verifier.result("req-1").unwrap().result_identity,
        "overlay:wg0"
    );
    assert_eq!(
        verifier.verify_and_consume(
            &grant,
            GrantAction::NetworkCreate,
            "123e4567-e89b-12d3-a456-426614174000",
            7,
            &params,
            100,
            9_000
        ),
        Err(GrantError::Replay)
    );
    drop(verifier);
    let mut reopened = GrantVerifier::new(
        key.verifying_key(),
        "runtime",
        "key-1",
        "boot-a",
        GrantLedger::open(dir.path().join("grants.json")).unwrap(),
    );
    assert_eq!(
        reopened.verify_and_consume(
            &grant,
            GrantAction::NetworkCreate,
            "123e4567-e89b-12d3-a456-426614174000",
            7,
            &params,
            100,
            9_000
        ),
        Err(GrantError::Replay)
    );
}

#[test]
fn rejects_substitution_generation_boot_and_expiry() {
    let (key, claims, params) = fixture();
    let grant = GrantIssuer::new("key-1", key.clone()).sign(claims);
    let make = || GrantVerifier::memory(key.verifying_key(), "runtime", "boot-a");
    let wrong_key_id = GrantIssuer::new("retired-key", key.clone()).sign(grant.claims.clone());
    assert_eq!(
        make().verify(
            &wrong_key_id,
            GrantAction::NetworkCreate,
            "123e4567-e89b-12d3-a456-426614174000",
            7,
            &params,
            100,
            9_000
        ),
        Err(GrantError::WrongIssuer)
    );
    let changed = GrantParameters::new(
        "overlay.apply",
        vec![("overlay_id".into(), "wg1".into())],
        vec![],
    )
    .unwrap();
    assert_eq!(
        make().verify(
            &grant,
            GrantAction::NetworkCreate,
            "123e4567-e89b-12d3-a456-426614174000",
            7,
            &changed,
            100,
            9_000
        ),
        Err(GrantError::ParameterMismatch)
    );
    assert_eq!(
        make().verify(
            &grant,
            GrantAction::NetworkCreate,
            "123e4567-e89b-12d3-a456-426614174000",
            8,
            &params,
            100,
            9_000
        ),
        Err(GrantError::ResourceMismatch)
    );
    assert_eq!(
        GrantVerifier::memory(key.verifying_key(), "runtime", "boot-b").verify(
            &grant,
            GrantAction::NetworkCreate,
            "123e4567-e89b-12d3-a456-426614174000",
            7,
            &params,
            100,
            9_000
        ),
        Err(GrantError::WrongBoot)
    );
    assert_eq!(
        make().verify(
            &grant,
            GrantAction::NetworkCreate,
            "123e4567-e89b-12d3-a456-426614174000",
            7,
            &params,
            111,
            9_000
        ),
        Err(GrantError::Expired)
    );
}

#[test]
fn binds_file_descriptors_and_cleanup_is_deletion_only() {
    let (key, mut claims, _) = fixture();
    claims.kind = GrantKind::Cleanup;
    let params = GrantParameters::new(
        "overlay.delete",
        vec![("overlay_id".into(), "wg0".into())],
        vec![(4, 9, 22)],
    )
    .unwrap();
    claims.parameter_digest = params.digest();
    claims.action = GrantAction::NetworkDelete;
    let grant = GrantIssuer::new("key-1", key.clone()).sign(claims);
    let verifier = GrantVerifier::memory(key.verifying_key(), "runtime", "boot-a");
    assert_eq!(
        verifier.verify(
            &grant,
            GrantAction::NetworkCreate,
            "123e4567-e89b-12d3-a456-426614174000",
            7,
            &params,
            100,
            9_000
        ),
        Err(GrantError::CleanupEscalation)
    );
    let substituted = GrantParameters::new(
        "overlay.delete",
        vec![("overlay_id".into(), "wg0".into())],
        vec![(4, 9, 23)],
    )
    .unwrap();
    assert_eq!(
        verifier.verify(
            &grant,
            GrantAction::NetworkDelete,
            "123e4567-e89b-12d3-a456-426614174000",
            7,
            &substituted,
            100,
            9_000
        ),
        Err(GrantError::ParameterMismatch)
    );
}
