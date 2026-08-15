use ferro_netd::{grants, policy, protocol, server};

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use ferro_core::authorization::helper_grant::{
    signing_bytes, GrantAction, GrantClaims, GrantKind, GrantParameters, HelperGrant,
    ResourceBinding,
};
use grants::{GrantError, GrantLedger, GrantVerifier};
use tempfile::tempdir;

fn sign(key: &SigningKey, claims: GrantClaims) -> HelperGrant {
    let signature = key.sign(&signing_bytes(&claims));
    HelperGrant {
        claims,
        signature: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
    }
}

fn fixture() -> (SigningKey, GrantClaims, GrantParameters) {
    let key = SigningKey::from_bytes(&[19; 32]);
    let params = GrantParameters::new(
        "overlay.apply",
        vec![("overlay_id".into(), "wg0".into())],
        vec![],
    )
    .unwrap();
    let claims = GrantClaims {
        schema_version: 1,
        request_id: "req-1".into(),
        action: GrantAction::NetworkCreate,
        resource: ResourceBinding::new("123e4567-e89b-12d3-a456-426614174000", 7).unwrap(),
        parameter_digest: params.digest(),
        boot_id: "boot-a".into(),
        wall_deadline_secs: 110,
        monotonic_deadline_millis: 10_000,
        nonce: [3; 16],
        operation_id: [4; 16],
        request_digest: [5; 32],
        precondition_digest: [6; 32],
        recovery_recipe_digest: [7; 32],
        issuer: "runtime".into(),
        key_id: "key-1".into(),
        kind: GrantKind::Mutation,
        origin_request_id: None,
        live_identity_digest: None,
    };
    (key, claims, params)
}

#[test]
fn accepts_once_and_correlates_the_result() {
    let (key, claims, params) = fixture();
    let grant = sign(&key, claims);
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
fn grant_ledger_has_exactly_one_process_writer() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("grants.json");
    let first = GrantLedger::open(path.clone()).unwrap();
    assert!(matches!(GrantLedger::open(path), Err(GrantError::Locked)));
    drop(first);
}

#[test]
fn restart_quarantines_an_armed_unknown_effect_without_replay() {
    let (key, claims, params) = fixture();
    let grant = sign(&key, claims);
    let dir = tempdir().unwrap();
    let path = dir.path().join("grants.json");
    let mut verifier = GrantVerifier::new(
        key.verifying_key(),
        "runtime",
        "key-1",
        "boot-a",
        GrantLedger::open(path.clone()).unwrap(),
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
    verifier.arm_effect(&consumed).unwrap();
    drop(verifier);

    let reopened = GrantVerifier::new(
        key.verifying_key(),
        "runtime",
        "key-1",
        "boot-a",
        GrantLedger::open(path).unwrap(),
    );
    let result = reopened.result("req-1").unwrap();
    assert_eq!(result.outcome, "quarantined_after_unknown_effect");
    assert!(result.result_identity.contains("NetworkCreate"));
}

#[test]
fn rejects_substitution_generation_boot_and_expiry() {
    let (key, claims, params) = fixture();
    let grant = sign(&key, claims);
    let make = || GrantVerifier::memory(key.verifying_key(), "runtime", "boot-a");
    let mut retired = grant.claims.clone();
    retired.key_id = "retired-key".into();
    let wrong_key_id = sign(&key, retired);
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
fn key_rotation_accepts_overlap_then_rejects_retired_key() {
    let (old, mut claims, params) = fixture();
    let new = SigningKey::from_bytes(&[20; 32]);
    claims.key_id = "key-2".into();
    let grant = sign(&new, claims);
    let mut verifier = GrantVerifier::memory(old.verifying_key(), "runtime", "boot-a");
    verifier
        .add_verification_key("key-2", new.verifying_key())
        .unwrap();
    assert!(verifier
        .verify(
            &grant,
            GrantAction::NetworkCreate,
            "123e4567-e89b-12d3-a456-426614174000",
            7,
            &params,
            100,
            9_000
        )
        .is_ok());
    verifier.retire_verification_key("key-2").unwrap();
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
        Err(GrantError::WrongIssuer)
    );
}

#[test]
fn granted_wire_reaches_the_real_server_without_ambient_authority() {
    let manager = SigningKey::from_bytes(&[7; 32]);
    let manager_public =
        base64::engine::general_purpose::STANDARD.encode(manager.verifying_key().as_bytes());
    let helper = SigningKey::from_bytes(&[19; 32]);
    let mut envelope = protocol::SignedEnvelope {
        cluster_id: "cluster".into(),
        node_id: "node".into(),
        epoch: 1,
        revision: 1,
        lease_expires_unix_secs: 200,
        request: protocol::NetdRequest::Inspect {
            overlay_id: "wg0".into(),
        },
        signature: String::new(),
    };
    envelope.signature = base64::engine::general_purpose::STANDARD.encode(
        manager
            .sign(&serde_json::to_vec(&envelope).unwrap())
            .to_bytes(),
    );
    let params = GrantParameters::new(
        "overlay.inspect",
        vec![("overlay_id".into(), "wg0".into())],
        vec![],
    )
    .unwrap();
    let (_, mut claims, _) = fixture();
    claims.action = GrantAction::NetworkInspect;
    claims.parameter_digest = params.digest();
    claims.wall_deadline_secs = 200;
    claims.monotonic_deadline_millis = u64::MAX;
    let request = protocol::GrantedEnvelope {
        envelope,
        resource_uuid: claims.resource.resource_uuid.clone(),
        resource_generation: claims.resource.generation,
        grant: sign(&helper, claims),
    };
    let body = serde_json::to_vec(&request).unwrap();
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend(body);
    let verifier = GrantVerifier::memory(helper.verifying_key(), "runtime", "boot-a");
    let mut server = server::NetdServer::new(
        1001,
        policy::Policy::new("cluster".into(), "node".into(), &manager_public).unwrap(),
    )
    .with_grants(verifier);
    assert!(
        matches!(server.handle_peer(1001, &frame, 100), protocol::NetdResponse::Snapshot { overlay_id, revision: 1 } if overlay_id == "wg0")
    );
}

#[test]
fn rejects_descriptor_bearing_requests_and_cleanup_is_deletion_only() {
    let (key, mut claims, _) = fixture();
    claims.kind = GrantKind::Cleanup;
    assert!(GrantParameters::new(
        "overlay.delete",
        vec![("overlay_id".into(), "wg0".into())],
        vec![(4, 9, 22)],
    )
    .is_err());
    let params = GrantParameters::new(
        "overlay.delete",
        vec![("overlay_id".into(), "wg0".into())],
        vec![],
    )
    .unwrap();
    claims.parameter_digest = params.digest();
    claims.action = GrantAction::NetworkDelete;
    let grant = sign(&key, claims);
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
    assert_eq!(
        verifier.verify(
            &grant,
            GrantAction::NetworkDelete,
            "123e4567-e89b-12d3-a456-426614174000",
            7,
            &params,
            100,
            9_000
        ),
        Err(GrantError::CleanupProvenance)
    );
}
