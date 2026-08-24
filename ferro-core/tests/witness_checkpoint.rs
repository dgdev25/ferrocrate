#![cfg(target_os = "linux")]

use ed25519_dalek::SigningKey;
use ferro_core::witness::{
    decode_record, encode_record, Checkpoint, CheckpointKind, CheckpointVerifier, FaultPoint,
    FlushBoundary, FlushedHead, Invocation, JournalConfig, JournalFaults, JournalMode, KeyStore,
    PrincipalSummary, ResourceSummary, TrustBundle, WitnessAction, WitnessJournal, WitnessOutcome,
    WitnessRecord, WitnessResourceKind, WitnessStage,
};
use sha2::{Digest, Sha256};
use std::{fs, time::Duration};

fn publication_record_at(
    checkpoint: &Checkpoint,
    sequence: u64,
    previous_hash: [u8; 32],
) -> WitnessRecord {
    let digest: [u8; 32] = Sha256::digest(checkpoint.encode()).into();
    WitnessRecord {
        epoch: checkpoint.head.epoch,
        sequence,
        previous_hash,
        event_id: [sequence as u8; 16],
        request_id: [(sequence + 32) as u8; 16],
        runtime_instance_id: [3; 16],
        boot_id: [4; 16],
        principal: PrincipalSummary::pseudonymize(&[5; 32], b"checkpoint-coordinator").unwrap(),
        invocation: Invocation::Manager,
        action: WitnessAction::CheckpointPublish,
        resource_kind: WitnessResourceKind::Administrative,
        resource: ResourceSummary::pseudonymize(&[6; 32], b"checkpoint").unwrap(),
        resource_generation: checkpoint.head.epoch,
        policy_version: 0,
        policy_digest: [0; 32],
        decision_id: None,
        rule: None,
        decision: None,
        reason: None,
        request_digest: digest,
        result_digest: Some(digest),
        wall_time_ns: 0,
        monotonic_ns: 0,
        stage: WitnessStage::CheckpointPublished,
        outcome: WitnessOutcome::Succeeded,
        recovery_link: None,
        path_class: None,
        device_class: None,
        correlation_digest: None,
    }
}

fn publication_evidence(checkpoint: &Checkpoint) -> Vec<Vec<u8>> {
    let record = publication_record_at(
        checkpoint,
        checkpoint.head.sequence + 1,
        checkpoint.head.hash,
    );
    vec![encode_record(checkpoint.head.journal_id, &record)
        .unwrap()
        .as_ref()
        .to_vec()]
}

fn publication_record(checkpoint: &Checkpoint) -> WitnessRecord {
    publication_record_at(
        checkpoint,
        checkpoint.head.sequence + 1,
        checkpoint.head.hash,
    )
}

fn publication_hash(checkpoint: &Checkpoint) -> [u8; 32] {
    decode_record(&publication_evidence(checkpoint)[0])
        .unwrap()
        .record_hash()
}

fn lineage_evidence(first: &Checkpoint, second: &Checkpoint) -> Vec<Vec<u8>> {
    let mut evidence = publication_evidence(first);
    evidence.extend(publication_evidence(second));
    evidence
}

#[test]
fn key_store_creates_owner_only_key_and_stable_id() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("keys");
    fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let store = KeyStore::new(&root);
    let first = store.create("active").unwrap();
    let loaded = store.load("active").unwrap();
    assert_eq!(first.key_id(), loaded.key_id());
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            fs::metadata(root.join("active.key")).unwrap().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn key_store_requires_a_preprovisioned_private_root() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("keys");
    assert!(KeyStore::new(&missing).create("active").is_err());
    assert!(!missing.exists());
}

#[test]
fn key_store_refuses_symlink_and_checkpoint_frame_is_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("keys");
    fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let outside = dir.path().join("outside");
    fs::write(&outside, [0_u8; 32]).unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&outside, root.join("linked.key")).unwrap();
        assert!(KeyStore::new(&root).load("linked").is_err());
    }
    let key = SigningKey::from_bytes(&[9; 32]);
    let checkpoint = Checkpoint::sign(
        FlushedHead::new([4; 16], 1, 1, [8; 32]),
        1,
        &key,
        CheckpointKind::Periodic,
    )
    .unwrap();
    assert_eq!(
        Checkpoint::decode(&checkpoint.encode()).unwrap(),
        checkpoint
    );
    assert!(Checkpoint::decode(&vec![0; 2048]).is_err());
}

#[test]
fn checkpoint_grace_stops_users_but_preserves_cleanup() {
    let dir = tempfile::tempdir().unwrap();
    let coordinator = ferro_core::witness::CheckpointCoordinator::new(
        dir.path().join("current.chk"),
        Duration::from_secs(60),
        Duration::from_secs(10),
    );
    assert!(coordinator.allows_user_mutation(100, 170));
    assert!(!coordinator.allows_user_mutation(100, 171));
    assert!(coordinator.allows_reserved_cleanup());
}

#[test]
fn coordinator_signs_only_the_durably_flushed_journal_head() {
    let dir = tempfile::tempdir().unwrap();
    let journal = WitnessJournal::open(JournalConfig::new(
        dir.path().join("journal"),
        [12; 16],
        JournalMode::Required,
    ))
    .unwrap();
    let key = SigningKey::from_bytes(&[11; 32]);
    fs::create_dir(dir.path().join("published")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            dir.path().join("published"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }
    let path = dir.path().join("published/checkpoint.bin");
    let coordinator = ferro_core::witness::CheckpointCoordinator::new(
        &path,
        Duration::from_secs(60),
        Duration::from_secs(10),
    );
    let outcome = coordinator
        .capture_publish_bind(&journal, 100, &key, None, publication_record)
        .unwrap();
    let checkpoint = match outcome {
        ferro_core::witness::PublicationOutcome::Bound(cp) => cp,
        _ => panic!("binding must be durable"),
    };
    assert_eq!(checkpoint.head, FlushedHead::new([12; 16], 1, 0, [0; 32]));
    assert_eq!(
        Checkpoint::decode(&fs::read(path).unwrap()).unwrap(),
        checkpoint
    );
    let evidence = journal.records().unwrap();
    let trust = TrustBundle::new([12; 16], key.verifying_key());
    assert!(CheckpointVerifier::new(trust)
        .verify(&evidence, &[checkpoint], 100, Duration::from_secs(60))
        .is_ok());
}

#[test]
fn failed_checkpoint_replacement_never_exposes_partial_bytes() {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let journal = WitnessJournal::open(JournalConfig::new(
        dir.path().join("journal"),
        [1; 16],
        JournalMode::Required,
    ))
    .unwrap();
    let target = dir.path().join("occupied");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("sentinel"), b"intact").unwrap();
    let key = SigningKey::from_bytes(&[13; 32]);
    let coordinator = ferro_core::witness::CheckpointCoordinator::new(
        &target,
        Duration::from_secs(1),
        Duration::from_secs(1),
    );
    assert!(coordinator
        .capture_publish_bind(&journal, 1, &key, None, publication_record)
        .is_err());
    assert_eq!(fs::read(target.join("sentinel")).unwrap(), b"intact");
}

#[test]
fn verifier_requires_explicit_root_and_detects_truncation() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let head = FlushedHead::new([1; 16], 1, 0, [0; 32]);
    let checkpoint = Checkpoint::sign(head, 50, &key, CheckpointKind::Periodic).unwrap();
    let trust = TrustBundle::new([1; 16], key.verifying_key()).with_minimum(checkpoint.clone());
    let report = CheckpointVerifier::new(trust.clone())
        .verify(
            &publication_evidence(&checkpoint),
            &[checkpoint],
            55,
            Duration::from_secs(10),
        )
        .unwrap();
    assert!(report.integrity);
    assert!(report.lifecycle_consistent);
    assert_eq!(report.completeness_through_checkpoint, Some(true));
    assert_eq!(
        report.tail_freshness,
        ferro_core::witness::Freshness::UnknownTail
    );

    let older = Checkpoint::sign(
        FlushedHead::new([1; 16], 1, 1, [3; 32]),
        49,
        &key,
        CheckpointKind::Periodic,
    )
    .unwrap();
    assert!(CheckpointVerifier::new(trust)
        .verify(&[], &[older], 55, Duration::from_secs(10))
        .is_err());
}

#[test]
fn rotation_is_dual_signed_and_untrusted_branch_is_rejected() {
    let old = SigningKey::from_bytes(&[3; 32]);
    let new = SigningKey::from_bytes(&[4; 32]);
    let root = Checkpoint::sign(
        FlushedHead::new([8; 16], 1, 0, [0; 32]),
        10,
        &old,
        CheckpointKind::Periodic,
    )
    .unwrap();
    let rotation = Checkpoint::rotate_after(
        FlushedHead::new([8; 16], 1, 1, publication_hash(&root)),
        11,
        &root,
        &old,
        &new,
    )
    .unwrap();
    let trust = TrustBundle::new([8; 16], old.verifying_key()).with_minimum(rotation.clone());
    assert!(CheckpointVerifier::new(trust.clone())
        .verify(
            &lineage_evidence(&root, &rotation),
            &[root.clone(), rotation],
            12,
            Duration::from_secs(5)
        )
        .is_ok());

    let attacker = SigningKey::from_bytes(&[5; 32]);
    let branch = Checkpoint::rotate_after(
        FlushedHead::new([8; 16], 1, 1, publication_hash(&root)),
        11,
        &root,
        &attacker,
        &new,
    )
    .unwrap();
    assert!(CheckpointVerifier::new(trust)
        .verify(&[], &[branch], 12, Duration::from_secs(5))
        .is_err());
}

#[test]
fn key_loss_requires_explicit_new_epoch_discontinuity() {
    let old = SigningKey::from_bytes(&[1; 32]);
    let new = SigningKey::from_bytes(&[2; 32]);
    let root = Checkpoint::sign(
        FlushedHead::new([6; 16], 1, 0, [0; 32]),
        19,
        &old,
        CheckpointKind::Periodic,
    )
    .unwrap();
    let reset = Checkpoint::trust_reset_after(
        FlushedHead::new([6; 16], 2, 1, publication_hash(&root)),
        20,
        &root,
        &new,
    )
    .unwrap();
    let trust =
        TrustBundle::new([6; 16], old.verifying_key()).allow_epoch_reset(2, new.verifying_key());
    let report = CheckpointVerifier::new(trust)
        .verify(
            &lineage_evidence(&root, &reset),
            &[root, reset],
            20,
            Duration::from_secs(1),
        )
        .unwrap();
    assert_eq!(report.discontinuities, 1);
}

#[test]
fn provisioned_signing_key_disappearance_requires_new_named_key_and_trust_reset() {
    let dir = tempfile::tempdir().unwrap();
    let key_root = dir.path().join("keys");
    fs::create_dir(&key_root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key_root, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let store = KeyStore::new(&key_root);
    let old = store.create("active").unwrap();
    let root = Checkpoint::sign(
        FlushedHead::new([0x66; 16], 1, 0, [0; 32]),
        40,
        old.signing_key(),
        CheckpointKind::Periodic,
    )
    .unwrap();
    fs::remove_file(key_root.join("active.key")).unwrap();
    assert!(store.load("active").is_err());
    let replacement = store.create("recovery-epoch-2").unwrap();
    let reset = Checkpoint::trust_reset_after(
        FlushedHead::new([0x66; 16], 2, 1, publication_hash(&root)),
        41,
        &root,
        replacement.signing_key(),
    )
    .unwrap();
    let trust = TrustBundle::new([0x66; 16], old.verifying_key())
        .allow_epoch_reset(2, replacement.verifying_key());
    let report = CheckpointVerifier::new(trust)
        .verify(
            &lineage_evidence(&root, &reset),
            &[root, reset],
            41,
            Duration::from_secs(1),
        )
        .unwrap();
    assert_eq!(report.discontinuities, 1);
}

#[test]
fn verifier_rejects_missing_corrupt_reordered_and_future_evidence() {
    let key = SigningKey::from_bytes(&[21; 32]);
    let cp = Checkpoint::sign(
        FlushedHead::new([2; 16], 1, 0, [0; 32]),
        100,
        &key,
        CheckpointKind::Periodic,
    )
    .unwrap();
    let verifier = CheckpointVerifier::new(TrustBundle::new([2; 16], key.verifying_key()));
    assert!(verifier
        .verify(&[], std::slice::from_ref(&cp), 100, Duration::from_secs(5))
        .is_err());
    let mut corrupt = publication_evidence(&cp);
    corrupt[0][20] ^= 1;
    assert!(verifier
        .verify(
            &corrupt,
            std::slice::from_ref(&cp),
            100,
            Duration::from_secs(5)
        )
        .is_err());
    assert!(verifier
        .verify(
            &publication_evidence(&cp),
            &[cp],
            99,
            Duration::from_secs(5)
        )
        .is_err());
}

#[test]
fn verifier_rejects_unlinked_epoch_jump() {
    let old = SigningKey::from_bytes(&[22; 32]);
    let new = SigningKey::from_bytes(&[23; 32]);
    let root = Checkpoint::sign(
        FlushedHead::new([3; 16], 1, 0, [0; 32]),
        1,
        &old,
        CheckpointKind::Periodic,
    )
    .unwrap();
    let jump = Checkpoint::trust_reset_after(
        FlushedHead::new([3; 16], 3, 1, publication_hash(&root)),
        2,
        &root,
        &new,
    )
    .unwrap();
    let trust =
        TrustBundle::new([3; 16], old.verifying_key()).allow_epoch_reset(3, new.verifying_key());
    assert!(CheckpointVerifier::new(trust)
        .verify(
            &lineage_evidence(&root, &jump),
            &[root, jump],
            2,
            Duration::from_secs(5)
        )
        .is_err());
}

#[test]
fn periodic_lineage_spans_three_heads_and_rotation() {
    let old = SigningKey::from_bytes(&[31; 32]);
    let new = SigningKey::from_bytes(&[32; 32]);
    let first = Checkpoint::sign(
        FlushedHead::new([14; 16], 1, 0, [0; 32]),
        1,
        &old,
        CheckpointKind::Periodic,
    )
    .unwrap();
    let second = Checkpoint::sign_after(
        FlushedHead::new([14; 16], 1, 1, publication_hash(&first)),
        2,
        &first,
        &old,
    )
    .unwrap();
    let rotation = Checkpoint::rotate_after(
        FlushedHead::new([14; 16], 1, 2, publication_hash(&second)),
        3,
        &second,
        &old,
        &new,
    )
    .unwrap();
    let fourth = Checkpoint::sign_after(
        FlushedHead::new([14; 16], 1, 3, publication_hash(&rotation)),
        4,
        &rotation,
        &new,
    )
    .unwrap();
    let mut evidence = publication_evidence(&first);
    evidence.extend(publication_evidence(&second));
    evidence.extend(publication_evidence(&rotation));
    evidence.extend(publication_evidence(&fourth));
    let trust = TrustBundle::new([14; 16], old.verifying_key()).with_minimum(fourth.clone());
    let report = CheckpointVerifier::new(trust)
        .verify(
            &evidence,
            &[first, second, rotation, fourth],
            4,
            Duration::from_secs(5),
        )
        .unwrap();
    assert_eq!(
        report.tail_freshness,
        ferro_core::witness::Freshness::UnknownTail
    );
    assert_eq!(
        report.checkpoint_age,
        Some(ferro_core::witness::CheckpointAge::Current { seconds: 0 })
    );
}

#[test]
fn crash_after_artifact_rename_returns_pending_and_reconciles_idempotently() {
    let dir = tempfile::tempdir().unwrap();
    let faults = JournalFaults::new();
    faults.fail_once(FaultPoint::DuringFlush(FlushBoundary::Outcome));
    let journal = WitnessJournal::open_with_faults(
        JournalConfig::new(dir.path().join("journal"), [15; 16], JournalMode::Required),
        faults,
    )
    .unwrap();
    let published = dir.path().join("published");
    fs::create_dir(&published).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&published, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let coordinator = ferro_core::witness::CheckpointCoordinator::new(
        published.join("head.chk"),
        Duration::from_secs(5),
        Duration::from_secs(1),
    );
    let key = SigningKey::from_bytes(&[33; 32]);
    let outcome = coordinator
        .capture_publish_bind(&journal, 1, &key, None, publication_record)
        .unwrap();
    let pending = match outcome {
        ferro_core::witness::PublicationOutcome::PendingBinding(pending) => pending,
        _ => panic!("flush ambiguity must be pending"),
    };
    assert!(matches!(
        coordinator.capture_publish_bind(
            &journal,
            2,
            &key,
            Some(pending.checkpoint()),
            publication_record
        ),
        Err(ferro_core::witness::CheckpointError::PendingExists)
    ));
    let replacement = SigningKey::from_bytes(&[34; 32]);
    assert!(matches!(
        coordinator.capture_rotate_publish_bind(
            &journal,
            2,
            &key,
            &replacement,
            pending.checkpoint(),
            publication_record
        ),
        Err(ferro_core::witness::CheckpointError::PendingExists)
    ));
    assert!(matches!(
        coordinator.capture_reset_publish_bind(
            &journal,
            2,
            &replacement,
            pending.checkpoint(),
            publication_record
        ),
        Err(ferro_core::witness::CheckpointError::PendingExists)
    ));
    coordinator
        .reconcile_binding(&journal, &pending, publication_record(pending.checkpoint()))
        .unwrap();
    coordinator
        .reconcile_binding(&journal, &pending, publication_record(pending.checkpoint()))
        .unwrap();
    assert_eq!(journal.records().unwrap().len(), 1);
}

#[test]
fn authenticated_reset_advances_epoch_without_reusing_sequence() {
    let dir = tempfile::tempdir().unwrap();
    let journal = WitnessJournal::open(JournalConfig::new(
        dir.path().join("journal"),
        [16; 16],
        JournalMode::Required,
    ))
    .unwrap();
    let published = dir.path().join("published");
    fs::create_dir(&published).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&published, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let coordinator = ferro_core::witness::CheckpointCoordinator::new(
        published.join("head.chk"),
        Duration::from_secs(5),
        Duration::from_secs(1),
    );
    let old = SigningKey::from_bytes(&[34; 32]);
    let new = SigningKey::from_bytes(&[35; 32]);
    let first = match coordinator
        .capture_publish_bind(&journal, 1, &old, None, publication_record)
        .unwrap()
    {
        ferro_core::witness::PublicationOutcome::Bound(cp) => cp,
        _ => panic!("initial bind"),
    };
    let reset = match coordinator
        .capture_reset_publish_bind(&journal, 2, &new, &first, publication_record)
        .unwrap()
    {
        ferro_core::witness::PublicationOutcome::Bound(cp) => cp,
        _ => panic!("reset bind"),
    };
    let records = journal.records().unwrap();
    assert_eq!(
        (
            decode_record(&records[0]).unwrap().epoch(),
            decode_record(&records[0]).unwrap().sequence()
        ),
        (1, 1)
    );
    assert_eq!(
        (
            decode_record(&records[1]).unwrap().epoch(),
            decode_record(&records[1]).unwrap().sequence()
        ),
        (2, 2)
    );
    let trust =
        TrustBundle::new([16; 16], old.verifying_key()).allow_epoch_reset(2, new.verifying_key());
    assert!(CheckpointVerifier::new(trust)
        .verify(&records, &[first, reset], 2, Duration::from_secs(5))
        .is_ok());
}

#[cfg(unix)]
#[test]
fn key_store_rejects_public_root_and_hardlinked_key() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    assert!(KeyStore::new(dir.path()).create("bad").is_err());
    let root = dir.path().join("keys");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let store = KeyStore::new(&root);
    store.create("active").unwrap();
    fs::hard_link(root.join("active.key"), dir.path().join("copy")).unwrap();
    assert!(store.load("active").is_err());
    let alias = dir.path().join("alias");
    std::os::unix::fs::symlink(dir.path(), &alias).unwrap();
    assert!(KeyStore::new(alias.join("keys")).load("active").is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn publication_rejects_symlink_ancestor() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    fs::create_dir(&real).unwrap();
    fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
    let alias = dir.path().join("alias");
    std::os::unix::fs::symlink(&real, &alias).unwrap();
    let journal = WitnessJournal::open(JournalConfig::new(
        dir.path().join("journal"),
        [19; 16],
        JournalMode::Required,
    ))
    .unwrap();
    let key = SigningKey::from_bytes(&[39; 32]);
    let coordinator = ferro_core::witness::CheckpointCoordinator::new(
        alias.join("head.chk"),
        Duration::from_secs(1),
        Duration::from_secs(1),
    );
    assert!(coordinator
        .capture_publish_bind(&journal, 1, &key, None, publication_record)
        .is_err());
}

#[test]
fn verifier_bounds_checkpoint_state() {
    let key = SigningKey::from_bytes(&[40; 32]);
    let cp = Checkpoint::sign(
        FlushedHead::new([20; 16], 1, 0, [0; 32]),
        1,
        &key,
        CheckpointKind::Periodic,
    )
    .unwrap();
    let excessive = vec![cp.clone(); 4097];
    let verifier = CheckpointVerifier::new(TrustBundle::new([20; 16], key.verifying_key()));
    assert!(verifier
        .verify_iter(
            publication_evidence(&cp).iter().map(Vec::as_slice),
            &excessive,
            1,
            Duration::from_secs(1)
        )
        .is_err());
}

#[test]
fn stale_checkpoint_does_not_claim_known_tail() {
    let key = SigningKey::from_bytes(&[41; 32]);
    let cp = Checkpoint::sign(
        FlushedHead::new([21; 16], 1, 0, [0; 32]),
        1,
        &key,
        CheckpointKind::Periodic,
    )
    .unwrap();
    let report = CheckpointVerifier::new(TrustBundle::new([21; 16], key.verifying_key()))
        .verify(
            &publication_evidence(&cp),
            &[cp],
            20,
            Duration::from_secs(5),
        )
        .unwrap();
    assert_eq!(
        report.tail_freshness,
        ferro_core::witness::Freshness::UnknownTail
    );
    assert_eq!(
        report.checkpoint_age,
        Some(ferro_core::witness::CheckpointAge::Stale { seconds: 19 })
    );
}

#[test]
fn trust_bundle_rejects_an_arbitrary_starting_epoch() {
    let key = SigningKey::from_bytes(&[61; 32]);
    let checkpoint = Checkpoint::sign(
        FlushedHead::new([3; 16], 7, 0, [0; 32]),
        1,
        &key,
        CheckpointKind::Periodic,
    )
    .unwrap();
    assert!(
        CheckpointVerifier::new(TrustBundle::new([3; 16], key.verifying_key()))
            .verify(
                &publication_evidence(&checkpoint),
                &[checkpoint],
                1,
                Duration::from_secs(5)
            )
            .is_err()
    );
}

#[test]
fn pending_binding_survives_a_hard_coordinator_restart() {
    let dir = tempfile::tempdir().unwrap();
    let faults = JournalFaults::new();
    faults.fail_once(FaultPoint::DuringFlush(FlushBoundary::Outcome));
    let journal = WitnessJournal::open_with_faults(
        JournalConfig::new(dir.path().join("journal"), [62; 16], JournalMode::Required),
        faults,
    )
    .unwrap();
    let published = dir.path().join("published");
    fs::create_dir(&published).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&published, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = published.join("head.chk");
    let coordinator = ferro_core::witness::CheckpointCoordinator::new(
        &path,
        Duration::from_secs(5),
        Duration::from_secs(1),
    );
    let key = SigningKey::from_bytes(&[62; 32]);
    assert!(matches!(
        coordinator
            .capture_publish_bind(&journal, 1, &key, None, publication_record)
            .unwrap(),
        ferro_core::witness::PublicationOutcome::PendingBinding(_)
    ));
    drop(coordinator);
    let restarted = ferro_core::witness::CheckpointCoordinator::new(
        &path,
        Duration::from_secs(5),
        Duration::from_secs(1),
    );
    assert_eq!(
        restarted.pending_binding().unwrap().unwrap().state(),
        ferro_core::witness::PendingState::Published
    );
    restarted.reconcile_pending(&journal).unwrap();
    assert!(restarted.pending_binding().unwrap().is_none());
    assert_eq!(journal.records().unwrap().len(), 1);
}

#[test]
fn prepared_sidecar_republishes_a_missing_artifact_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let faults = JournalFaults::new();
    faults.fail_once(FaultPoint::DuringFlush(FlushBoundary::Outcome));
    let journal = WitnessJournal::open_with_faults(
        JournalConfig::new(dir.path().join("journal"), [72; 16], JournalMode::Required),
        faults,
    )
    .unwrap();
    let published = dir.path().join("published");
    fs::create_dir(&published).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&published, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let artifact = published.join("head.chk");
    let coordinator = ferro_core::witness::CheckpointCoordinator::new(
        &artifact,
        Duration::from_secs(5),
        Duration::from_secs(1),
    );
    let key = SigningKey::from_bytes(&[72; 32]);
    coordinator
        .capture_publish_bind(&journal, 1, &key, None, publication_record)
        .unwrap();
    let sidecar = published.join("head.chk.pending");
    let mut bytes = fs::read(&sidecar).unwrap();
    bytes[8] = 1;
    let end = bytes.len() - 32;
    let checksum: [u8; 32] = Sha256::digest(&bytes[..end]).into();
    bytes[end..].copy_from_slice(&checksum);
    fs::write(&sidecar, bytes).unwrap();
    fs::remove_file(&artifact).unwrap();
    let restarted = ferro_core::witness::CheckpointCoordinator::new(
        &artifact,
        Duration::from_secs(5),
        Duration::from_secs(1),
    );
    assert_eq!(
        restarted.pending_binding().unwrap().unwrap().state(),
        ferro_core::witness::PendingState::Prepared
    );
    restarted.reconcile_pending(&journal).unwrap();
    assert!(artifact.exists());
    assert!(restarted.pending_binding().unwrap().is_none());
}

#[test]
fn disabled_journal_is_rejected_before_existing_artifact_is_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let journal = WitnessJournal::open(JournalConfig::new(
        dir.path().join("journal"),
        [73; 16],
        JournalMode::Disabled,
    ))
    .unwrap();
    let published = dir.path().join("published");
    fs::create_dir(&published).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&published, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let artifact = published.join("head.chk");
    fs::write(&artifact, b"previous-bound-artifact").unwrap();
    let before = fs::read(&artifact).unwrap();
    let coordinator = ferro_core::witness::CheckpointCoordinator::new(
        &artifact,
        Duration::from_secs(5),
        Duration::from_secs(1),
    );
    let key = SigningKey::from_bytes(&[73; 32]);
    assert!(matches!(
        coordinator.capture_publish_bind(&journal, 1, &key, None, publication_record),
        Err(ferro_core::witness::CheckpointError::Journal(
            ferro_core::witness::JournalError::Disabled
        ))
    ));
    assert_eq!(fs::read(&artifact).unwrap(), before);
    assert!(coordinator.pending_binding().unwrap().is_none());
}

#[test]
fn definite_post_publication_failure_is_terminal_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    let faults = JournalFaults::new();
    faults.fail_once(FaultPoint::CheckpointBindingRejected);
    let journal = WitnessJournal::open_with_faults(
        JournalConfig::new(dir.path().join("journal"), [74; 16], JournalMode::Required),
        faults,
    )
    .unwrap();
    let published = dir.path().join("published");
    fs::create_dir(&published).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&published, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let artifact = published.join("head.chk");
    let coordinator = ferro_core::witness::CheckpointCoordinator::new(
        &artifact,
        Duration::from_secs(5),
        Duration::from_secs(1),
    );
    let key = SigningKey::from_bytes(&[74; 32]);
    assert!(coordinator
        .capture_publish_bind(&journal, 1, &key, None, publication_record)
        .is_err());
    drop(coordinator);
    let restarted = ferro_core::witness::CheckpointCoordinator::new(
        &artifact,
        Duration::from_secs(5),
        Duration::from_secs(1),
    );
    let terminal = restarted.pending_binding().unwrap().unwrap();
    assert_eq!(
        terminal.state(),
        ferro_core::witness::PendingState::BindingFailed
    );
    assert_eq!(
        terminal.recoverability(),
        ferro_core::witness::Recoverability::OperatorRequired
    );
    assert!(matches!(
        restarted.reconcile_pending(&journal),
        Err(ferro_core::witness::CheckpointError::BindingFailed)
    ));
    assert!(matches!(
        restarted.capture_publish_bind(&journal, 2, &key, None, publication_record),
        Err(ferro_core::witness::CheckpointError::PendingExists)
    ));
}

#[test]
fn stale_reset_sidecar_fails_terminally_when_journal_advanced_past_it() {
    let dir = tempfile::tempdir().unwrap();
    let faults = JournalFaults::new();
    let journal = WitnessJournal::open_with_faults(
        JournalConfig::new(dir.path().join("journal"), [75; 16], JournalMode::Required),
        faults.clone(),
    )
    .unwrap();
    let published = dir.path().join("published");
    fs::create_dir(&published).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&published, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let first_coord = ferro_core::witness::CheckpointCoordinator::new(
        published.join("one.chk"),
        Duration::from_secs(5),
        Duration::from_secs(1),
    );
    let old = SigningKey::from_bytes(&[75; 32]);
    let next = SigningKey::from_bytes(&[76; 32]);
    let third = SigningKey::from_bytes(&[77; 32]);
    let first = match first_coord
        .capture_publish_bind(&journal, 1, &old, None, publication_record)
        .unwrap()
    {
        ferro_core::witness::PublicationOutcome::Bound(cp) => cp,
        _ => panic!(),
    };
    faults.fail_once(FaultPoint::DuringFlush(FlushBoundary::Outcome));
    let stale = match first_coord
        .capture_reset_publish_bind(&journal, 2, &next, &first, publication_record)
        .unwrap()
    {
        ferro_core::witness::PublicationOutcome::PendingBinding(p) => p,
        _ => panic!(),
    };
    let second_coord = ferro_core::witness::CheckpointCoordinator::new(
        published.join("two.chk"),
        Duration::from_secs(5),
        Duration::from_secs(1),
    );
    let reset2 = match second_coord
        .capture_reset_publish_bind(&journal, 3, &third, stale.checkpoint(), publication_record)
        .unwrap()
    {
        ferro_core::witness::PublicationOutcome::Bound(cp) => cp,
        _ => panic!(),
    };
    assert_eq!(reset2.head.epoch, 3);
    assert!(first_coord.reconcile_pending(&journal).is_err());
    drop(first_coord);
    let reopened = ferro_core::witness::CheckpointCoordinator::new(
        published.join("one.chk"),
        Duration::from_secs(5),
        Duration::from_secs(1),
    );
    assert_eq!(
        reopened.pending_binding().unwrap().unwrap().state(),
        ferro_core::witness::PendingState::BindingFailed
    );
}

#[test]
fn pending_binding_rejects_tampering_and_a_cross_journal_reconcile() {
    let dir = tempfile::tempdir().unwrap();
    let faults = JournalFaults::new();
    faults.fail_once(FaultPoint::DuringFlush(FlushBoundary::Outcome));
    let journal = WitnessJournal::open_with_faults(
        JournalConfig::new(dir.path().join("one"), [63; 16], JournalMode::Required),
        faults,
    )
    .unwrap();
    let published = dir.path().join("published");
    fs::create_dir(&published).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&published, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = published.join("head.chk");
    let coordinator = ferro_core::witness::CheckpointCoordinator::new(
        &path,
        Duration::from_secs(5),
        Duration::from_secs(1),
    );
    let key = SigningKey::from_bytes(&[63; 32]);
    coordinator
        .capture_publish_bind(&journal, 1, &key, None, publication_record)
        .unwrap();
    let other = WitnessJournal::open(JournalConfig::new(
        dir.path().join("two"),
        [64; 16],
        JournalMode::Required,
    ))
    .unwrap();
    assert!(coordinator.reconcile_pending(&other).is_err());
    let pending_path = published.join("head.chk.pending");
    let mut bytes = fs::read(&pending_path).unwrap();
    bytes[20] ^= 1;
    fs::write(&pending_path, bytes).unwrap();
    assert!(coordinator.pending_binding().is_err());
}

#[test]
fn independently_pinned_chunks_enforce_exact_boundary() {
    let key = SigningKey::from_bytes(&[71; 32]);
    let first = Checkpoint::sign(
        FlushedHead::new([71; 16], 1, 0, [0; 32]),
        1,
        &key,
        CheckpointKind::Periodic,
    )
    .unwrap();
    let first_evidence = publication_evidence(&first);
    CheckpointVerifier::new(TrustBundle::new([71; 16], key.verifying_key()).with_max_records(1))
        .verify(
            &first_evidence,
            std::slice::from_ref(&first),
            1,
            Duration::from_secs(5),
        )
        .unwrap();
    let predecessor = publication_hash(&first);
    let second = Checkpoint::sign_chunk_after(
        FlushedHead::new([71; 16], 1, 1, predecessor),
        2,
        2,
        &first,
        &key,
    )
    .unwrap();
    let trust = TrustBundle::from_boundary(
        [71; 16],
        1,
        2,
        predecessor,
        first.clone(),
        key.verifying_key(),
    )
    .unwrap()
    .with_max_records(1);
    CheckpointVerifier::new(trust)
        .verify(
            &publication_evidence(&second),
            std::slice::from_ref(&second),
            2,
            Duration::from_secs(5),
        )
        .unwrap();
    assert!(TrustBundle::from_boundary(
        [71; 16],
        2,
        2,
        predecessor,
        first.clone(),
        key.verifying_key()
    )
    .is_err());
    let wrong =
        TrustBundle::from_boundary([71; 16], 1, 2, [9; 32], first, key.verifying_key()).unwrap();
    assert!(CheckpointVerifier::new(wrong)
        .verify(
            &publication_evidence(&second),
            &[second],
            2,
            Duration::from_secs(5)
        )
        .is_err());
}
