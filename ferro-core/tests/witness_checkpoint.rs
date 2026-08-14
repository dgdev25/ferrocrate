use ed25519_dalek::SigningKey;
use ferro_core::witness::{
    decode_record, encode_record, Checkpoint, CheckpointKind, CheckpointVerifier, FlushedHead,
    Invocation, JournalConfig, JournalMode, KeyStore, PrincipalSummary, ResourceSummary,
    TrustBundle, WitnessAction, WitnessJournal, WitnessOutcome, WitnessRecord, WitnessResourceKind,
    WitnessStage,
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
    let path = dir.path().join("published/checkpoint.bin");
    let coordinator = ferro_core::witness::CheckpointCoordinator::new(
        &path,
        Duration::from_secs(60),
        Duration::from_secs(10),
    );
    let checkpoint = coordinator
        .capture_and_publish(&journal, 100, &key)
        .unwrap();
    assert_eq!(checkpoint.head, FlushedHead::new([12; 16], 1, 0, [0; 32]));
    assert_eq!(
        Checkpoint::decode(&fs::read(path).unwrap()).unwrap(),
        checkpoint
    );
    coordinator
        .publish_and_bind(&journal, &checkpoint, publication_record(&checkpoint))
        .unwrap();
    let evidence = journal.records().unwrap();
    let trust = TrustBundle::new([12; 16], key.verifying_key());
    assert!(CheckpointVerifier::new(trust)
        .verify(&evidence, &[checkpoint], 100, Duration::from_secs(60))
        .is_ok());
}

#[test]
fn failed_checkpoint_replacement_never_exposes_partial_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("occupied");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("sentinel"), b"intact").unwrap();
    let key = SigningKey::from_bytes(&[13; 32]);
    let checkpoint = Checkpoint::sign(
        FlushedHead::new([1; 16], 1, 1, [2; 32]),
        1,
        &key,
        CheckpointKind::Periodic,
    )
    .unwrap();
    let coordinator = ferro_core::witness::CheckpointCoordinator::new(
        &target,
        Duration::from_secs(1),
        Duration::from_secs(1),
    );
    assert!(coordinator.publish(&checkpoint).is_err());
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
    assert!(report.unknown_tail_freshness);

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
}
