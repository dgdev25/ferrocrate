use ed25519_dalek::SigningKey;
use ferro_core::witness::{
    Checkpoint, CheckpointKind, CheckpointVerifier, FlushedHead, JournalConfig, JournalMode,
    KeyStore, TrustBundle, WitnessJournal,
};
use std::{fs, time::Duration};

#[test]
fn key_store_creates_owner_only_key_and_stable_id() {
    let dir = tempfile::tempdir().unwrap();
    let store = KeyStore::new(dir.path());
    let first = store.create("active").unwrap();
    let loaded = store.load("active").unwrap();
    assert_eq!(first.key_id(), loaded.key_id());
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            fs::metadata(dir.path().join("active.key")).unwrap().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn key_store_refuses_symlink_and_checkpoint_frame_is_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let outside = dir.path().join("outside");
    fs::write(&outside, [0_u8; 32]).unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&outside, dir.path().join("linked.key")).unwrap();
        assert!(KeyStore::new(dir.path()).load("linked").is_err());
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
    let head = FlushedHead::new([1; 16], 1, 9, [2; 32]);
    let checkpoint = Checkpoint::sign(head, 50, &key, CheckpointKind::Periodic).unwrap();
    let trust = TrustBundle::new([1; 16], key.verifying_key()).with_minimum(checkpoint.clone());
    let report = CheckpointVerifier::new(trust.clone())
        .verify(&[checkpoint], 55, Duration::from_secs(10))
        .unwrap();
    assert!(report.integrity);
    assert!(report.lifecycle_consistent);
    assert_eq!(report.completeness_through_checkpoint, Some(true));
    assert!(report.unknown_tail_freshness);

    let older = Checkpoint::sign(
        FlushedHead::new([1; 16], 1, 8, [3; 32]),
        49,
        &key,
        CheckpointKind::Periodic,
    )
    .unwrap();
    assert!(CheckpointVerifier::new(trust)
        .verify(&[older], 55, Duration::from_secs(10))
        .is_err());
}

#[test]
fn rotation_is_dual_signed_and_untrusted_branch_is_rejected() {
    let old = SigningKey::from_bytes(&[3; 32]);
    let new = SigningKey::from_bytes(&[4; 32]);
    let root = Checkpoint::sign(
        FlushedHead::new([8; 16], 1, 2, [9; 32]),
        10,
        &old,
        CheckpointKind::Periodic,
    )
    .unwrap();
    let rotation =
        Checkpoint::rotate(FlushedHead::new([8; 16], 1, 3, [10; 32]), 11, &old, &new).unwrap();
    let trust = TrustBundle::new([8; 16], old.verifying_key());
    assert!(CheckpointVerifier::new(trust.clone())
        .verify(&[root, rotation], 12, Duration::from_secs(5))
        .is_ok());

    let attacker = SigningKey::from_bytes(&[5; 32]);
    let branch = Checkpoint::rotate(
        FlushedHead::new([8; 16], 1, 3, [10; 32]),
        11,
        &attacker,
        &new,
    )
    .unwrap();
    assert!(CheckpointVerifier::new(trust)
        .verify(&[branch], 12, Duration::from_secs(5))
        .is_err());
}

#[test]
fn key_loss_requires_explicit_new_epoch_discontinuity() {
    let old = SigningKey::from_bytes(&[1; 32]);
    let new = SigningKey::from_bytes(&[2; 32]);
    let reset =
        Checkpoint::trust_reset(FlushedHead::new([6; 16], 2, 1, [7; 32]), 20, &new, 1).unwrap();
    let trust =
        TrustBundle::new([6; 16], old.verifying_key()).allow_epoch_reset(2, new.verifying_key());
    let report = CheckpointVerifier::new(trust)
        .verify(&[reset], 20, Duration::from_secs(1))
        .unwrap();
    assert_eq!(report.discontinuities, 1);
}
