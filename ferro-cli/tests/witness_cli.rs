use sha2::{Digest, Sha256};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{fs, os::unix::fs::PermissionsExt};

fn cli(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_ferro-cli"))
        .args(args)
        .env_remove("SUDO_USER")
        .output()
        .expect("run ferrocrate")
}

fn cli_runtime(args: &[&str], runtime: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_ferro-cli"))
        .args(args)
        .env("FERROCRATE_RUNTIME_DIR", runtime)
        .output()
        .expect("run ferrocrate")
}

#[test]
fn administrative_command_tree_is_exposed_by_the_actual_binary() {
    for command in ["policy", "witness", "emergency"] {
        let output = cli(&[command, "--help"]);
        assert!(
            output.status.success(),
            "{command}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn witness_verify_requires_explicit_trust_and_minimum_inputs() {
    let output = cli(&["witness", "verify", "--journal", "/no/such/journal"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--trust-bundle"), "{stderr}");
    assert!(stderr.contains("--minimum-checkpoint"), "{stderr}");
}

#[test]
fn emergency_is_not_exposed_on_remote_surfaces() {
    for origin in ["docker", "cri", "remote"] {
        let output = cli(&["emergency", "activate", "--origin", origin]);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("local-console-only"));
    }
}

fn protected_write(path: &std::path::Path, bytes: impl AsRef<[u8]>) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn provision_admission(auth_dir: &std::path::Path, id: [u8; 16]) {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x77; 32]);
    provision_admission_with_key(auth_dir, id, &key);
}

fn provision_admission_with_key(
    auth_dir: &std::path::Path,
    id: [u8; 16],
    key: &ed25519_dalek::SigningKey,
) {
    use sha2::Digest;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let checkpoint = ferro_core::witness::Checkpoint::sign(
        ferro_core::witness::FlushedHead::new(id, 1, 0, [0; 32]),
        now,
        &key,
        ferro_core::witness::CheckpointKind::Periodic,
    )
    .unwrap();
    let admission = auth_dir.join("admission");
    fs::create_dir(&admission).unwrap();
    fs::set_permissions(&admission, fs::Permissions::from_mode(0o700)).unwrap();
    let checkpoint_bytes = checkpoint.encode();
    protected_write(&admission.join("minimum.bin"), &checkpoint_bytes);
    protected_write(&admission.join("checkpoint-0001.bin"), &checkpoint_bytes);
    let id_hex = id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let public = key
        .verifying_key()
        .to_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let trust = serde_json::to_vec(&serde_json::json!({
        "schema": 1, "journal_id": id_hex, "initial_public_key": public, "starting_epoch": 1
    }))
    .unwrap();
    protected_write(&admission.join("trust.json"), &trust);
    let digest = |bytes: &[u8]| {
        sha2::Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let key_id = digest(key.verifying_key().as_bytes());
    let manifest = ferro_core::authorization::admission::AdmissionSnapshotManifest {
        schema: 1,
        generation: 1,
        journal_id: id.iter().map(|byte| format!("{byte:02x}")).collect(),
        trust_bundle: ferro_core::authorization::admission::AdmissionArtifact {
            file: "trust.json".into(),
            sha256: digest(&trust),
        },
        minimum_checkpoint: ferro_core::authorization::admission::AdmissionArtifact {
            file: "minimum.bin".into(),
            sha256: digest(&checkpoint_bytes),
        },
        checkpoint_chain: vec![ferro_core::authorization::admission::AdmissionArtifact {
            file: "checkpoint-0001.bin".into(),
            sha256: digest(&checkpoint_bytes),
        }],
        trust_key_ids: vec![key_id],
        latest_checkpoint: "checkpoint-0001.bin".into(),
        latest_created_at_secs: now,
    };
    protected_write(
        &admission.join("manifest.json"),
        serde_json::to_vec(&manifest).unwrap(),
    );
}

#[test]
fn policy_check_prints_stable_version_rule_reason_and_digest() {
    let temp = tempfile::tempdir().unwrap();
    let policy = temp.path().join("policy.toml");
    protected_write(
        &policy,
        b"schema_version = 1\ngeneration = 7\nmode = \"enforce\"\n",
    );
    let output = cli(&["policy", "check", policy.to_str().unwrap()]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    for field in [
        "allowed=true",
        "reason=policy-valid",
        "rule=policy.schema",
        "policy_version=7",
        "policy_digest=",
    ] {
        assert!(text.contains(field), "missing {field}: {text}");
    }
}

#[test]
fn policy_reload_rejects_rollback_without_exact_separate_approval() {
    if nix::unistd::geteuid().as_raw() != 0 {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let auth_dir = temp.path().join("authorization");
    fs::create_dir(&auth_dir).unwrap();
    fs::set_permissions(&auth_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let active = auth_dir.join("active-policy.toml");
    protected_write(
        &auth_dir.join("journal-id"),
        b"42424242424242424242424242424242\n",
    );
    provision_admission(&auth_dir, [0x42; 16]);
    let older = temp.path().join("older.toml");
    protected_write(
        &active,
        b"schema_version = 1\ngeneration = 9\nmode = \"enforce\"\n",
    );
    protected_write(
        &older,
        b"schema_version = 1\ngeneration = 8\nmode = \"enforce\"\n",
    );
    let output = cli_runtime(&["policy", "reload", older.to_str().unwrap()], temp.path());
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(
        error.contains("reason=policy-generation-rollback"),
        "{error}"
    );

    let approval = temp.path().join("rollback.approval");
    let digest: [u8; 32] = Sha256::digest(fs::read(&older).unwrap()).into();
    let hex = digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    protected_write(
        &approval,
        format!("FERROCRATE-POLICY-ROLLBACK-V1\n9\n8\n{hex}\n"),
    );
    let output = cli_runtime(
        &[
            "policy",
            "reload",
            older.to_str().unwrap(),
            "--rollback-approval",
            approval.to_str().unwrap(),
        ],
        temp.path(),
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("policy_version=8"));
    let runtime = ferro_core::runtime::ContainerRuntime::new(temp.path()).unwrap();
    assert_eq!(runtime.policy_binding().0, 8);
    drop(runtime);
    let mut reader = ferro_core::witness::WitnessReader::open_read_only(
        auth_dir.join("witness-journal"),
        [0x42; 16],
    )
    .unwrap();
    let mut saw_rollback = false;
    while let Some(bytes) = reader.next_record().unwrap() {
        let record = ferro_core::witness::decode_record(&bytes).unwrap();
        saw_rollback |= record.action() == ferro_core::witness::WitnessAction::PolicyRollback;
    }
    reader.finish().unwrap();
    assert!(
        saw_rollback,
        "authorized rollback must be durably witnessed"
    );
}

#[test]
fn unreconciled_emergency_state_blocks_normal_commands_after_restart() {
    let temp = tempfile::tempdir().unwrap();
    let state_dir = temp.path().join("authorization");
    fs::create_dir_all(&state_dir).unwrap();
    protected_write(&state_dir.join("emergency-active.json"), b"durable-marker");
    let output = Command::new(env!("CARGO_BIN_EXE_ferro-cli"))
        .args(["images"])
        .env("FERROCRATE_RUNTIME_DIR", temp.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("reconciliation is required"));
}

#[test]
fn witness_show_is_bounded_and_rejects_unbounded_requests() {
    let temp = tempfile::tempdir().unwrap();
    let missing = temp.path().join("missing-journal");
    let output = cli(&[
        "witness",
        "show",
        "--journal",
        missing.to_str().unwrap(),
        "--journal-id",
        "00000000000000000000000000000000",
        "--limit",
        "1001",
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("between 1 and 1000"));
    let readonly = cli(&[
        "witness",
        "show",
        "--journal",
        missing.to_str().unwrap(),
        "--journal-id",
        "00000000000000000000000000000000",
    ]);
    assert!(!readonly.status.success());
    assert!(!missing.exists());
}

#[test]
fn checkpoint_show_and_verify_use_real_journal_and_explicit_trust() {
    if nix::unistd::geteuid().as_raw() != 0 {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let auth_dir = temp.path().join("authorization");
    fs::create_dir(&auth_dir).unwrap();
    fs::set_permissions(&auth_dir, fs::Permissions::from_mode(0o700)).unwrap();
    protected_write(
        &auth_dir.join("active-policy.toml"),
        b"schema_version = 1\ngeneration = 1\nmode = \"enforce\"\n",
    );
    let journal_path = auth_dir.join("witness-journal");
    let key_dir = temp.path().join("keys");
    fs::create_dir(&key_dir).unwrap();
    fs::set_permissions(&key_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let id = [0x31; 16];
    let id_hex = id.iter().map(|b| format!("{b:02x}")).collect::<String>();
    protected_write(&auth_dir.join("journal-id"), format!("{id_hex}\n"));
    let journal =
        ferro_core::witness::WitnessJournal::open(ferro_core::witness::JournalConfig::new(
            &journal_path,
            id,
            ferro_core::witness::JournalMode::Required,
        ))
        .unwrap();
    drop(journal);
    let key = ferro_core::witness::KeyStore::new(&key_dir)
        .create("active")
        .unwrap();
    provision_admission_with_key(&auth_dir, id, key.signing_key());
    let public = key
        .verifying_key()
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let artifact = auth_dir.join("checkpoint.bin");
    let output = cli_runtime(
        &[
            "witness",
            "checkpoint",
            "--journal",
            journal_path.to_str().unwrap(),
            "--journal-id",
            &id_hex,
            "--artifact",
            artifact.to_str().unwrap(),
            "--key-dir",
            key_dir.to_str().unwrap(),
            "--key-name",
            "active",
        ],
        temp.path(),
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("checkpoint bound"));
    let published_manifest: ferro_core::authorization::admission::AdmissionSnapshotManifest =
        serde_json::from_slice(&fs::read(auth_dir.join("admission/manifest.json")).unwrap())
            .unwrap();
    assert_eq!(published_manifest.generation, 2);
    assert_eq!(published_manifest.checkpoint_chain.len(), 2);
    assert_eq!(
        published_manifest.latest_checkpoint,
        "checkpoint-00000000000000000002.bin"
    );

    let live_writer =
        ferro_core::witness::WitnessJournal::open(ferro_core::witness::JournalConfig::new(
            &journal_path,
            id,
            ferro_core::witness::JournalMode::Required,
        ))
        .unwrap();

    let show = cli(&[
        "witness",
        "show",
        "--journal",
        journal_path.to_str().unwrap(),
        "--journal-id",
        &id_hex,
    ]);
    assert!(
        show.status.success(),
        "{}",
        String::from_utf8_lossy(&show.stderr)
    );
    assert!(String::from_utf8_lossy(&show.stdout).contains("CheckpointPublished"));

    let trust = temp.path().join("trust.json");
    protected_write(&trust, serde_json::to_vec(&serde_json::json!({"schema":1,"journal_id":id_hex,"initial_public_key":public,"starting_epoch":1})).unwrap());
    let verify = cli(&[
        "witness",
        "verify",
        "--journal",
        journal_path.to_str().unwrap(),
        "--trust-bundle",
        trust.to_str().unwrap(),
        "--minimum-checkpoint",
        artifact.to_str().unwrap(),
        "--checkpoint",
        artifact.to_str().unwrap(),
    ]);
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let report = String::from_utf8_lossy(&verify.stdout);
    for dimension in [
        "integrity=true",
        "lifecycle_consistency=true",
        "completeness=true",
        "freshness=",
    ] {
        assert!(report.contains(dimension), "missing {dimension}: {report}");
    }
    assert!(
        !report.contains("verified=true"),
        "must not collapse dimensions: {report}"
    );
    drop(live_writer);

    let first = temp.path().join("first-checkpoint.bin");
    fs::copy(&artifact, &first).unwrap();
    let rotate = cli_runtime(
        &[
            "witness",
            "rotate-key",
            "--journal",
            journal_path.to_str().unwrap(),
            "--journal-id",
            &id_hex,
            "--artifact",
            artifact.to_str().unwrap(),
            "--key-dir",
            key_dir.to_str().unwrap(),
            "--old-key",
            "active",
            "--new-key",
            "successor",
            "--predecessor",
            first.to_str().unwrap(),
        ],
        temp.path(),
    );
    assert!(
        rotate.status.success(),
        "{}",
        String::from_utf8_lossy(&rotate.stderr)
    );
    let rotation_output = String::from_utf8_lossy(&rotate.stdout);
    assert!(rotation_output.contains("checkpoint bound"));
    assert!(rotation_output.contains("new_key_id="));
    assert!(!rotation_output.contains("private"));
    assert!(!rotation_output.contains(&public));

    let verify_rotation = cli(&[
        "witness",
        "verify",
        "--journal",
        journal_path.to_str().unwrap(),
        "--trust-bundle",
        trust.to_str().unwrap(),
        "--minimum-checkpoint",
        artifact.to_str().unwrap(),
        "--checkpoint",
        first.to_str().unwrap(),
        "--checkpoint",
        artifact.to_str().unwrap(),
    ]);
    assert!(
        verify_rotation.status.success(),
        "{}",
        String::from_utf8_lossy(&verify_rotation.stderr)
    );
    assert!(String::from_utf8_lossy(&verify_rotation.stdout).contains("completeness=true"));
}
