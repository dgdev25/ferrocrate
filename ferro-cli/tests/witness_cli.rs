use sha2::{Digest, Sha256};
use std::process::Command;
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
    let active = temp.path().join("active.toml");
    let older = temp.path().join("older.toml");
    protected_write(
        &active,
        b"schema_version = 1\ngeneration = 9\nmode = \"enforce\"\n",
    );
    protected_write(
        &older,
        b"schema_version = 1\ngeneration = 8\nmode = \"enforce\"\n",
    );
    let output = cli_runtime(
        &[
            "policy",
            "reload",
            older.to_str().unwrap(),
            "--active",
            active.to_str().unwrap(),
        ],
        temp.path(),
    );
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
            "--active",
            active.to_str().unwrap(),
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
    let output = cli(&[
        "witness",
        "show",
        "--journal",
        "/unused",
        "--journal-id",
        "00000000000000000000000000000000",
        "--limit",
        "1001",
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("between 1 and 1000"));
}

#[test]
fn checkpoint_show_and_verify_use_real_journal_and_explicit_trust() {
    if nix::unistd::geteuid().as_raw() != 0 {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let journal_path = temp.path().join("journal");
    let key_dir = temp.path().join("keys");
    fs::create_dir(&key_dir).unwrap();
    fs::set_permissions(&key_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let id = [0x31; 16];
    let id_hex = id.iter().map(|b| format!("{b:02x}")).collect::<String>();
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
    let public = key
        .verifying_key()
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let artifact = temp.path().join("checkpoint.bin");
    let output = cli(&[
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
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("checkpoint bound"));

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

    let first = temp.path().join("first-checkpoint.bin");
    fs::copy(&artifact, &first).unwrap();
    let rotate = cli(&[
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
    ]);
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
