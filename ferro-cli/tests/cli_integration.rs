use std::process::Command;

#[cfg(target_os = "linux")]
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

fn bin() -> (Command, tempfile::TempDir) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ferro-cli"));
    let temp = tempfile::tempdir().expect("tempdir");
    cmd.env("FERROCRATE_RUNTIME_DIR", temp.path());
    cmd.env("FERROCRATE_IMAGE_STORE", temp.path().join("images"));
    cmd.env("FERROCRATE_DESKTOP_FORWARD", "0");
    (cmd, temp)
}

#[test]
fn images_command_succeeds() {
    let (mut cmd, _temp) = bin();
    let status = cmd.arg("images").status().expect("run ferro-cli");
    assert!(status.success());
}

#[cfg(target_os = "linux")]
#[test]
fn containers_command_succeeds() {
    let (mut cmd, _temp) = bin();
    let status = cmd.arg("containers").status().expect("run ferro-cli");
    assert!(status.success());
}

#[cfg(target_os = "linux")]
#[test]
fn logs_requires_container() {
    let (mut cmd, _temp) = bin();
    let output = cmd.arg("logs").output().expect("run ferro-cli");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("required arguments were not provided"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn pull_rejects_invalid_image() {
    let (mut cmd, _temp) = bin();
    let output = cmd.args(["pull", ""]).output().expect("run ferro-cli");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid image reference"),
        "unexpected stderr: {stderr}"
    );
}

#[cfg(target_os = "linux")]
fn protected(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("write protected fixture");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("protect fixture");
}

#[cfg(target_os = "linux")]
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Produces exactly the signed admission snapshot that the production runtime
/// loader accepts. The subprocess still constructs its authorization gate
/// through `ContainerRuntime::new`; this fixture only supplies its protected
/// on-disk authority inputs.
#[cfg(target_os = "linux")]
fn provision_admission(auth: &Path, id: [u8; 16]) {
    use ed25519_dalek::SigningKey;
    use sha2::Digest;

    let key = SigningKey::from_bytes(&[0x54; 32]);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs();
    let journal =
        ferro_core::witness::WitnessJournal::open(ferro_core::witness::JournalConfig::new(
            auth.join("witness-journal"),
            id,
            ferro_core::witness::JournalMode::Required,
        ))
        .expect("initialize production witness journal");
    let checkpoint = ferro_core::witness::Checkpoint::sign(
        ferro_core::witness::FlushedHead::new(id, 1, 0, [0; 32]),
        now.saturating_sub(1),
        &key,
        ferro_core::witness::CheckpointKind::Periodic,
    )
    .expect("sign checkpoint");
    let admission = auth.join("admission");
    fs::create_dir(&admission).expect("create admission directory");
    fs::set_permissions(&admission, fs::Permissions::from_mode(0o700))
        .expect("protect admission directory");
    let checkpoint_bytes = checkpoint.encode();
    let checkpoint_digest: [u8; 32] = sha2::Sha256::digest(&checkpoint_bytes).into();
    journal
        .append_checkpoint_publication(
            checkpoint_digest,
            ferro_core::witness::WitnessRecord {
                epoch: 1,
                sequence: 1,
                previous_hash: [0; 32],
                event_id: [0x54; 16],
                request_id: [0x55; 16],
                runtime_instance_id: [0x56; 16],
                boot_id: [0x57; 16],
                principal: ferro_core::witness::PrincipalSummary::pseudonymize(
                    &[0x58; 32],
                    b"qualification",
                )
                .expect("pseudonymize principal"),
                invocation: ferro_core::witness::Invocation::Manager,
                action: ferro_core::witness::WitnessAction::CheckpointPublish,
                resource_kind: ferro_core::witness::WitnessResourceKind::Administrative,
                resource: ferro_core::witness::ResourceSummary::pseudonymize(
                    &[0x59; 32],
                    b"checkpoint",
                )
                .expect("pseudonymize resource"),
                resource_generation: 1,
                policy_version: 0,
                policy_digest: [0; 32],
                decision_id: None,
                rule: None,
                decision: None,
                reason: None,
                request_digest: checkpoint_digest,
                result_digest: Some(checkpoint_digest),
                wall_time_ns: 0,
                monotonic_ns: 0,
                stage: ferro_core::witness::WitnessStage::CheckpointPublished,
                outcome: ferro_core::witness::WitnessOutcome::Succeeded,
                recovery_link: None,
                path_class: None,
                device_class: None,
                correlation_digest: None,
            },
        )
        .expect("record checkpoint publication");
    protected(&admission.join("minimum.bin"), &checkpoint_bytes);
    protected(&admission.join("checkpoint-0001.bin"), &checkpoint_bytes);
    let trust = serde_json::to_vec(&serde_json::json!({
        "schema": 1, "journal_id": hex(&id),
        "initial_public_key": hex(key.verifying_key().as_bytes()), "starting_epoch": 1,
    }))
    .expect("serialize trust bundle");
    protected(&admission.join("trust.json"), &trust);
    let digest = |bytes: &[u8]| hex(&sha2::Sha256::digest(bytes));
    let manifest = ferro_core::authorization::admission::AdmissionSnapshotManifest {
        schema: 1,
        generation: 1,
        journal_id: hex(&id),
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
        trust_key_ids: vec![digest(key.verifying_key().as_bytes())],
        latest_checkpoint: "checkpoint-0001.bin".into(),
        latest_created_at_secs: now.saturating_sub(1),
    };
    protected(
        &admission.join("manifest.json"),
        &serde_json::to_vec(&manifest).expect("serialize admission manifest"),
    );
    drop(journal);
}

#[cfg(target_os = "linux")]
pub fn configured_runtime(mode: &str) -> tempfile::TempDir {
    let runtime = tempfile::tempdir().expect("runtime directory");
    fs::set_permissions(runtime.path(), fs::Permissions::from_mode(0o700))
        .expect("protect runtime directory");
    if mode == "disabled" {
        return runtime;
    }
    let auth = runtime.path().join("authorization");
    fs::create_dir(&auth).expect("create authorization directory");
    fs::set_permissions(&auth, fs::Permissions::from_mode(0o700))
        .expect("protect authorization directory");
    let id = [0x44; 16];
    protected(
        &auth.join("active-policy.toml"),
        format!("schema_version = 1\ngeneration = 1\nmode = \"{mode}\"\n").as_bytes(),
    );
    protected(
        &auth.join("journal-id"),
        format!("{}\n", hex(&id)).as_bytes(),
    );
    provision_admission(&auth, id);
    runtime
}

#[cfg(target_os = "linux")]
#[test]
fn public_cli_volume_mutation_preserves_disabled_shadow_and_enforce_contracts() {
    for mode in ["disabled", "shadow"] {
        let runtime = configured_runtime(mode);
        let output = Command::new(env!("CARGO_BIN_EXE_ferro-cli"))
            .env("FERROCRATE_RUNTIME_DIR", runtime.path())
            .args(["volume", "create", &format!("{mode}-volume")])
            .output()
            .expect("execute public CLI mutation");
        assert!(
            output.status.success(),
            "{mode}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let store =
            ferro_core::volume_store::LocalVolumeStore::open(runtime.path().join("volumes"))
                .expect("open production volume store");
        assert!(store
            .get(&format!("{mode}-volume"))
            .expect("read volume")
            .is_some());
    }

    let runtime = configured_runtime("enforce");
    let output = Command::new(env!("CARGO_BIN_EXE_ferro-cli"))
        .env("FERROCRATE_RUNTIME_DIR", runtime.path())
        .args(["volume", "create", "enforced-volume"])
        .output()
        .expect("execute public CLI mutation");
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(
        error.contains("authorization denied for ") && error.contains(": PolicyDenied"),
        "stable public enforce error: {error}"
    );
    let store = ferro_core::volume_store::LocalVolumeStore::open(runtime.path().join("volumes"))
        .expect("open production volume store");
    assert!(store.get("enforced-volume").expect("read volume").is_none());
}
