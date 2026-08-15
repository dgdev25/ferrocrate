//! Shared on-disk authorization authority for public qualification tests.
//!
//! It deliberately creates only protected production inputs. Callers must
//! create their runtime through `ContainerRuntime::new` (or their public
//! process/socket entry point), never through a test-only authorization gate.

use ed25519_dalek::SigningKey;
use ferro_core::{
    authorization::admission::{AdmissionArtifact, AdmissionSnapshotManifest},
    witness::{
        Checkpoint, CheckpointKind, FlushedHead, Invocation, JournalConfig, JournalMode,
        PrincipalSummary, ResourceSummary, WitnessAction, WitnessJournal, WitnessOutcome,
        WitnessRecord, WitnessResourceKind, WitnessStage,
    },
};
use sha2::Digest;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub const JOURNAL_ID: [u8; 16] = [0x44; 16];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn protected(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("write protected qualification fixture");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .expect("protect qualification fixture");
}

/// Construct a protected runtime directory with a signed active policy and
/// admission checkpoint. Disabled deliberately has no active policy, exactly
/// as the production compatibility loader expects.
pub fn configured_runtime(mode: &str) -> tempfile::TempDir {
    assert!(matches!(mode, "disabled" | "shadow" | "enforce"));
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
    protected(
        &auth.join("active-policy.toml"),
        format!("schema_version = 1\ngeneration = 1\nmode = \"{mode}\"\n").as_bytes(),
    );
    protected(
        &auth.join("journal-id"),
        format!("{}\n", hex(&JOURNAL_ID)).as_bytes(),
    );

    let key = SigningKey::from_bytes(&[0x54; 32]);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs();
    let journal = WitnessJournal::open(JournalConfig::new(
        auth.join("witness-journal"),
        JOURNAL_ID,
        JournalMode::Required,
    ))
    .expect("open production witness journal");
    let checkpoint = Checkpoint::sign(
        FlushedHead::new(JOURNAL_ID, 1, 0, [0; 32]),
        now.saturating_sub(1),
        &key,
        CheckpointKind::Periodic,
    )
    .expect("sign checkpoint");
    let checkpoint_bytes = checkpoint.encode();
    let checkpoint_digest: [u8; 32] = sha2::Sha256::digest(&checkpoint_bytes).into();
    journal
        .append_checkpoint_publication(
            checkpoint_digest,
            WitnessRecord {
                epoch: 1,
                sequence: 1,
                previous_hash: [0; 32],
                event_id: [0x54; 16],
                request_id: [0x55; 16],
                runtime_instance_id: [0x56; 16],
                boot_id: [0x57; 16],
                principal: PrincipalSummary::pseudonymize(&[0x58; 32], b"qualification")
                    .expect("pseudonymize principal"),
                invocation: Invocation::Manager,
                action: WitnessAction::CheckpointPublish,
                resource_kind: WitnessResourceKind::Administrative,
                resource: ResourceSummary::pseudonymize(&[0x59; 32], b"checkpoint")
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
                stage: WitnessStage::CheckpointPublished,
                outcome: WitnessOutcome::Succeeded,
                recovery_link: None,
                path_class: None,
                device_class: None,
                correlation_digest: None,
            },
        )
        .expect("record checkpoint publication");
    let admission = auth.join("admission");
    fs::create_dir(&admission).expect("create admission directory");
    fs::set_permissions(&admission, fs::Permissions::from_mode(0o700))
        .expect("protect admission directory");
    protected(&admission.join("minimum.bin"), &checkpoint_bytes);
    protected(&admission.join("checkpoint-0001.bin"), &checkpoint_bytes);
    let trust = serde_json::to_vec(&serde_json::json!({"schema":1,"journal_id":hex(&JOURNAL_ID),"initial_public_key":hex(key.verifying_key().as_bytes()),"starting_epoch":1})).expect("serialize trust bundle");
    protected(&admission.join("trust.json"), &trust);
    let digest = |bytes: &[u8]| hex(&sha2::Sha256::digest(bytes));
    let manifest = AdmissionSnapshotManifest {
        schema: 1,
        generation: 1,
        journal_id: hex(&JOURNAL_ID),
        trust_bundle: AdmissionArtifact {
            file: "trust.json".into(),
            sha256: digest(&trust),
        },
        minimum_checkpoint: AdmissionArtifact {
            file: "minimum.bin".into(),
            sha256: digest(&checkpoint_bytes),
        },
        checkpoint_chain: vec![AdmissionArtifact {
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
    runtime
}
