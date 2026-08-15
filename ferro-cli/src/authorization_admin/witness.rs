use super::{decode_hex, digest, hex};
use ed25519_dalek::VerifyingKey;
use ferro_core::witness::{
    decode_record, Checkpoint, CheckpointCoordinator, CheckpointVerifier, Invocation,
    JournalConfig, JournalMode, KeyStore, PrincipalSummary, PublicationOutcome, ResourceSummary,
    TrustBundle, WitnessAction, WitnessJournal, WitnessOutcome, WitnessReader, WitnessRecord,
    WitnessResourceKind, WitnessStage,
};
use serde::Deserialize;
use std::sync::Arc;
use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub fn open_required_journal(path: &Path, journal_id: &str) -> Result<Arc<WitnessJournal>, String> {
    let id = decode_hex::<16>(journal_id)?;
    WitnessJournal::open(JournalConfig::new(path, id, JournalMode::Required))
        .map(Arc::new)
        .map_err(|error| error.to_string())
}

pub struct ShowArgs<'a> {
    pub journal: &'a Path,
    pub journal_id: &'a str,
    pub limit: usize,
    pub from_sequence: Option<u64>,
    pub stage: Option<&'a str>,
}
pub struct VerifyArgs<'a> {
    pub journal: &'a Path,
    pub trust_bundle: &'a Path,
    pub minimum_checkpoint: &'a Path,
    pub checkpoints: &'a [PathBuf],
    pub max_age_seconds: u64,
}
pub struct CheckpointArgs<'a> {
    pub journal: &'a Path,
    pub journal_id: &'a str,
    pub artifact: &'a Path,
    pub key_dir: Option<&'a Path>,
    pub key_name: Option<&'a str>,
    pub predecessor: Option<&'a Path>,
    pub recover_pending: bool,
}
pub struct RotateArgs<'a> {
    pub journal: &'a Path,
    pub journal_id: &'a str,
    pub artifact: &'a Path,
    pub key_dir: &'a Path,
    pub old_key: &'a str,
    pub new_key: &'a str,
    pub predecessor: &'a Path,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustFile {
    schema: u8,
    journal_id: String,
    initial_public_key: String,
    #[serde(default = "default_epoch")]
    starting_epoch: u64,
}
fn default_epoch() -> u64 {
    1
}

pub fn show(args: ShowArgs<'_>) -> Result<String, String> {
    if args.limit == 0 || args.limit > 1000 {
        return Err("witness show limit must be between 1 and 1000".into());
    }
    let id = decode_hex::<16>(args.journal_id)?;
    let mut reader = WitnessReader::open_read_only(args.journal, id).map_err(|e| e.to_string())?;
    let wanted = args.stage.map(parse_stage).transpose()?;
    let mut lines = Vec::new();
    while let Some(bytes) = reader.next_record().map_err(|e| e.to_string())? {
        let record = decode_record(&bytes).map_err(|e| e.to_string())?;
        if record.sequence() < args.from_sequence.unwrap_or(1)
            || wanted.is_some_and(|stage| record.stage() != stage)
        {
            continue;
        }
        if lines.len() < args.limit {
            lines.push(format!(
                "epoch={} sequence={} stage={:?} principal={} action={:?} resource_kind={:?} resource={} resource_generation={} decision={:?} reason={:?} rule={} policy_generation={} policy_digest={} record_hash={}",
                record.epoch(),
                record.sequence(),
                record.stage(),
                hex(&record.principal_pseudonym()),
                record.action(),
                record.resource_kind(),
                hex(&record.resource_pseudonym()),
                record.resource_generation(),
                record.decision(),
                record.reason(),
                record.rule_id().map(|value| hex(&value)).unwrap_or_else(|| "none".into()),
                record.policy_generation(),
                hex(&record.policy_digest()),
                hex(&record.record_hash())
            ));
        }
    }
    reader.finish().map_err(|e| e.to_string())?;
    Ok(if lines.is_empty() {
        "witness records: <none>".into()
    } else {
        lines.join("\n")
    })
}

pub fn verify(args: VerifyArgs<'_>) -> Result<String, String> {
    let trust_bytes = fs::read(args.trust_bundle).map_err(|e| format!("trust bundle: {e}"))?;
    let trust_file: TrustFile =
        serde_json::from_slice(&trust_bytes).map_err(|e| format!("trust bundle: {e}"))?;
    if trust_file.schema != 1 || trust_file.starting_epoch != 1 {
        return Err("unsupported trust bundle boundary; use an explicit v1 genesis bundle".into());
    }
    let id = decode_hex::<16>(&trust_file.journal_id)?;
    let key = VerifyingKey::from_bytes(&decode_hex::<32>(&trust_file.initial_public_key)?)
        .map_err(|_| "invalid trust bundle public key")?;
    let minimum = read_checkpoint(args.minimum_checkpoint)?;
    if minimum.head.journal_id != id {
        return Err("minimum checkpoint does not match pinned journal ID".into());
    }
    let mut checkpoints = Vec::with_capacity(args.checkpoints.len());
    let mut minimum_present = false;
    for path in args.checkpoints {
        let cp = read_checkpoint(path)?;
        minimum_present |= cp == minimum;
        checkpoints.push(cp);
    }
    if !minimum_present {
        return Err(
            "minimum checkpoint is not present in the explicitly supplied checkpoint chain".into(),
        );
    }
    let mut reader = WitnessReader::open_read_only(args.journal, id).map_err(|e| e.to_string())?;
    let report = CheckpointVerifier::new(TrustBundle::new(id, key).with_minimum(minimum))
        .verify_iter(
            reader.records(),
            &checkpoints,
            now_secs()?,
            Duration::from_secs(args.max_age_seconds),
        )
        .map_err(|e| format!("witness verification failed: {e}"))?;
    reader.finish().map_err(|e| e.to_string())?;
    Ok(format!(
        "integrity={}\nlifecycle_consistency={}\ncompleteness={}\nfreshness={:?}\ncheckpoint_age={:?}\nrecords={}",
        report.integrity,
        report.lifecycle_consistent,
        report.completeness_through_checkpoint.map(|v| v.to_string()).unwrap_or_else(|| "unknown".into()),
        report.tail_freshness,
        report.checkpoint_age,
        report.records))
}

pub fn checkpoint(args: CheckpointArgs<'_>) -> Result<String, String> {
    super::require_host_admin()?;
    let id = decode_hex::<16>(args.journal_id)?;
    let journal = WitnessJournal::open(JournalConfig::new(args.journal, id, JournalMode::Required))
        .map_err(|e| e.to_string())?;
    checkpoint_on(args, &journal)
}

pub fn checkpoint_on(args: CheckpointArgs<'_>, journal: &WitnessJournal) -> Result<String, String> {
    let coordinator = CheckpointCoordinator::new(
        args.artifact,
        Duration::from_secs(300),
        Duration::from_secs(60),
    );
    if args.recover_pending {
        coordinator
            .reconcile_pending(journal)
            .map_err(|e| e.to_string())?;
        return Ok("checkpoint pending binding reconciled=true".into());
    }
    let key_dir = args
        .key_dir
        .ok_or("--key-dir is required unless --recover-pending is used")?;
    let key_name = args
        .key_name
        .ok_or("--key-name is required unless --recover-pending is used")?;
    let key = KeyStore::new(key_dir)
        .load(key_name)
        .map_err(|e| e.to_string())?;
    let predecessor = args.predecessor.map(read_checkpoint).transpose()?;
    let outcome = coordinator
        .capture_publish_bind(
            journal,
            now_secs()?,
            key.signing_key(),
            predecessor.as_ref(),
            publication_record,
        )
        .map_err(|e| e.to_string())?;
    Ok(publication_output(outcome))
}

pub fn rotate_key(args: RotateArgs<'_>) -> Result<String, String> {
    super::require_host_admin()?;
    let id = decode_hex::<16>(args.journal_id)?;
    let journal = WitnessJournal::open(JournalConfig::new(args.journal, id, JournalMode::Required))
        .map_err(|e| e.to_string())?;
    rotate_key_on(args, &journal)
}

pub fn rotate_key_on(args: RotateArgs<'_>, journal: &WitnessJournal) -> Result<String, String> {
    let store = KeyStore::new(args.key_dir);
    let old = store.load(args.old_key).map_err(|e| e.to_string())?;
    let new = store.create(args.new_key).map_err(|e| e.to_string())?;
    let predecessor = read_checkpoint(args.predecessor)?;
    let coordinator = CheckpointCoordinator::new(
        args.artifact,
        Duration::from_secs(300),
        Duration::from_secs(60),
    );
    let outcome = coordinator
        .capture_rotate_publish_bind(
            journal,
            now_secs()?,
            old.signing_key(),
            new.signing_key(),
            &predecessor,
            publication_record,
        )
        .map_err(|e| e.to_string())?;
    Ok(format!(
        "{} new_key_id={}",
        publication_output(outcome),
        hex(&(new.key_id().0))
    ))
}

fn publication_output(outcome: PublicationOutcome) -> String {
    match outcome {
        PublicationOutcome::Bound(cp) => format!(
            "checkpoint bound epoch={} sequence={} key_id={}",
            cp.head.epoch,
            cp.head.sequence,
            hex(&(cp.key_id.0))
        ),
        PublicationOutcome::PendingBinding(pending) => format!(
            "checkpoint published binding=pending recoverability={:?} epoch={} sequence={}",
            pending.recoverability(),
            pending.checkpoint().head.epoch,
            pending.checkpoint().head.sequence
        ),
    }
}

fn publication_record(checkpoint: &Checkpoint) -> WitnessRecord {
    let artifact_digest = digest(&checkpoint.encode());
    let ids = digest(&[checkpoint.encode().as_slice(), b"publication"].concat());
    let mut event = [0; 16];
    event.copy_from_slice(&ids[..16]);
    let mut request = [0; 16];
    request.copy_from_slice(&ids[16..]);
    let boot = fs::read("/proc/sys/kernel/random/boot_id")
        .map(|b| digest(&b))
        .unwrap_or([0; 32]);
    let mut boot_id = [0; 16];
    boot_id.copy_from_slice(&boot[..16]);
    WitnessRecord {
        epoch: checkpoint.head.epoch,
        sequence: checkpoint.head.sequence + 1,
        previous_hash: checkpoint.head.hash,
        event_id: event,
        request_id: request,
        runtime_instance_id: [0; 16],
        boot_id,
        principal: PrincipalSummary::pseudonymize(&artifact_digest, b"checkpoint-coordinator")
            .expect("fixed purpose"),
        invocation: Invocation::Manager,
        action: WitnessAction::CheckpointPublish,
        resource_kind: WitnessResourceKind::Administrative,
        resource: ResourceSummary::pseudonymize(&artifact_digest, b"checkpoint-artifact")
            .expect("fixed purpose"),
        resource_generation: checkpoint.head.epoch,
        policy_version: 0,
        policy_digest: [0; 32],
        decision_id: None,
        rule: None,
        decision: None,
        reason: None,
        request_digest: artifact_digest,
        result_digest: Some(artifact_digest),
        wall_time_ns: (checkpoint.created_at_secs as i64).saturating_mul(1_000_000_000),
        monotonic_ns: 0,
        stage: WitnessStage::CheckpointPublished,
        outcome: WitnessOutcome::Succeeded,
        recovery_link: None,
        path_class: None,
        device_class: None,
        correlation_digest: None,
    }
}

fn read_checkpoint(path: &Path) -> Result<Checkpoint, String> {
    Checkpoint::decode(&fs::read(path).map_err(|e| format!("checkpoint {}: {e}", path.display()))?)
        .map_err(|e| format!("checkpoint {}: {e}", path.display()))
}
fn now_secs() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|_| "system clock is before Unix epoch".into())
}
fn parse_stage(value: &str) -> Result<WitnessStage, String> {
    match value {
        "received" => Ok(WitnessStage::RequestReceived),
        "decision" => Ok(WitnessStage::Decision),
        "denied" => Ok(WitnessStage::Denied),
        "outcome" => Ok(WitnessStage::Outcome),
        "recovery" => Ok(WitnessStage::Recovery),
        "checkpoint" => Ok(WitnessStage::CheckpointPublished),
        _ => Err("unknown witness stage filter".into()),
    }
}
