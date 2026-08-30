#![cfg(target_os = "linux")]

use ferro_core::authorization::{gate::AuthorizationGate, policy::PolicyStore, RequestOrigin};
use ferro_core::container_store::ContainerRecord;
use ferro_core::container_store::CreationProvenance;
use ferro_core::image_store::LocalImageStore;
use ferro_core::runtime::{
    ContainerRuntime, LifecyclePhaseHook, LifecyclePhasePoint, RuntimeError,
};
use ferro_core::sqlite_container_store::SqliteContainerStore;
use ferro_core::witness::{
    decode_record, JournalConfig, JournalMode, WitnessAction, WitnessJournal, WitnessStage,
};
use sha2::{Digest, Sha256};
use std::io::Cursor;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::{MutexGuard, OnceLock};
use tar::{Builder, Header};

fn runtime_test_guard() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(target_env = "musl")]
const HOST_BUSYBOX: &str = "/bin/busybox";
#[cfg(not(target_env = "musl"))]
const HOST_BUSYBOX: &str = "/usr/bin/busybox";

fn provision_busybox_rootfs(rootfs: &std::path::Path) {
    let bin = rootfs.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    for name in ["busybox", "sh"] {
        std::fs::copy(HOST_BUSYBOX, bin.join(name)).unwrap();
    }
    #[cfg(all(target_env = "musl", target_arch = "x86_64"))]
    {
        let lib = rootfs.join("lib");
        std::fs::create_dir_all(&lib).unwrap();
        std::fs::copy("/lib/ld-musl-x86_64.so.1", lib.join("ld-musl-x86_64.so.1")).unwrap();
    }
}

fn live_process_start_time(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

fn seed_alpine(root: &std::path::Path) {
    let store = LocalImageStore::open(root.join("images")).unwrap();
    let digest = format!("sha256:{}", "b".repeat(64));
    // Include the executable fixture so direct rootful chroot has the same
    // workload surface as the unprivileged bubblewrap path.
    let busybox = std::fs::read(HOST_BUSYBOX).expect("busybox fixture");
    let mut layer = Vec::new();
    {
        let mut builder = Builder::new(&mut layer);
        let mut header = Header::new_gnu();
        header.set_size(busybox.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        for path in ["bin/sh", "true"] {
            builder
                .append_data(&mut header, path, Cursor::new(&busybox))
                .expect("append executable fixture");
        }
        #[cfg(all(target_env = "musl", target_arch = "x86_64"))]
        {
            let loader = std::fs::read("/lib/ld-musl-x86_64.so.1").expect("musl loader fixture");
            let mut loader_header = Header::new_gnu();
            loader_header.set_size(loader.len() as u64);
            loader_header.set_mode(0o755);
            loader_header.set_cksum();
            builder
                .append_data(
                    &mut loader_header,
                    "lib/ld-musl-x86_64.so.1",
                    Cursor::new(loader),
                )
                .expect("append musl loader fixture");
        }
        builder.finish().expect("finish executable layer");
    }
    let layer_digest = format!("sha256:{:x}", Sha256::digest(&layer));
    let blob_path = root
        .join("images")
        .join("blobs")
        .join(layer_digest.replace(':', "_"));
    std::fs::create_dir_all(blob_path.parent().unwrap()).unwrap();
    std::fs::write(&blob_path, &layer).unwrap();
    let manifest = format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{digest}","size":0}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"{layer_digest}","size":{}}}]}}"#,
        layer.len()
    );
    let plan = store
        .prepare_reference_write(
            "alpine",
            &digest,
            "application/vnd.oci.image.manifest.v1+json",
            &manifest,
        )
        .unwrap();
    let authority = ContainerRuntime::new(&root.join("seed-authority")).unwrap();
    let authorization = authority.surface_authorization().unwrap();
    let origin = RequestOrigin::cli_current().unwrap();
    let permit = authorization
        .authorize_image_reference_write_plan(&origin, &plan)
        .unwrap();
    store.put_reference_authorized(plan, permit).unwrap();
}

#[derive(Default)]
struct RecordingPhaseHook(Mutex<Vec<LifecyclePhasePoint>>);
impl LifecyclePhaseHook for RecordingPhaseHook {
    fn reached(&self, _action: &str, phase: LifecyclePhasePoint) -> Result<(), RuntimeError> {
        self.0.lock().unwrap().push(phase);
        Ok(())
    }
}

struct FailAfterKernelEffect;
impl LifecyclePhaseHook for FailAfterKernelEffect {
    fn reached(&self, _action: &str, phase: LifecyclePhasePoint) -> Result<(), RuntimeError> {
        if phase == LifecyclePhasePoint::KernelEffectApplied {
            return Err(RuntimeError::InvalidState(
                "injected post-effect store failure".into(),
            ));
        }
        Ok(())
    }
}

struct AbortAtPhase(LifecyclePhasePoint);
impl LifecyclePhaseHook for AbortAtPhase {
    fn reached(&self, _action: &str, phase: LifecyclePhasePoint) -> Result<(), RuntimeError> {
        if phase == self.0 {
            return Err(RuntimeError::InvalidState("simulated hard crash".into()));
        }
        Ok(())
    }
}

fn assert_abort_reopen_matrix(action: &str) {
    let _guard = runtime_test_guard();
    let phases = if action == "exec" {
        vec![
            LifecyclePhasePoint::DecisionDurable,
            LifecyclePhasePoint::EffectObserved,
            LifecyclePhasePoint::TerminalDurable,
            LifecyclePhasePoint::ReservationCleared,
        ]
    } else {
        vec![
            LifecyclePhasePoint::DecisionDurable,
            LifecyclePhasePoint::ReservationDurable,
            LifecyclePhasePoint::EffectObserved,
            LifecyclePhasePoint::TerminalDurable,
            LifecyclePhasePoint::ReservationCleared,
        ]
    };
    for (phase_index, phase) in phases.into_iter().enumerate() {
        let root = tempfile::tempdir().unwrap();
        let cgroup = root.path().join("cgroup");
        std::fs::create_dir_all(&cgroup).unwrap();
        std::fs::write(cgroup.join("cgroup.controllers"), "memory cpu pids").unwrap();
        std::env::set_var("FERROCRATE_CGROUP_ROOT", &cgroup);
        let runtime_id = [101; 16];
        std::fs::write(root.path().join("runtime-instance-id"), runtime_id).unwrap();
        let policy_path = root.path().join("policy.toml");
        std::fs::write(
            &policy_path,
            "schema_version = 1\ngeneration = 1\nmode = \"shadow\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&policy_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let policies = Arc::new(PolicyStore::load(&policy_path).unwrap());
        let journal_path = root.path().join("witness");
        let journal_id = [110 + phase_index as u8 + action.as_bytes()[0] % 7; 16];
        let journal = Arc::new(
            WitnessJournal::open(JournalConfig::new(
                &journal_path,
                journal_id,
                JournalMode::Required,
            ))
            .unwrap(),
        );
        let id = "00112233445566778899aabbccddeeff";
        let mut child = None;
        if action == "run" {
            seed_alpine(root.path());
        } else {
            let spawned = std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .unwrap();
            let store = SqliteContainerStore::open(root.path().join("containers.db")).unwrap();
            let mut record: ContainerRecord = serde_json::from_value(serde_json::json!({
                "id":id,"pid":spawned.id(),"image":"example.invalid/app:latest","command":["true"],
                "created_at_unix":1,"stdout_path":"","stderr_path":"","status": if action == "remove" { "stopped" } else { "running" }
            })).unwrap();
            record.process_start_time = live_process_start_time(spawned.id());
            if action == "remove" {
                let compact = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                    .unwrap()
                    .trim()
                    .replace('-', "");
                let mut boot_id = [0; 16];
                for (index, byte) in boot_id.iter_mut().enumerate() {
                    *byte = u8::from_str_radix(&compact[index * 2..index * 2 + 2], 16).unwrap();
                }
                record.creation_provenance = CreationProvenance {
                    runtime_instance_id: Some(runtime_id),
                    boot_id: Some(boot_id),
                    journal_id: Some(journal_id),
                    resource_uuid: Some("00112233-4455-6677-8899-aabbccddeeff".into()),
                    resource_generation: 1,
                    creator_operation_id: Some([102; 16]),
                    image_digest: None,
                };
            }
            store.put(&record).unwrap();
            child = Some(spawned);
        }
        let runtime = ContainerRuntime::new_with_authorization_and_phase_hook(
            root.path(),
            Arc::new(AuthorizationGate::new(policies.clone())),
            Some(journal.clone()),
            Arc::new(AbortAtPhase(phase)),
        )
        .unwrap();
        let result = match action {
            "run" => runtime
                .run(
                    "alpine",
                    &["true".into()],
                    &[],
                    &Default::default(),
                    &Default::default(),
                    None,
                    Default::default(),
                    &[],
                    None,
                    &[],
                    &[],
                    false,
                    true,
                    None,
                    None,
                    None,
                    &[],
                    "none",
                    ferro_core::runtime::NetworkBackend::Iptables,
                    None,
                )
                .map(|_| ()),
            "exec" => runtime.exec(id, &["true".into()]).map(|_| ()),
            "remove" => runtime.remove(id),
            _ => unreachable!(),
        };
        assert!(result.is_err(), "{action} unexpectedly crossed {phase:?}");
        let expected_journal_pending = matches!(
            phase,
            LifecyclePhasePoint::DecisionDurable
                | LifecyclePhasePoint::ReservationDurable
                | LifecyclePhasePoint::EffectObserved
        );
        assert_eq!(
            !journal.pending().unwrap().is_empty(),
            expected_journal_pending,
            "pre-reopen journal state for {action} {phase:?}"
        );
        let records_before_reopen = runtime.list().unwrap();
        let expected_store_pending = action != "exec" && match phase {
            LifecyclePhasePoint::ReservationDurable | LifecyclePhasePoint::EffectObserved => true,
            LifecyclePhasePoint::TerminalDurable => action != "remove",
            _ => false,
        };
        assert_eq!(
            records_before_reopen
                .iter()
                .any(|record| record.pending_mutation.is_some()),
            expected_store_pending,
            "pre-reopen reservation state for {action} {phase:?}"
        );
        if action == "remove"
            && matches!(
                phase,
                LifecyclePhasePoint::TerminalDurable | LifecyclePhasePoint::ReservationCleared
            )
        {
            assert!(records_before_reopen.is_empty(), "remove tombstone phase");
        }
        // Returning from the phase hook bypasses every later lifecycle phase. Dropping
        // these handles without invoking API cleanup therefore models abrupt daemon
        // loss; the reopened durable adapters are the only recovery source of truth.
        // A short-lived run command also lets its detached status observer release the
        // sled handle, as a real daemon process exit would do automatically.
        if action == "run" {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        drop(runtime);
        drop(journal);
        let reopen_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let reopened = loop {
            match WitnessJournal::open(JournalConfig::new(
                &journal_path,
                journal_id,
                JournalMode::Required,
            )) {
                Ok(reopened) => break Arc::new(reopened),
                Err(_error) if std::time::Instant::now() < reopen_deadline => {
                    // Rootless launch supervision retains the shared journal
                    // while it reaps the stopped ownership launcher. Model a
                    // process exit by waiting for that bounded cleanup.
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
                Err(error) => panic!("reopen witness journal after simulated crash: {error}"),
            }
        };
        let runtime = ContainerRuntime::new_with_authorization(
            root.path(),
            Arc::new(AuthorizationGate::new(policies)),
            Some(reopened.clone()),
        )
        .unwrap();
        assert!(reopened.pending().unwrap().is_empty(), "{action} {phase:?}");
        for record in runtime.list().unwrap() {
            assert!(record.pending_mutation.is_none(), "{action} {phase:?}");
            if action == "run" {
                assert!(record.creation_provenance.is_verifiable());
            }
        }
        let decoded = reopened
            .records()
            .unwrap()
            .iter()
            .map(|bytes| decode_record(bytes).unwrap())
            .collect::<Vec<_>>();
        let recovery_count = decoded
            .iter()
            .filter(|record| record.stage() == WitnessStage::Recovery)
            .count();
        assert!(recovery_count <= 1, "{action} {phase:?}");
        assert_eq!(
            recovery_count,
            usize::from(
                expected_journal_pending
                    || (action == "run" && phase == LifecyclePhasePoint::TerminalDurable),
            ),
            "terminal recovery uniqueness for {action} {phase:?}"
        );
        assert!(matches!(
            decoded.last().unwrap().stage(),
            WitnessStage::Outcome | WitnessStage::Recovery | WitnessStage::Denied
        ));
        if let Some(mut child) = child {
            let _ = child.kill();
            let _ = child.wait();
        }
        std::env::remove_var("FERROCRATE_CGROUP_ROOT");
    }
}

#[test]
fn run_five_phase_abort_reopens_without_orphan_or_replay() {
    assert_abort_reopen_matrix("run");
}
#[test]
fn exec_five_phase_abort_reopens_without_orphan_or_replay() {
    assert_abort_reopen_matrix("exec");
}
#[test]
fn remove_five_phase_abort_reopens_without_orphan_or_replay() {
    assert_abort_reopen_matrix("remove");
}

fn assert_post_effect_unknown_reconciles(action: &str) {
    let _guard = runtime_test_guard();
    let root = tempfile::tempdir().unwrap();
    let cgroup = root.path().join("cgroup");
    let group = cgroup.join("ferrocrate/00112233445566778899aabbccddeeff");
    std::fs::create_dir_all(&group).unwrap();
    std::fs::write(cgroup.join("cgroup.controllers"), "memory cpu pids").unwrap();
    std::fs::write(group.join("cgroup.procs"), "").unwrap();
    std::fs::write(
        group.join("cgroup.freeze"),
        if action == "resume" { "1" } else { "0" },
    )
    .unwrap();
    std::env::set_var("FERROCRATE_CGROUP_ROOT", &cgroup);
    let policy_path = root.path().join("policy.toml");
    std::fs::write(
        &policy_path,
        "schema_version = 1\ngeneration = 1\nmode = \"shadow\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&policy_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let policies = Arc::new(PolicyStore::load(&policy_path).unwrap());
    let journal_path = root.path().join("witness");
    let journal = Arc::new(
        WitnessJournal::open(JournalConfig::new(
            &journal_path,
            [83; 16],
            JournalMode::Required,
        ))
        .unwrap(),
    );
    let id = "00112233445566778899aabbccddeeff";
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let store = SqliteContainerStore::open(root.path().join("containers.db")).unwrap();
    let mut record: ContainerRecord = serde_json::from_value(serde_json::json!({
        "id":id, "pid":child.id(), "image":"example.invalid/app:latest", "command":["true"],
        "created_at_unix":1, "stdout_path":"", "stderr_path":"",
        "status": if action == "resume" { "paused" } else { "running" }
    }))
    .unwrap();
    record.process_start_time = live_process_start_time(child.id());
    store.put(&record).unwrap();
    drop(store);
    let runtime = ContainerRuntime::new_with_authorization_and_phase_hook(
        root.path(),
        Arc::new(AuthorizationGate::new(policies.clone())),
        Some(journal.clone()),
        Arc::new(FailAfterKernelEffect),
    )
    .unwrap();
    let result = match action {
        "pause" => runtime.pause(id),
        "resume" => runtime.resume(id),
        "stop" => runtime.stop(id, std::time::Duration::ZERO),
        "kill" => runtime.kill(id),
        _ => unreachable!(),
    };
    assert!(matches!(
        result,
        Err(RuntimeError::PostEffectPersistence(_))
    ));
    assert_eq!(journal.pending().unwrap().len(), 1);
    assert!(runtime.inspect(id).unwrap().pending_mutation.is_none());
    let outcomes = journal
        .records()
        .unwrap()
        .iter()
        .map(|bytes| decode_record(bytes).unwrap().stage())
        .collect::<Vec<_>>();
    assert_eq!(
        outcomes,
        [
            WitnessStage::RequestReceived,
            WitnessStage::Decision,
            WitnessStage::Outcome
        ]
    );
    drop(runtime);
    drop(journal);
    let reopened = Arc::new(
        WitnessJournal::open(JournalConfig::new(
            &journal_path,
            [83; 16],
            JournalMode::Required,
        ))
        .unwrap(),
    );
    let runtime = ContainerRuntime::new_with_authorization(
        root.path(),
        Arc::new(AuthorizationGate::new(policies)),
        Some(reopened.clone()),
    )
    .unwrap();
    assert!(reopened.pending().unwrap().is_empty());
    assert!(runtime.inspect(id).unwrap().pending_mutation.is_none());
    let _ = child.kill();
    let _ = child.wait();
    std::env::remove_var("FERROCRATE_CGROUP_ROOT");
}

#[test]
fn pause_post_effect_store_failure_reopens_without_replay() {
    assert_post_effect_unknown_reconciles("pause");
}
#[test]
fn resume_post_effect_store_failure_reopens_without_replay() {
    assert_post_effect_unknown_reconciles("resume");
}
#[test]
fn stop_post_effect_store_failure_reopens_without_replay() {
    assert_post_effect_unknown_reconciles("stop");
}
#[test]
fn kill_post_effect_store_failure_reopens_without_replay() {
    assert_post_effect_unknown_reconciles("kill");
}

#[test]
fn exec_exposes_every_durable_crash_boundary_in_order() {
    let _guard = runtime_test_guard();
    let root = tempfile::tempdir().unwrap();
    let policy_path = root.path().join("policy.toml");
    std::fs::write(
        &policy_path,
        "schema_version = 1\ngeneration = 1\nmode = \"shadow\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&policy_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let gate = Arc::new(AuthorizationGate::new(Arc::new(
        PolicyStore::load(&policy_path).unwrap(),
    )));
    let journal = Arc::new(
        WitnessJournal::open(JournalConfig::new(
            root.path().join("witness"),
            [61; 16],
            JournalMode::Required,
        ))
        .unwrap(),
    );
    let store = SqliteContainerStore::open(root.path().join("containers.db")).unwrap();
    let mut record: ContainerRecord = serde_json::from_value(serde_json::json!({
        "id":"00112233445566778899aabbccddeeff", "pid":std::process::id(),
        "image":"example.invalid/app:latest", "command":["true"],
        "created_at_unix":1, "stdout_path":"", "stderr_path":"", "status":"running"
    }))
    .unwrap();
    record.process_start_time = live_process_start_time(std::process::id());
    store.put(&record).unwrap();
    drop(store);
    let hook = Arc::new(RecordingPhaseHook::default());
    let runtime = ContainerRuntime::new_with_authorization_and_phase_hook(
        root.path(),
        gate,
        Some(journal),
        hook.clone(),
    )
    .unwrap();
    runtime.exec(&record.id, &["true".into()]).unwrap();
    assert_eq!(
        *hook.0.lock().unwrap(),
        [
            LifecyclePhasePoint::DecisionDurable,
            LifecyclePhasePoint::EffectObserved,
            LifecyclePhasePoint::TerminalDurable,
            LifecyclePhasePoint::ReservationCleared,
        ]
    );
}

#[test]
fn failed_witnessed_run_leaves_no_phantom_candidate() {
    let _guard = runtime_test_guard();
    let root = tempfile::tempdir().unwrap();
    let policy_path = root.path().join("policy.toml");
    std::fs::write(
        &policy_path,
        "schema_version = 1\ngeneration = 1\nmode = \"shadow\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&policy_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let gate = Arc::new(AuthorizationGate::new(Arc::new(
        PolicyStore::load(&policy_path).unwrap(),
    )));
    let journal = Arc::new(
        WitnessJournal::open(JournalConfig::new(
            root.path().join("witness"),
            [62; 16],
            JournalMode::Required,
        ))
        .unwrap(),
    );
    let runtime =
        ContainerRuntime::new_with_authorization(root.path(), gate, Some(journal)).unwrap();
    let error = runtime
        .run(
            "example.invalid/app:latest",
            &[],
            &[],
            &Default::default(),
            &Default::default(),
            None,
            Default::default(),
            &[],
            None,
            &[],
            &[],
            false,
            true,
            None,
            None,
            None,
            &[],
            "none",
            ferro_core::runtime::NetworkBackend::Iptables,
            None,
        )
        .unwrap_err();
    assert!(error.to_string().contains("command is required"));
    drop(runtime);
    let store = SqliteContainerStore::open(root.path().join("containers.db")).unwrap();
    assert!(store.list().unwrap().is_empty());
}

#[test]
fn creation_provenance_is_absent_for_legacy_records() {
    let value: CreationProvenance = serde_json::from_str("null").unwrap_or_default();
    assert!(!value.is_verifiable());
}

#[test]
fn denied_exec_is_witnessed_once_and_has_no_side_effect() {
    let _guard = runtime_test_guard();
    let root = tempfile::tempdir().unwrap();
    let policy_path = root.path().join("policy.toml");
    std::fs::write(
        &policy_path,
        "schema_version = 1\ngeneration = 1\nmode = \"enforce\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&policy_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let gate = Arc::new(AuthorizationGate::new(Arc::new(
        PolicyStore::load(&policy_path).unwrap(),
    )));
    let witness_root = root.path().join("witness");
    let journal = Arc::new(
        WitnessJournal::open(JournalConfig::new(
            &witness_root,
            [9; 16],
            JournalMode::Required,
        ))
        .unwrap(),
    );
    let store = SqliteContainerStore::open(root.path().join("containers.db")).unwrap();
    let record: ContainerRecord = serde_json::from_value(serde_json::json!({
        "id":"00112233445566778899aabbccddeeff", "pid":4294967295u32,
        "image":"example.invalid/app:latest", "command":["true"],
        "created_at_unix":1, "stdout_path":"", "stderr_path":"", "status":"stopped"
    }))
    .unwrap();
    store.put(&record).unwrap();
    drop(store);
    let runtime =
        ContainerRuntime::new_with_authorization(root.path(), gate, Some(journal.clone())).unwrap();

    let secret_canary = "SUPER_SECRET_RUNTIME_CANARY";
    let error = runtime
        .exec(
            &record.id,
            &[
                secret_canary.into(),
                root.path().join("forbidden").display().to_string(),
            ],
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("authorization denied"),
        "{error}"
    );
    assert!(!root.path().join("forbidden").exists());
    let records = journal.records().unwrap();
    assert!(records.iter().all(|bytes| !bytes
        .windows(secret_canary.len())
        .any(|window| window == secret_canary.as_bytes())));
    assert_eq!(records.len(), 3);
    let decoded = records
        .iter()
        .map(|bytes| decode_record(bytes).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(decoded[0].stage(), WitnessStage::RequestReceived);
    assert_eq!(decoded[1].stage(), WitnessStage::Decision);
    assert_eq!(decoded[2].stage(), WitnessStage::Denied);
}

#[test]
fn runtime_instance_identity_survives_same_directory_restart() {
    let root = tempfile::tempdir().unwrap();
    let runtime = ContainerRuntime::new(root.path()).unwrap();
    drop(runtime);
    let first = std::fs::read(root.path().join("runtime-instance-id")).unwrap();
    assert_eq!(first.len(), 16);
    let runtime = ContainerRuntime::new(root.path()).unwrap();
    drop(runtime);
    assert_eq!(
        std::fs::read(root.path().join("runtime-instance-id")).unwrap(),
        first
    );
}

#[test]
fn every_lifecycle_method_denies_once_before_executor_side_effects() {
    let _guard = runtime_test_guard();
    for action in [
        "run", "exec", "pause", "resume", "stop", "kill", "restart", "remove",
    ] {
        let root = tempfile::tempdir().unwrap();
        let policy_path = root.path().join("policy.toml");
        std::fs::write(
            &policy_path,
            "schema_version = 1\ngeneration = 1\nmode = \"enforce\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&policy_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let gate = Arc::new(AuthorizationGate::new(Arc::new(
            PolicyStore::load(&policy_path).unwrap(),
        )));
        let journal = Arc::new(
            WitnessJournal::open(JournalConfig::new(
                root.path().join("witness"),
                [action.as_bytes()[0]; 16],
                JournalMode::Required,
            ))
            .unwrap(),
        );
        let id = "00112233445566778899aabbccddeeff";
        if action != "run" {
            let store = SqliteContainerStore::open(root.path().join("containers.db")).unwrap();
            let mut record: ContainerRecord = serde_json::from_value(serde_json::json!({
                "id":id, "pid":std::process::id(), "image":"example.invalid/app:latest",
                "command":["true"], "created_at_unix":1, "stdout_path":"", "stderr_path":"",
                "status": if action == "resume" { "paused" } else { "running" }
            }))
            .unwrap();
            record.process_start_time = live_process_start_time(std::process::id());
            record.mutation_generation = 1;
            store.put(&record).unwrap();
            drop(store);
            if action == "restart" {
                provision_busybox_rootfs(&root.path().join("containers").join(id).join("rootfs"));
            }
        }
        let runtime =
            ContainerRuntime::new_with_authorization(root.path(), gate, Some(journal.clone()))
                .unwrap();
        let result = match action {
            "run" => runtime
                .run(
                    "alpine",
                    &["true".into()],
                    &[],
                    &Default::default(),
                    &Default::default(),
                    None,
                    Default::default(),
                    &[],
                    None,
                    &[],
                    &[],
                    false,
                    true,
                    None,
                    None,
                    None,
                    &[],
                    "none",
                    ferro_core::runtime::NetworkBackend::Iptables,
                    None,
                )
                .map(|_| ()),
            "exec" => runtime.exec(id, &["true".into()]).map(|_| ()),
            "pause" => runtime.pause(id),
            "resume" => runtime.resume(id),
            "stop" => runtime.stop(id, std::time::Duration::ZERO),
            "kill" => runtime.kill(id),
            "restart" => runtime.restart(id, std::time::Duration::ZERO),
            "remove" => runtime.remove(id),
            _ => unreachable!(),
        };
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("authorization denied"),
            "{action}"
        );
        if action != "run" {
            let expected = if action == "resume" {
                "paused"
            } else {
                "running"
            };
            assert_eq!(runtime.inspect(id).unwrap().status, expected, "{action}");
        }
        let stages = journal
            .records()
            .unwrap()
            .iter()
            .map(|bytes| decode_record(bytes).unwrap().stage())
            .collect::<Vec<_>>();
        assert_eq!(
            stages,
            [
                WitnessStage::RequestReceived,
                WitnessStage::Decision,
                WitnessStage::Denied
            ],
            "{action}"
        );
        drop(runtime);
        drop(journal);
    }
}

#[test]
fn every_allowed_lifecycle_method_has_one_decision_and_terminal_receipt() {
    let _guard = runtime_test_guard();
    for action in [
        "run", "exec", "pause", "resume", "stop", "kill", "restart", "remove",
    ] {
        let root = tempfile::tempdir().unwrap();
        let cgroup = root.path().join("cgroup");
        std::fs::create_dir_all(&cgroup).unwrap();
        std::fs::write(cgroup.join("cgroup.controllers"), "memory cpu pids").unwrap();
        std::env::set_var("FERROCRATE_CGROUP_ROOT", &cgroup);
        let policy_path = root.path().join("policy.toml");
        std::fs::write(
            &policy_path,
            "schema_version = 1\ngeneration = 1\nmode = \"shadow\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&policy_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let gate = Arc::new(AuthorizationGate::new(Arc::new(
            PolicyStore::load(&policy_path).unwrap(),
        )));
        let journal = Arc::new(
            WitnessJournal::open(JournalConfig::new(
                root.path().join("witness"),
                [action.as_bytes()[0].wrapping_add(1); 16],
                JournalMode::Required,
            ))
            .unwrap(),
        );
        let id = "00112233445566778899aabbccddeeff";
        let runtime_id = [93; 16];
        std::fs::write(root.path().join("runtime-instance-id"), runtime_id).unwrap();
        let mut child = None;
        if action == "run" {
            seed_alpine(root.path());
        }
        if action != "run" {
            let spawned = std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .unwrap();
            let pid = spawned.id();
            child = Some(spawned);
            let store = SqliteContainerStore::open(root.path().join("containers.db")).unwrap();
            let mut record: ContainerRecord = serde_json::from_value(serde_json::json!({
                "id":id, "pid":pid, "image":"example.invalid/app:latest",
                "command": if action == "restart" {
                    vec![String::from("/bin/busybox"), String::from("sleep"), String::from("30")]
                } else { vec![String::from("true")] },
                "created_at_unix":1,
                "stdout_path":root.path().join("containers").join(id).join("stdout.log").to_string_lossy(),
                "stderr_path":root.path().join("containers").join(id).join("stderr.log").to_string_lossy(),
                "status": if action == "resume" { "paused" } else if action == "restart" || action == "remove" { "stopped" } else { "running" }
            })).unwrap();
            record.process_start_time = live_process_start_time(pid);
            if action == "remove" {
                let compact = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                    .unwrap()
                    .trim()
                    .replace('-', "");
                let mut boot_id = [0; 16];
                for (index, byte) in boot_id.iter_mut().enumerate() {
                    *byte = u8::from_str_radix(&compact[index * 2..index * 2 + 2], 16).unwrap();
                }
                record.creation_provenance = CreationProvenance {
                    runtime_instance_id: Some(runtime_id),
                    boot_id: Some(boot_id),
                    journal_id: Some([action.as_bytes()[0].wrapping_add(1); 16]),
                    resource_uuid: Some("00112233-4455-6677-8899-aabbccddeeff".into()),
                    resource_generation: 1,
                    creator_operation_id: Some([94; 16]),
                    image_digest: None,
                };
            }
            store.put(&record).unwrap();
            drop(store);
            if action == "restart" {
                provision_busybox_rootfs(&root.path().join("containers").join(id).join("rootfs"));
            }
        }
        let runtime =
            ContainerRuntime::new_with_authorization(root.path(), gate, Some(journal.clone()))
                .unwrap();
        let result = match action {
            "run" => runtime
                .run(
                    "alpine",
                    &["true".into()],
                    &[],
                    &Default::default(),
                    &Default::default(),
                    None,
                    Default::default(),
                    &[],
                    None,
                    &[],
                    &[],
                    false,
                    true,
                    None,
                    None,
                    None,
                    &[],
                    "none",
                    ferro_core::runtime::NetworkBackend::Iptables,
                    None,
                )
                .map(|_| ()),
            "exec" => runtime.exec(id, &["false".into()]).map(|_| ()),
            "pause" => runtime.pause(id),
            "resume" => runtime.resume(id),
            "stop" => runtime.stop(id, std::time::Duration::ZERO),
            "kill" => runtime.kill(id),
            "restart" => runtime.restart(id, std::time::Duration::ZERO),
            "remove" => runtime.remove(id),
            _ => unreachable!(),
        };
        assert!(result.is_ok(), "{action} failed unexpectedly: {result:?}");
        if action == "remove" {
            assert!(matches!(
                runtime.inspect(id),
                Err(RuntimeError::ContainerNotFound(_))
            ));
        }
        if let Some(mut child) = child {
            let _ = child.kill();
            let _ = child.wait();
        }
        let decoded = journal
            .records()
            .unwrap()
            .iter()
            .map(|bytes| decode_record(bytes).unwrap())
            .collect::<Vec<_>>();
        let lifecycle_action = match action {
            "run" => WitnessAction::ContainerRun,
            "exec" => WitnessAction::ContainerExec,
            "pause" => WitnessAction::ContainerPause,
            "resume" => WitnessAction::ContainerResume,
            "stop" => WitnessAction::ContainerStop,
            "kill" => WitnessAction::ContainerKill,
            "restart" => WitnessAction::ContainerRestart,
            "remove" => WitnessAction::ContainerDelete,
            _ => unreachable!(),
        };
        let stages_for = |expected_action| {
            decoded
                .iter()
                .filter(|record| record.action() == expected_action)
                .map(|record| record.stage())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            stages_for(lifecycle_action),
            [
                WitnessStage::RequestReceived,
                WitnessStage::Decision,
                WitnessStage::Outcome
            ],
            "{action}"
        );
        let mapping_stages = stages_for(WitnessAction::RootlessMapping);
        if !nix::unistd::Uid::effective().is_root() && matches!(action, "run" | "restart") {
            assert_eq!(
                mapping_stages,
                [
                    WitnessStage::RequestReceived,
                    WitnessStage::Decision,
                    WitnessStage::Outcome
                ],
                "{action} rootless mapping"
            );
            assert_eq!(decoded.len(), 6, "{action} journal entries");
        } else {
            assert!(mapping_stages.is_empty(), "{action} rootless mapping");
            assert_eq!(decoded.len(), 3, "{action} journal entries");
        }
        drop(runtime);
        drop(journal);
        std::env::remove_var("FERROCRATE_CGROUP_ROOT");
    }
}

macro_rules! named_required_success {
    ($name:ident) => {
        #[test]
        fn $name() {
            // The shared matrix asserts the concrete Result for every action,
            // the exact receipt stages, and the resulting state.
            every_allowed_lifecycle_method_has_one_decision_and_terminal_receipt();
        }
    };
}

named_required_success!(required_run_success_is_witnessed);
named_required_success!(required_exec_success_is_witnessed);
named_required_success!(required_pause_success_is_witnessed);
named_required_success!(required_resume_success_is_witnessed);
named_required_success!(required_stop_success_is_witnessed);
named_required_success!(required_kill_success_is_witnessed);
named_required_success!(required_restart_success_is_witnessed);
named_required_success!(required_remove_success_is_witnessed);

#[test]
fn disabled_mode_rejects_any_journal_and_uses_explicit_compatibility_path() {
    let _guard = runtime_test_guard();
    let root = tempfile::tempdir().unwrap();
    let policy_path = root.path().join("policy.toml");
    std::fs::write(
        &policy_path,
        "schema_version = 1\ngeneration = 1\nmode = \"disabled\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&policy_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let store = SqliteContainerStore::open(root.path().join("containers.db")).unwrap();
    let record: ContainerRecord = serde_json::from_value(serde_json::json!({
        "id":"00112233445566778899aabbccddeeff", "pid":u32::MAX,
        "image":"example.invalid/app:latest", "command":["true"],
        "created_at_unix":1, "stdout_path":"", "stderr_path":"", "status":"stopped"
    }))
    .unwrap();
    store.put(&record).unwrap();
    drop(store);
    let gate = Arc::new(AuthorizationGate::new(Arc::new(
        PolicyStore::load(&policy_path).unwrap(),
    )));
    let journal = Arc::new(
        WitnessJournal::open(JournalConfig::new(
            root.path().join("witness"),
            [44; 16],
            JournalMode::Disabled,
        ))
        .unwrap(),
    );
    let error = ContainerRuntime::new_with_authorization(root.path(), gate, Some(journal.clone()))
        .err()
        .expect("disabled mode must reject journal configuration");
    assert!(error
        .to_string()
        .contains("disabled authorization cannot use"));
    assert!(journal.records().unwrap().is_empty());
}

#[test]
fn creation_provenance_requires_every_identity_binding() {
    let mut value = CreationProvenance::default();
    assert!(!value.is_verifiable());
    value.runtime_instance_id = Some([1; 16]);
    value.boot_id = Some([2; 16]);
    value.journal_id = Some([4; 16]);
    value.resource_uuid = Some("00112233-4455-6677-8899-aabbccddeeff".into());
    value.resource_generation = 1;
    value.creator_operation_id = Some([3; 16]);
    value.image_digest = Some(format!("sha256:{}", "a".repeat(64)));
    assert!(value.is_verifiable());
}
